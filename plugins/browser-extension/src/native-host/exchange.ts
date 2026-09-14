/**
 * The pure projection from a native-host `WebExchange` payload onto the
 * gateway-port inputs for one assistant turn: an `llm_call` leaf and its
 * `tool_call` leaves.
 *
 * No I/O and no gateway here — the caller (host.ts) owns the store, the
 * consent gate and the response capture. This module only shapes the bag.
 */
// Type-only: the scanner is an injected seam (see TargetScanner below), so
// this module never touches @akasecurity/detections or the bundled packs
// itself — it stays pure and cheap to unit-test.
import type { ScanFinding } from '@akasecurity/plugin-sdk';
import type {
  LlmCallAttributes,
  LlmCallInput,
  ToolCallAttributes,
  ToolCallInput,
  ToolCallInspection,
  WebExchange,
} from '@akasecurity/schema';
import { RESPONSE_TEXT_MAX_BYTES } from '@akasecurity/schema';

import type { WebSourceTool } from './protocol.ts';

// The longest (masked) tool target we store — a search query or a connector
// argument can be long, and the point is "which call", not the whole body.
// Applied AFTER masking (see toToolCallInputs) so a truncated redaction marker
// leaks nothing, whereas truncating the RAW target first could split a secret
// across the cap and leak its unmasked prefix.
const MAX_TARGET_LEN = 500;
const truncateTarget = (s: string): string =>
  s.length > MAX_TARGET_LEN ? `${s.slice(0, MAX_TARGET_LEN)}…` : s;

// What a target may cost to SCAN. `WebToolCall.target` carries no `.max()` and
// the wire frame is the only other bound, so without this the mask-then-cap
// order above — correct as far as it goes — is charged against an unbounded
// string: shieldPointers, scan and redact all walk the whole raw value. One
// host process serves every tab in sequence, so a single exchange carrying a
// multi-megabyte target stalls every other tab's capture, exchange and ping
// behind it.
//
// Cutting the raw before scanning is the same trade `capResponseText` already
// makes for `responseText`, and it carries the same cost: a secret straddling
// the cut is scanned only up to it. The ceiling is set far above any target
// this product can meaningfully audit — a URL, a search query, a connector
// argument — so reaching it means the value was never one of those.
const TARGET_SCAN_MAX_BYTES = 64 * 1024;

// How many server-side tool calls one turn may contribute. A turn is a handful
// of calls; a five-figure list is not a turn this can audit, and each entry
// costs a scan. Bounded HERE rather than with a `.max()` on the schema
// deliberately: a schema refusal would drop the whole exchange — its reply,
// its usage, its llm_call leaf — over a tail nobody reads, whereas dropping
// the tail keeps every row the turn is actually worth.
const MAX_TOOL_CALLS = 256;

/** How a tool-call target is inspected on the host. Injected so this module stays pure. */
export type TargetScanner = (text: string) => { masked: string; findings: ScanFinding[] };

/**
 * Cut `text` to at most `maxBytes` UTF-8 bytes, on a character boundary.
 *
 * Copied verbatim from `bridge.ts`'s `cutToBytes` rather than imported: that
 * file is the content-script bundle, and importing it here would drag the
 * page-side adapters, `tab-session.ts` and the `chrome.*` globals into the
 * native-host bundle.
 */
function cutToBytes(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength <= maxBytes) return { text, truncated: false };
  let end = maxBytes;
  // Walk back off any continuation byte so the partial character is dropped
  // whole.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return { text: new TextDecoder().decode(bytes.subarray(0, end)), truncated: true };
}

/**
 * The exchange with its response text cut to `maxBytes` UTF-8 bytes on a
 * character boundary, and `truncated` raised when this cut shortened it.
 *
 * The host's own enforcement of the schema ceiling. The bridge applies the same
 * number before relaying, but the bridge is not the only thing that can reach
 * this host: `WebExchange.responseText` is an unbounded `z.string()`, and
 * Chrome's Chrome-to-host direction has no 1 MB cap. Returns the input
 * unchanged when there is no text or the text is already within the ceiling.
 */
export function capResponseText(
  exchange: WebExchange,
  maxBytes: number = RESPONSE_TEXT_MAX_BYTES,
): WebExchange {
  if (exchange.responseText === undefined) return exchange;
  const cut = cutToBytes(exchange.responseText, maxBytes);
  return {
    ...exchange,
    responseText: cut.text,
    // OR, never assign: a text already marked truncated upstream (the tap's
    // raw-byte cut, or the bridge's own text cut) must stay truncated even
    // when this cut has nothing left to do.
    truncated: exchange.truncated || cut.truncated,
  };
}

/**
 * Trim, and treat a blank result as absent. Never write `''` to the store.
 *
 * Exported for host.ts, which needs the SAME trim for a response capture whose
 * exchange has no `llm_call` leaf to read an already-trimmed attribute off.
 */
export function trimmed(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const t = value.trim();
  return t === '' ? undefined : t;
}

// Set a numeric attribute only when the source is a finite number — keeps an
// absent count out of the bag rather than coercing it to 0.
function setNum(attrs: LlmCallAttributes, key: string, value: number | undefined): void {
  if (typeof value === 'number' && Number.isFinite(value)) attrs[key] = value;
}

/**
 * One observed assistant turn as an `llm_call` leaf input, or null when the
 * exchange cannot be keyed.
 *
 * Null, not a throw and not a fabricated id: the row id hashes on
 * (sessionId, messageId), so a blank or whitespace-only message id would
 * collapse every turn of a conversation onto one row and the UPSERT-take-MAX
 * would overwrite the session's token history with its largest single turn.
 * The caller records nothing for such an exchange.
 */
export function toLlmCallInput(
  exchange: WebExchange,
  sessionId: string,
  tool: WebSourceTool,
): LlmCallInput | null {
  const messageId = trimmed(exchange.messageId);
  if (messageId === undefined) return null;

  // The web tool id, never the vendor: the price map is keyed on
  // (provider, model) and never guesses, so a provider string it does not
  // recognise prices the leaf at null rather than at API rates — which is
  // exactly what keeps subscription traffic from being billed as API usage.
  // Never gateway.readSessionProvider() here: the session root carries the
  // vendor id (openai/anthropic) for a separate display purpose, and reading
  // it back would undo this on the very next line.
  const attrs: LlmCallAttributes = { provider: tool, message_id: messageId };

  const model = trimmed(exchange.model);
  if (model !== undefined) attrs.model = model;

  // The source decides which lane, the counts decide whether a lane field is
  // written. 'none' drops every count, priced and estimated alike — the
  // source is authoritative, so a contradictory 'none' + counts payload never
  // reaches the store as numbers.
  if (exchange.usageSource === 'site') {
    setNum(attrs, 'input_tokens', exchange.usage?.inputTokens);
    setNum(attrs, 'output_tokens', exchange.usage?.outputTokens);
    setNum(attrs, 'cache_read_input_tokens', exchange.usage?.cacheReadInputTokens);
    setNum(attrs, 'cache_creation_input_tokens', exchange.usage?.cacheCreationInputTokens);
  } else if (exchange.usageSource === 'estimated') {
    // No estimated_cache_* spelling exists, and an estimated cache-read count
    // is meaningless anyway — dropped, not guessed.
    setNum(attrs, 'estimated_input_tokens', exchange.usage?.inputTokens);
    setNum(attrs, 'estimated_output_tokens', exchange.usage?.outputTokens);
  }
  // Written for all three values, including 'none' — so a reader can tell
  // "the site reported nothing" from "nobody looked".
  attrs.usage_source = exchange.usageSource;

  const stopReason = trimmed(exchange.stopReason);
  if (stopReason !== undefined) attrs.stop_reason = stopReason;

  const conversationId = trimmed(exchange.conversationId);
  if (conversationId !== undefined) {
    // Two keys, deliberately: run_key is the grouping-key grammar the CLI
    // leaves already use, site_conversation_id is the site-correlation fact.
    attrs.run_key = conversationId;
    attrs.site_conversation_id = conversationId;
  }

  if (exchange.turnIndex !== undefined) attrs.turn_index = exchange.turnIndex;

  // Names neither ceiling that could have produced it — see WebExchange's own
  // comment. Rides this bag (rather than CaptureAttributes) because the
  // llm_call leaf is always written while the response row is conditional;
  // omitted, never false.
  if (exchange.truncated) attrs.response_truncated = true;

  return {
    sessionId,
    messageId,
    parentId: sessionId,
    rootSessionId: sessionId,
    startedAt: exchange.startedAt,
    attributes: attrs,
  };
}

/**
 * The server-side tool calls in one turn as `tool_call` leaf inputs.
 *
 * `scanTarget` is required rather than defaulted: a caller that forgets it
 * would write a raw target into the store, and a default is invisible at the
 * call site. It is applied HERE, on the host — the bridge forwards `target`
 * raw, as it forwards every other body, and nothing page-side is trusted to
 * have cleaned it.
 *
 * A tool call whose `toolUseId` is blank after trimming is dropped, and so is
 * a second one repeating an id already seen in this exchange (the row id is
 * content-addressed on (sessionId, toolUseId), so a duplicate would be
 * swallowed by INSERT OR IGNORE and the caller's own count would lie).
 */
export function toToolCallInputs(
  exchange: WebExchange,
  sessionId: string,
  scanTarget: TargetScanner,
): ToolCallInput[] {
  const conversationId = trimmed(exchange.conversationId);
  const seen = new Set<string>();
  const inputs: ToolCallInput[] = [];

  // `.default([])` fills this in only when the payload went through a parse;
  // a caller handing over an object that skipped one can still omit the key
  // entirely, so this never trusts the static type's non-optional `toolCalls`
  // and reads it back through a type that admits absence.
  const toolCalls = (exchange as { toolCalls?: WebExchange['toolCalls'] }).toolCalls ?? [];
  for (const tc of toolCalls.slice(0, MAX_TOOL_CALLS)) {
    const toolUseId = trimmed(tc.toolUseId);
    if (toolUseId === undefined) continue;
    if (seen.has(toolUseId)) continue;
    seen.add(toolUseId);

    const attrs: ToolCallAttributes = { tool_use_id: toolUseId };
    // A blank name does not drop the row: a nameless tool call is still a
    // fact, so only the key is omitted.
    const toolName = trimmed(tc.toolName);
    if (toolName !== undefined) attrs.tool_name = toolName;

    let inspections: ToolCallInspection[] = [];
    if (tc.target !== undefined) {
      // Mask the target, THEN size-cap the masked value — masking first
      // guarantees a secret is redacted whole before truncation. What is
      // masked is the target cut to TARGET_SCAN_MAX_BYTES, which is what
      // bounds the scan itself; see that constant for the cost.
      const { masked, findings } = scanTarget(cutToBytes(tc.target, TARGET_SCAN_MAX_BYTES).text);
      if (masked !== '') attrs.target = truncateTarget(masked);
      // actionTaken = 'log': these are observed post-hoc, after the tool
      // already ran — an audit record, not an enforcement decision.
      inspections = findings.map((f) => ({
        ruleId: f.ruleId,
        ruleName: f.ruleName,
        ruleVersion: f.ruleVersion,
        category: f.category,
        severity: f.severity,
        span: f.span,
        maskedMatch: f.maskedMatch,
        actionTaken: 'log',
        confidence: f.confidence,
      }));
    }

    if (tc.isError !== undefined) attrs.is_error = tc.isError;
    if (tc.inputSize !== undefined) attrs.input_size = tc.inputSize;
    if (tc.outputSize !== undefined) attrs.output_size = tc.outputSize;
    if (conversationId !== undefined) attrs.run_key = conversationId;

    inputs.push({
      sessionId,
      toolUseId,
      parentId: sessionId,
      rootSessionId: sessionId,
      startedAt: exchange.startedAt,
      attributes: attrs,
      inspections,
    });
  }

  return inputs;
}
