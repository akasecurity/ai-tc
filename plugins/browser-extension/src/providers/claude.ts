import { createSseAssembler } from '../stream-assembler.ts';
import {
  extractComposerText,
  firstMatch,
  setComposerText,
  watchButtonClick,
  watchEnterToSend,
} from './dom-utils.ts';
import type {
  ExchangeAssembler,
  MatchedExchange,
  ParsedRequest,
  ProviderAdapter,
  WebExchangeSummary,
} from './types.ts';

// Same caveat as chatgpt.ts: best-effort, layered fallback selectors that
// can go stale with a site redesign — verify against the live site before
// relying on block/redact actually firing.
const COMPOSER_SELECTORS = [
  'div[contenteditable="true"][aria-label*="claude" i]',
  'fieldset [contenteditable="true"]',
  'form [contenteditable="true"]',
];
const SEND_BUTTON_SELECTORS = ['button[aria-label*="send" i]', 'fieldset button[type="submit"]'];

// The completion route's own path segments, spelled as constants because the
// endpoint pattern below is BUILT from them rather than repeating them: they
// are also what `protocolTokens` declares, so a fixture records the real route
// instead of a row of surrogates while the two ids between them are still
// replaced.
//
// Both ids are shape-matched rather than captured — nothing here reads them,
// and the conversation id is not recoverable from the request body at all.
const SEGMENT_API = 'api';
const SEGMENT_ORGANIZATIONS = 'organizations';
const SEGMENT_CONVERSATIONS = 'chat_conversations';
const SEGMENT_COMPLETION = 'completion';
const SEGMENT_ID = '[0-9a-fA-F-]{36}';

/**
 * The conversation uuid, read off the matched URL's own path.
 *
 * It is recoverable ONLY here: the completion body carries the two turn
 * message uuids and no conversation uuid, so before `parseStream` was given
 * the matched exchange this field had nowhere to come from and was left
 * undefined rather than guessed.
 *
 * Read by SEGMENT rather than by re-running the endpoint pattern: the pattern
 * shape-matches both ids without capturing either, and adding a capture group
 * to it would couple the route's own matching to this one field.
 */
function conversationIdOf(url: string): string | undefined {
  let path: string;
  try {
    path = new URL(url).pathname;
  } catch {
    // A URL this cannot parse is one no id can be read from.
    return undefined;
  }
  const segments = path.split('/');
  const at = segments.indexOf(SEGMENT_CONVERSATIONS);
  if (at === -1) return undefined;
  const value = segments[at + 1];
  return value === undefined || value === '' ? undefined : value;
}

// Anchored end to end, so it matches the completion route and nothing else the
// site serves. The tap matches path+query against this, and an anchored pattern
// is what keeps a query string from reaching a pattern written against a path.
const COMPLETION_PATH = new RegExp(
  `^/${SEGMENT_API}/${SEGMENT_ORGANIZATIONS}/${SEGMENT_ID}` +
    `/${SEGMENT_CONVERSATIONS}/${SEGMENT_ID}/${SEGMENT_COMPLETION}$`,
);

function findSendButton(): HTMLElement | null {
  return firstMatch(SEND_BUTTON_SELECTORS);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The response half of one claude.ai completion turn.
 *
 * SSE framing across chunk boundaries is `createSseAssembler`'s job; this
 * dispatches on the JSON payload's own `type` field — never on the SSE
 * `event:` name, which the assembler drops and this parser never needs.
 *
 * Two things were observed separately: the `event:` name sequence, and that
 * `type` is one of the payload keys. That the two carry the SAME vocabulary
 * is the documented Messages-format correspondence, not a site observation.
 * If they do not, no case below matches, `messageId` stays undefined and
 * `end()` returns null — this recovers nothing rather than fabricating.
 *
 * UNEXERCISED BY REAL TRAFFIC: this parser has no fixtures and cannot have
 * any until a real capture exists — see the doc comment on
 * EXPECTED_DECLARING_ADAPTERS in test/helpers/fixture-bar.ts. Its own suite
 * (test/providers/claude-stream.test.ts) drives it against synthetic streams
 * shaped from the survey and certifies its FRAMING and ASSEMBLY — never what
 * claude.ai actually sends. `endpoints` stays empty below, so none of this is
 * reachable in production yet.
 */
function createClaudeStreamAssembler(exchange: MatchedExchange): ExchangeAssembler {
  const conversationId = conversationIdOf(exchange.url);
  const sse = createSseAssembler();
  let messageId: string | undefined;
  let model: string | undefined;
  let stopReason: string | undefined;
  const blocks = new Map<number, string[]>();
  let ended = false;

  function blockPieces(index: number): string[] {
    const existing = blocks.get(index);
    if (existing !== undefined) return existing;
    const created: string[] = [];
    blocks.set(index, created);
    return created;
  }

  function handlePayload(raw: string): void {
    let payload: unknown;
    try {
      payload = JSON.parse(raw);
    } catch {
      // A line fragment, a non-JSON `data:` line, or malformed JSON — this
      // parser only ever sees a whole payload once createSseAssembler framed
      // it, so this is a garbage/edge input rather than the ordinary case.
      return;
    }
    if (!isPlainObject(payload)) return;

    switch (payload.type) {
      case 'message_start': {
        // FIRST message_start wins. Defensive about an unobserved input (a
        // second message_start in one stream was never seen) rather than a
        // claim about the site: overwriting would change the natural key
        // mid-stream.
        if (messageId !== undefined) return;
        const message = payload.message;
        if (!isPlainObject(message)) return;
        // `message.uuid` is the message id per the survey. `message.id` is a
        // separate observed key whose meaning was never established and is
        // read by nothing here.
        if (isNonEmptyString(message.uuid)) messageId = message.uuid;
        if (isNonEmptyString(message.model)) model = message.model;
        // Expected null here (the turn has not stopped yet); recovered only
        // in the rare case this event already carries a string. Never
        // `String(x)` — a null must stay an absent key, not become 'null'.
        if (isNonEmptyString(message.stop_reason)) stopReason = message.stop_reason;
        return;
      }
      case 'content_block_start':
        // Ensures the block's entry exists so an empty or text-less block
        // still sorts into position when the text is assembled.
        if (isNonNegativeInteger(payload.index)) blockPieces(payload.index);
        return;
      case 'content_block_delta': {
        if (!isNonNegativeInteger(payload.index)) return;
        const delta = payload.delta;
        if (!isPlainObject(delta)) return;
        if (delta.type !== 'text_delta' || typeof delta.text !== 'string') return;
        // Pushed even when content_block_start for this index was cut away —
        // the entry is created on demand.
        blockPieces(payload.index).push(delta.text);
        return;
      }
      case 'content_block_stop':
      case 'message_stop':
        // The two stop events carry nothing this summary needs.
        return;
      case 'message_delta':
        // This stream's message_delta inner keys were never enumerated. The
        // public API documents `delta.stop_reason` and `usage` here, but this
        // stream already deviates from that document by omitting `usage` on
        // message_start, so the document is not evidence for this site.
        return;
      case 'conversation_ready':
        // Its payload keys were never enumerated.
        return;
      case 'message_limit':
        // Per-window quota. This is per-account usage data rather than
        // anything about the turn, and nothing here reads a single field of
        // it, ever.
        return;
      default:
        // An unrecognised type — including one carrying its own `message`
        // key shaped like message_start's — is never inspected on the
        // strength of a key name alone. `discarded_parent_message_uuid` was
        // observed as a payload KEY and never as a `type` value, so it gets
        // no case of its own and lands here if it ever arrives as one.
        return;
    }
  }

  function drainAndFinish(): void {
    if (ended) return;
    // Drains whatever a final unterminated `data:` line left behind — a
    // stream cut exactly after the last data line still contributes its
    // payload. Idempotent: `ended` guards a second call from re-draining or
    // from a push() after end() changing anything.
    for (const payload of sse.end()) handlePayload(payload);
    ended = true;
  }

  return {
    push(chunk: string): void {
      if (ended) return;
      for (const payload of sse.push(chunk)) handlePayload(payload);
    },
    end(): WebExchangeSummary | null {
      drainAndFinish();
      // A summary cannot be half-built without a message id — it is the
      // natural key the stored row hashes on. Deliberately NOT gated on
      // message_stop: the tap's own byte ceiling can cut a healthy long
      // reply, and reporting that truncation as a contract change would be
      // the worse error.
      if (messageId === undefined) return null;
      const text = [...blocks.keys()]
        .sort((a, b) => a - b)
        .map((index) => (blocks.get(index) ?? []).join(''))
        .join('');
      return {
        messageId,
        usageSource: 'none',
        toolCalls: [],
        ...(conversationId !== undefined ? { conversationId } : {}),
        ...(model !== undefined ? { model } : {}),
        ...(stopReason !== undefined ? { stopReason } : {}),
        ...(text !== '' ? { responseText: text } : {}),
      };
    },
  };
}

export const claudeAdapter: ProviderAdapter = {
  id: 'claude-ai',
  hostnames: ['claude.ai'],
  findComposer() {
    return firstMatch(COMPOSER_SELECTORS);
  },
  findSendButton,
  extractText: extractComposerText,
  setText: setComposerText,
  watchSubmit(composer, onSubmit) {
    const unwatchEnter = watchEnterToSend(composer, onSubmit);
    const sendButton = findSendButton();
    const unwatchClick = sendButton ? watchButtonClick(sendButton, onSubmit) : undefined;
    return () => {
      unwatchEnter();
      unwatchClick?.();
    };
  },
  submit() {
    const sendButton = findSendButton();
    if (!sendButton) return false;
    sendButton.click();
    return true;
  },

  // NETWORK HALF. Declared against a real capture: a signed-in turn on
  // claude.ai, sanitised by scripts/sanitize-capture.mjs into
  // test/fixtures/claude-ai/. Nothing below is inferred from the survey
  // alone — the stream parser above was written from the observed event
  // sequence and then driven against the captured bytes unchanged, and the
  // request keys named here are the ones that capture carries.
  //
  // `requiredPaths.response` names only fields the capture showed
  // POPULATED. A declared path the site never fills makes `closeExchange`
  // record a shape miss on every healthy turn, so a permanently-absent
  // field reads as permanent drift. `stopReason` is therefore NOT among
  // them: it is a key on message_start.message that arrived null, and
  // message_delta — where a terminal stop_reason would arrive — is read by
  // nothing here. `usage` is absent from this stream entirely, which is why
  // the summary reports usageSource 'none' rather than estimating.
  endpoints: [{ host: 'claude.ai', path: COMPLETION_PATH, kind: 'conversation' }],
  requiredPaths: {
    request: ['model', 'prompt'],
    response: ['messageId', 'model', 'responseText'],
  },
  // What this adapter switches on: the `case` labels parseStream dispatches
  // on, the one `delta.type` it compares, and the path segments its endpoint
  // anchors on. Every one is a value the sanitiser must keep verbatim or a
  // fixture cannot exercise the dispatch — or record the route — at all. Nothing here is a pattern
  // or a prefix: the sanitiser preserves a captured value only on an EXACT
  // match, and the detector still gates each one. Adding to this list means
  // updating EXPECTED_PROTOCOL_TOKENS in test/helpers/fixture-bar.ts in the
  // same diff.
  protocolTokens: [
    // The path segments the endpoint above anchors on. Declared so a fixture
    // records the real route rather than a row of surrogates: the two ids
    // between them are NOT declared and are still replaced, so the shape
    // survives and the identifiers do not.
    'api',
    'organizations',
    'chat_conversations',
    'completion',
    // The `case` labels parseStream dispatches on.
    'conversation_ready',
    'message_start',
    'content_block_start',
    'content_block_delta',
    'content_block_stop',
    'message_delta',
    'message_limit',
    'message_stop',
    'text_delta',
  ],
  // The outbound turn. `model` and `prompt` are top-level strings on the
  // completion body; both are required, so a body carrying neither reports
  // its shape unmet rather than half-met.
  //
  // `conversationId` is deliberately NOT returned here, even though the
  // matched URL is now in reach. The body carries the two turn message uuids
  // and no conversation uuid, so it could only come from the URL — and
  // `parseStream` is the better seam for that: this one is reached only for a
  // body the bridge admitted, so a request with no body, or one over
  // REQUEST_BODY_MAX_BYTES, would lose the id here while keeping it there.
  // Returning a message uuid under that name would put a wrong id on every
  // stored row.
  //
  // The body arrives gzip-compressed on the wire; the tap inflates it
  // before this is reached, so this sees ordinary JSON text.
  parseRequest: (body: string): ParsedRequest => {
    let payload: unknown;
    try {
      payload = JSON.parse(body);
    } catch {
      // A body this cannot parse is one whose shape it cannot report on.
      return { requiredPathsSeen: false };
    }
    if (!isPlainObject(payload)) return { requiredPathsSeen: false };
    const model = isNonEmptyString(payload.model) ? payload.model : undefined;
    const prompt = isNonEmptyString(payload.prompt) ? payload.prompt : undefined;
    return {
      ...(model !== undefined ? { model } : {}),
      ...(prompt !== undefined ? { prompt } : {}),
      requiredPathsSeen: model !== undefined && prompt !== undefined,
    };
  },
  parseStream: createClaudeStreamAssembler,
};
