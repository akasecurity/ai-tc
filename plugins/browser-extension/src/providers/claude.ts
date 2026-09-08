import { createSseAssembler } from '../stream-assembler.ts';
import {
  extractContentEditableText,
  firstMatch,
  setContentEditableText,
  watchButtonClick,
  watchEnterToSend,
} from './dom-utils.ts';
import type { ExchangeAssembler, ProviderAdapter, WebExchangeSummary } from './types.ts';

// Same caveat as chatgpt.ts: best-effort, layered fallback selectors that
// can go stale with a site redesign — verify against the live site before
// relying on block/redact actually firing.
const COMPOSER_SELECTORS = [
  'div[contenteditable="true"][aria-label*="claude" i]',
  'fieldset [contenteditable="true"]',
  'form [contenteditable="true"]',
];
const SEND_BUTTON_SELECTORS = ['button[aria-label*="send" i]', 'fieldset button[type="submit"]'];

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
function createClaudeStreamAssembler(): ExchangeAssembler {
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
  extractText: extractContentEditableText,
  setText: setContentEditableText,
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

  // NETWORK HALF. `endpoints` stays empty and `requiredPaths` stays empty: an
  // empty `endpoints` puts nothing in the tap's build-time table, so nothing
  // from this site is forwarded and createClaudeStreamAssembler above is
  // never reached in production. This is NOT because the contract is
  // unknown — claude.ai's response stream (the SSE event sequence and the
  // message_start/content_block_* keys it carries) was fully observed and is
  // implemented above — but because a declaring adapter owes committed
  // fixtures under test/fixtures/claude-ai/, produced only by
  // scripts/sanitize-capture.mjs from a real capture. No sanitised capture
  // exists for this site, and the sanitiser's own value-preservation gate
  // (isVocabularyCandidate) would refuse several of this stream's protocol
  // tokens even if one did — its own fix is a separate, reviewed change to
  // the sanitiser, not something an adapter change may smuggle in. The bar
  // itself, and what declaring costs, is on EXPECTED_DECLARING_ADAPTERS in
  // test/helpers/fixture-bar.ts.
  //
  // When that list is filled, `requiredPaths.response` may name only fields a
  // capture has actually shown populated. A declared path the site never
  // fills makes `closeExchange` record a shape miss on every healthy turn, so
  // a permanently-absent field reads as permanent drift. On the observed
  // stream that is messageId, model and responseText. `stopReason` is NOT
  // among them: it is a key on message_start.message whose value was never
  // recorded, and message_delta — where a terminal stop_reason would arrive —
  // is read by nothing here.
  endpoints: [],
  requiredPaths: { request: [], response: [] },
  // The completion request's body keys were never observed: the tap only
  // learned to decode a typed-array body in a later commit than the capture
  // that would have shown them. This reads no key and never claims the
  // shape is met — returning `requiredPathsSeen: true` while reading nothing
  // would be vacuously true, and it is the one boolean the bridge trusts to
  // detect outbound drift.
  parseRequest: () => ({ requiredPathsSeen: false }),
  parseStream: createClaudeStreamAssembler,
};
