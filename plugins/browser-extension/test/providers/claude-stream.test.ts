// claude.ai response-stream parsing.
//
// These inputs are SYNTHETIC, shaped from a survey of the live site's event
// names, payload keys and assembly rule.
// They certify this parser's FRAMING and ASSEMBLY and certify NOTHING about
// what claude.ai sends. They are not fixtures: a fixture is a committed,
// sanitiser-produced envelope under test/fixtures/ that the bar in
// network-contract.test.ts re-judges against the live detector, and none
// exists for this site. The bar is armed the moment `claudeAdapter.endpoints`
// becomes non-empty (see EXPECTED_DECLARING_ADAPTERS in
// test/helpers/fixture-bar.ts).
//
// The DOM half of this adapter is covered separately in claude.test.ts under
// jsdom; this file runs under the default `node` environment.
import { describe, expect, it } from 'vitest';

import { claudeAdapter } from '../../src/providers/claude.ts';
import type { ParsedRequest, WebExchangeSummary } from '../../src/providers/types.ts';
import { matchedExchangeFor } from '../helpers/matched-exchange.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// ---- SSE event builders -----------------------------------------------

function sse(type: string, payload: Record<string, unknown> = {}): string {
  return `event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`;
}

// message.uuid is the message id per the survey; message.id is a distinct,
// separately-observed key whose meaning was never established and is not
// used by the adapter. Kept apart here so A1's self-check can prove the two
// values differ.
const UUID = 'msg-uuid-a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const LEGACY_ID = 'msg-id-11112222333344445555';
const MODEL = 'claude-survey-model-3-5';
const PARENT_UUID = 'parent-uuid-99998888777766665555';

function messageStartEvent(overrides: Record<string, unknown> = {}): string {
  return sse('message_start', {
    message: {
      id: LEGACY_ID,
      uuid: UUID,
      model: MODEL,
      parent_uuid: PARENT_UUID,
      stop_reason: null,
      ...overrides,
    },
  });
}

function contentBlockStartEvent(index: number): string {
  return sse('content_block_start', { index, content_block: { type: 'text', text: '' } });
}
function contentBlockDeltaEvent(index: number, text: string): string {
  return sse('content_block_delta', { index, delta: { type: 'text_delta', text } });
}
function contentBlockStopEvent(index: number): string {
  return sse('content_block_stop', { index });
}
function conversationReadyEvent(): string {
  return sse('conversation_ready');
}
function messageDeltaEvent(): string {
  return sse('message_delta', { delta: {} });
}
function messageLimitEvent(sentinel: string): string {
  return sse('message_limit', { quota: { remaining: sentinel } });
}
function messageStopEvent(): string {
  return sse('message_stop');
}

// >= 16 chars, matches no bundled detection rule — this file never runs the
// real detector (that only happens in network-contract.test.ts's fixture
// bar), but the value is kept rule-shaped-free anyway so nothing about this
// test depends on matching a rule pack that might grow later.
const SENTINEL = 'QUOTA_SENTINEL_7f3ac91e5b2d4a';

const S_EVENTS: readonly string[] = [
  conversationReadyEvent(),
  messageStartEvent(),
  contentBlockStartEvent(0),
  contentBlockStartEvent(1),
  contentBlockDeltaEvent(1, 'world'),
  contentBlockDeltaEvent(0, 'hello '),
  contentBlockDeltaEvent(1, '!'),
  contentBlockDeltaEvent(0, 'there'),
  contentBlockStopEvent(0),
  contentBlockStopEvent(1),
  messageDeltaEvent(),
  messageLimitEvent(SENTINEL),
  messageStopEvent(),
];
const S = S_EVENTS.join('');

// The conversation uuid the EXCHANGE's url names — recovered from the matched
// URL rather than from the stream, because it appears nowhere in the payloads.
const CONVERSATION_UUID = '66666666-7777-4888-8999-aaaaaaaaaaaa';

const EXPECTED_SUMMARY: WebExchangeSummary = {
  messageId: UUID,
  conversationId: CONVERSATION_UUID,
  model: MODEL,
  responseText: 'hello thereworld!',
  usageSource: 'none',
  toolCalls: [],
};

function replay(chunks: readonly string[]): WebExchangeSummary | null {
  const assembler = claudeAdapter.parseStream(EXCHANGE);
  for (const chunk of chunks) assembler.push(chunk);
  return assembler.end();
}

// Asserts non-null (so a summary-shaped assertion never silently passes on
// `undefined`) and narrows within this function's own scope — narrowing a
// `let` reassigned from inside a closure is not tracked outside it, and a
// non-null assertion or cast is banned by this package's lint config.
function summaryHasOwn(summary: WebExchangeSummary | null, key: string): boolean {
  expect(summary).not.toBeNull();
  return summary !== null && Object.hasOwn(summary, key);
}

// The exchange the bridge would hand parseStream for this adapter's one
// declared route, resolved through the bridge's own matcher.
const EXCHANGE = matchedExchangeFor(
  claudeAdapter,
  'https://claude.ai/api/organizations/11111111-2222-4333-8444-555555555555' +
    '/chat_conversations/66666666-7777-4888-8999-aaaaaaaaaaaa/completion',
);

describe('claudeAdapter.parseStream — canonical stream S', () => {
  it('assembles the expected summary with no other own keys', () => {
    const summary = replay([S]);
    expect(summary).toEqual(EXPECTED_SUMMARY);
    expect(Object.keys(summary ?? {}).sort()).toEqual(Object.keys(EXPECTED_SUMMARY).sort());
  });
});

describe('A — event-level assembly', () => {
  it('A1: messageId is message.uuid, not message.id', () => {
    expect(LEGACY_ID).not.toBe(UUID);
    const summary = replay([S]);
    expect(summary?.messageId).toBe(UUID);
  });

  it('A2: model comes from message_start.message.model', () => {
    const summary = replay([S]);
    expect(summary?.model).toBe(MODEL);
  });

  it('A3a: stopReason is recovered when message.stop_reason is a non-empty string', () => {
    const events = [
      conversationReadyEvent(),
      messageStartEvent({ stop_reason: 'end_turn' }),
      contentBlockStartEvent(0),
      contentBlockDeltaEvent(0, 'hi'),
      contentBlockStopEvent(0),
      messageStopEvent(),
    ];
    const summary = replay([events.join('')]);
    expect(summary?.stopReason).toBe('end_turn');
  });

  it('A3b: a null stop_reason yields an absent key, never the string "null"', () => {
    const summary = replay([S]);
    expect(summary).not.toBeNull();
    expect(summaryHasOwn(summary, 'stopReason')).toBe(false);
  });

  it('A4: responseText concatenates by ascending block index, not arrival order', () => {
    const summary = replay([S]);
    expect(summary?.responseText).toBe('hello thereworld!');

    // S's own content_block_start events happen to arrive in ascending
    // index order (0 then 1) — which would leave a MISSING sort
    // undetectable if block order were read off nothing but Map insertion
    // order, since insertion order already matches ascending order here.
    // This variant starts block 1 before block 0, so only an explicit
    // ascending-index sort (not insertion order) recovers 'hello thereworld!'.
    const reorderedStarts = [
      conversationReadyEvent(),
      messageStartEvent(),
      contentBlockStartEvent(1),
      contentBlockStartEvent(0),
      contentBlockDeltaEvent(1, 'world'),
      contentBlockDeltaEvent(0, 'hello '),
      contentBlockDeltaEvent(1, '!'),
      contentBlockDeltaEvent(0, 'there'),
      contentBlockStopEvent(1),
      contentBlockStopEvent(0),
      messageStopEvent(),
    ].join('');
    const reorderedSummary = replay([reorderedStarts]);
    expect(reorderedSummary?.responseText).toBe('hello thereworld!');
  });

  it('A5: only delta.type === "text_delta" contributes', () => {
    const NONTEXT = 'INPUT_JSON_SENTINEL_9a8b7c6d5e4f';
    // Carries `text` (not just the realistic `partial_json`) so that a
    // mutation dropping the `delta.type` guard is actually observable here:
    // without `text`, the separate `typeof delta.text === 'string'` guard
    // alone would already reject this payload and the type check would go
    // untested.
    const injected = sse('content_block_delta', {
      index: 0,
      delta: { type: 'input_json_delta', text: NONTEXT, partial_json: NONTEXT },
    });
    const stream = [...S_EVENTS.slice(0, 4), injected, ...S_EVENTS.slice(4)].join('');
    // Positive control: prove the sentinel is actually present in the input
    // before asserting it never reaches the summary.
    expect(stream).toContain(NONTEXT);
    const summary = replay([stream]);
    expect(summary?.responseText).toBe('hello thereworld!');
    expectNoEchoOf(summary?.responseText, NONTEXT);
  });

  it('A6: usageSource is "none" and no usage key exists', () => {
    const summary = replay([S]);
    expect(summary?.usageSource).toBe('none');
    expect(summaryHasOwn(summary, 'usage')).toBe(false);
  });

  it('A7: toolCalls is []', () => {
    const summary = replay([S]);
    expect(summary?.toolCalls).toEqual([]);
  });

  it('A8: conversationId comes from the matched URL, never from the stream', () => {
    // It appears in no payload — the stream carries the two message uuids and
    // no conversation uuid — so recovering it is entirely a property of the
    // exchange parseStream was handed.
    expect(PARENT_UUID).not.toBe(UUID);
    expect(S).not.toContain(CONVERSATION_UUID);
    expect(replay([S])?.conversationId).toBe(CONVERSATION_UUID);
  });

  it('A8b: a URL naming no conversation segment yields no id, rather than a wrong one', () => {
    // Reached when the matched URL is not the shape this reads. Leaving the
    // field undefined is the whole point: a segment picked positionally from
    // an unexpected path would put a wrong id on every stored row.
    const assembler = claudeAdapter.parseStream({
      url: 'https://claude.ai/api/organizations/abc/something-else/def/completion',
      endpoint: EXCHANGE.endpoint,
    });
    assembler.push(S);
    expect(summaryHasOwn(assembler.end(), 'conversationId')).toBe(false);
  });

  it('A8c: turnIndex and startedAt stay absent', () => {
    const summary = replay([S]);
    expect(summaryHasOwn(summary, 'turnIndex')).toBe(false);
    expect(summaryHasOwn(summary, 'startedAt')).toBe(false);
  });
});

describe('B — message_limit is never recorded', () => {
  it('B1: message_limit contributes nothing — two streams, one summary', () => {
    const withoutLimit = [...S_EVENTS.slice(0, 11), ...S_EVENTS.slice(12)];
    expect(withoutLimit.length).toBe(S_EVENTS.length - 1);
    const withLimitSummary = replay([S]);
    const withoutLimitSummary = replay([withoutLimit.join('')]);
    // Both sides must be a real summary before they are compared: two nulls
    // are equal, so a regression returning null everywhere satisfies the
    // equality below while asserting nothing about message_limit.
    expect(withLimitSummary).toEqual(EXPECTED_SUMMARY);
    expect(withLimitSummary).toEqual(withoutLimitSummary);
  });

  it('B2: no value from message_limit reaches the summary', () => {
    // Positive control on the INPUT, and on the asserted BYTES.
    // `JSON.stringify(null)` is the string "null" — defined and non-empty —
    // so expectNoEchoOf's own guard would pass over a null summary and every
    // not.toContain with it. Pinning the summary first is what stops that.
    expect(S).toContain(SENTINEL);
    const summary = replay([S]);
    expect(summary).toEqual(EXPECTED_SUMMARY);
    expectNoEchoOf(JSON.stringify(summary), SENTINEL);
  });
});

describe('C — chunk-boundary robustness', () => {
  it('C1: splitting at every byte boundary assembles identically', () => {
    // Pinned against the known-good EXPECTED_SUMMARY rather than a freshly
    // computed `replay([S])`: a mutation that breaks whole-chunk parsing too
    // (e.g. JSON.parse'ing the raw chunk instead of the assembler's decoded
    // payloads) would break that baseline the same way it breaks every
    // split, so comparing split-vs-split would stay green on a null-vs-null
    // match. Comparing against a fixed expectation catches it.
    for (let i = 0; i <= S.length; i += 1) {
      const summary = replay([S.slice(0, i), S.slice(i)]);
      expect(summary).toEqual(EXPECTED_SUMMARY);
    }
  });

  it('C2: one character per push assembles identically', () => {
    const summary = replay(S.split(''));
    expect(summary).toEqual(EXPECTED_SUMMARY);
  });

  it('C3: a final unterminated data: line still contributes — the end() drain', () => {
    // The A3a variant whose LAST event carries stop_reason, so the drain
    // bites on a field rather than a no-op event.
    const stopReasonLastEvents = [
      conversationReadyEvent(),
      contentBlockStartEvent(0),
      contentBlockDeltaEvent(0, 'hi'),
      contentBlockStopEvent(0),
      messageStopEvent(),
      messageStartEvent({ stop_reason: 'end_turn' }),
    ];
    const whole = stopReasonLastEvents.join('');
    // Strip the trailing "\n\n" of the final event so its data: line is
    // never terminated during push() and only end()'s drain recovers it.
    const truncated = whole.slice(0, -2);

    const wholeSummary = replay([whole]);
    const truncatedSummary = replay([truncated]);
    expect(wholeSummary?.stopReason).toBe('end_turn');
    expect(truncatedSummary).toEqual(wholeSummary);
  });

  it('C4: CRLF assembles identically to LF', () => {
    // Pinned against EXPECTED_SUMMARY, not a freshly computed `replay([S])`
    // — see C1's comment on why a self-referential baseline can go equally
    // wrong under some mutations and stay green.
    const crlf = replay([S.replace(/\n/g, '\r\n')]);
    expect(crlf).toEqual(EXPECTED_SUMMARY);
  });

  it('C5: an event: line is never needed and never read', () => {
    const stripped = S.split('\n')
      .filter((line) => !line.startsWith('event:'))
      .join('\n');
    const summary = replay([stripped]);
    expect(summary).toEqual(EXPECTED_SUMMARY);
  });

  it('C6: a terminator-free body yields no summary and no fabricated text', () => {
    const assembler = claudeAdapter.parseStream(EXCHANGE);
    const chunk = 'x'.repeat(4096);
    for (let i = 0; i < 512; i += 1) assembler.push(chunk);
    // 2 MB of a response carrying no `data:` line at all — an error page, or
    // plain JSON where SSE was expected. Nothing is recovered from it, and in
    // particular the body never becomes responseText. What that costs is the
    // ASSEMBLER's property, guarded as a two-size ratio in
    // test/stream-assembler.test.ts rather than by a clock here.
    expect(assembler.end()).toBeNull();
  });
});

describe('D — edges and garbage', () => {
  it('D1: a stream that ends before any message id was recovered returns null', () => {
    const assembler = claudeAdapter.parseStream(EXCHANGE);
    assembler.push(conversationReadyEvent());
    assembler.push('data: {"type":"message_st');
    expect(assembler.end()).toBeNull();
    expect(() => assembler.end()).not.toThrow();
    expect(assembler.end()).toBeNull();
  });

  it('D2: a stream cut after message_start but before message_stop still yields a summary', () => {
    // Through the second content_block_delta (indices 0..5 of S_EVENTS).
    const cutEvents = S_EVENTS.slice(0, 6);
    const summary = replay([cutEvents.join('')]);
    expect(summary).not.toBeNull();
    expect(summary?.messageId).toBe(UUID);
    expect(summary?.responseText).toBe('hello world');
    expect(summaryHasOwn(summary, 'stopReason')).toBe(false);
  });

  it('D3: garbage never throws and never fabricates', () => {
    const inputs = [
      '',
      ' �{{{',
      '['.repeat(4096),
      'a'.repeat(64 * 1024),
      'data:\n\n',
      'data: 5\n\n',
      'data: [1,2]\n\n',
      'data: null\n\n',
      ':comment\n\n',
    ];
    for (const input of inputs) {
      const assembler = claudeAdapter.parseStream(EXCHANGE);
      expect(() => {
        assembler.push(input);
      }).not.toThrow();
      expect(assembler.end()).toBeNull();
    }
  });

  it('D4: an unknown type is ignored even when it carries a message', () => {
    const unknown = sse('__aka_unknown__', {
      message: { uuid: 'OTHER-UUID-SHOULD-NOT-APPEAR', model: 'other-model-should-not-appear' },
    });
    const summary = replay([S + unknown]);
    expect(summary?.messageId).toBe(UUID);
    expect(summary?.model).toBe(MODEL);

    // Isolates the type gate from D5's FIRST-wins guard: here the unknown
    // event is the ONLY thing in the stream carrying a `message` field, so a
    // mutation that reads `payload.message` regardless of `payload.type`
    // would set messageId from it even though there is no earlier "first"
    // message_start for a first-wins check to be protecting against.
    const onlyUnknown = [conversationReadyEvent(), unknown].join('');
    expect(replay([onlyUnknown])).toBeNull();
  });

  it('D5: the FIRST message_start wins', () => {
    const second = messageStartEvent({ uuid: 'SECOND-UUID-SHOULD-NOT-WIN', model: 'second-model' });
    const summary = replay([S + second]);
    expect(summary?.messageId).toBe(UUID);
    expect(summary?.model).toBe(MODEL);
  });

  it('D6: end() is idempotent and a later push cannot change it', () => {
    const assembler = claudeAdapter.parseStream(EXCHANGE);
    assembler.push(S);
    const first = assembler.end();
    assembler.push(contentBlockDeltaEvent(0, 'MORE-TEXT-AFTER-END'));
    assembler.push(messageStartEvent({ uuid: 'AFTER-END-UUID' }));
    const second = assembler.end();
    expect(second).toEqual(first);
  });

  it('D7: the reverse-order and injected-unknown shapes already hold', () => {
    const reversed = [...S_EVENTS].reverse();
    const assembler = claudeAdapter.parseStream(EXCHANGE);
    expect(() => {
      for (const event of reversed) assembler.push(event);
    }).not.toThrow();
    // end() is idempotent (see D6), so calling it once inside the
    // not-to-throw probe and once more directly is safe and returns the
    // same answer either way — done this way rather than assigning to an
    // outer `let` from inside the closure, which TypeScript's narrowing
    // does not track across the callback boundary.
    expect(() => {
      assembler.end();
    }).not.toThrow();
    // The reversed stream still carries a message_start, so a summary is a
    // property this case can require rather than guard on: behind an
    // `if (summary !== null)` a regression that makes this stream yield null
    // leaves the assertion below unrun and the case green.
    const summary = assembler.end();
    expect(summary).not.toBeNull();
    expect(summary?.messageId.trim()).not.toBe('');
  });
});

describe('E — the declared network contract', () => {
  const ORG = '11111111-2222-4333-8444-555555555555';
  const CONV = '66666666-7777-4888-8999-aaaaaaaaaaaa';
  const ROUTE = `/api/organizations/${ORG}/chat_conversations/${CONV}/completion`;

  it('E1: one conversation endpoint on claude.ai, matching the completion route', () => {
    expect(claudeAdapter.endpoints).toHaveLength(1);
    const endpoint = claudeAdapter.endpoints[0];
    expect(endpoint?.host).toBe('claude.ai');
    expect(endpoint?.kind).toBe('conversation');
    expect(endpoint?.path.test(ROUTE)).toBe(true);
  });

  it('E1b: the pattern is anchored, so it claims no neighbouring route', () => {
    const path = claudeAdapter.endpoints[0]?.path;
    expect(path).toBeDefined();
    // The tap matches path+query, so an unanchored tail is what a query string
    // would slip through; the prefix cases are the mirror of that.
    for (const miss of [
      `${ROUTE}?beta=true`,
      `${ROUTE}/retry`,
      `/proxy${ROUTE}`,
      `/api/organizations/${ORG}/chat_conversations/${CONV}/title`,
      `/api/organizations/${ORG}/chat_conversations/${CONV}`,
      `/api/organizations/${ORG}/projects`,
      // Both ids are shape-matched: a segment that is not id-shaped is not this route.
      `/api/organizations/${ORG}/chat_conversations/latest/completion`,
    ]) {
      expect(path?.test(miss), miss).toBe(false);
    }
  });

  it('E1c: requiredPaths name only fields the capture showed populated', () => {
    // A declared path the site never fills makes closeExchange record a shape
    // miss on every healthy turn, so a permanently-absent field would read as
    // permanent drift. stopReason and usage are absent from this stream and
    // are deliberately not named.
    expect(claudeAdapter.requiredPaths).toEqual({
      request: ['model', 'prompt'],
      response: ['messageId', 'model', 'responseText'],
    });
  });

  it('E2: parseRequest never throws, and reports the shape met only when both fields are read', () => {
    const unmet = [
      '',
      '{}',
      'not json',
      '[]',
      'null',
      '"a string"',
      '{"prompt":"hi"}',
      '{"model":"m"}',
      '{"model":"","prompt":"hi"}',
      '{"model":123,"prompt":"hi"}',
      'a'.repeat(1024 * 1024),
    ];
    for (const input of unmet) {
      let parsed: ParsedRequest | undefined;
      expect(() => {
        parsed = claudeAdapter.parseRequest(input, EXCHANGE);
      }, input.slice(0, 40)).not.toThrow();
      expect(parsed?.requiredPathsSeen, input.slice(0, 40)).toBe(false);
    }
  });

  it('E2b: a body carrying both fields reports them, and invents no conversation id', () => {
    const parsed = claudeAdapter.parseRequest(
      '{"model":"a-model","prompt":"hi","extra":1}',
      EXCHANGE,
    );
    expect(parsed.requiredPathsSeen).toBe(true);
    expect(parsed.model).toBe('a-model');
    expect(parsed.prompt).toBe('hi');
    // The completion body carries the two turn message uuids and no
    // conversation uuid — that id exists only in the URL, which this seam is
    // not passed. Returning a message uuid under that name would put a wrong
    // id on every stored row.
    expect(parsed.conversationId).toBeUndefined();
  });
});
