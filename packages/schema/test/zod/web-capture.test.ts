import { describe, expect, it } from 'vitest';

import { EventMetadata } from '../../src/zod/event.ts';
import { toCaptureAttributes } from '../../src/zod/local.ts';
import { CaptureAttributes } from '../../src/zod/meta.ts';
import {
  fromCaptureStatusAttributes,
  pickReportedCaptureStatus,
  RESPONSE_TEXT_MAX_BYTES,
  toCaptureStatusAttributes,
  WebCaptureStatus,
  webCaptureStatusObservedTurnPath,
  WebEnforcementState,
  WebExchange,
  WebToolCall,
  WebUsage,
  WebUsageSource,
} from '../../src/zod/web-capture.ts';

const ISO = '2026-09-04T10:00:00.000Z';

describe('WebExchange', () => {
  it('parses a minimal exchange, defaulting the collection and the truncation flag', () => {
    const parsed = WebExchange.parse({
      messageId: 'msg_1',
      startedAt: ISO,
      usageSource: 'none',
    });
    // Defaults are load-bearing: the host projects `toolCalls` straight into a
    // batch write, and an undefined there is a crash rather than an empty pass.
    expect(parsed.toolCalls).toEqual([]);
    expect(parsed.truncated).toBe(false);
  });

  it('carries the model, usage and tool calls a site reported', () => {
    const parsed = WebExchange.parse({
      messageId: 'msg_2',
      startedAt: ISO,
      model: 'claude-x-1',
      usage: { inputTokens: 12, outputTokens: 34 },
      usageSource: 'site',
      stopReason: 'end_turn',
      conversationId: 'conv_1',
      turnIndex: 3,
      toolCalls: [{ toolUseId: 'tu_1', toolName: 'web_search', target: 'https://example.test' }],
      responseText: 'hello',
    });
    expect(parsed.model).toBe('claude-x-1');
    expect(parsed.usage?.outputTokens).toBe(34);
    expect(parsed.toolCalls[0]?.toolName).toBe('web_search');
  });

  it('refuses an exchange with no message id — the llm_call key is derived from it', () => {
    // A blank key would collapse every turn of a conversation onto one
    // deterministic row id, so the UPSERT-take-MAX would overwrite the session's
    // whole token history with its largest single turn.
    expect(
      WebExchange.safeParse({ messageId: '', startedAt: ISO, usageSource: 'none' }).success,
    ).toBe(false);
  });

  it('refuses a non-ISO startedAt', () => {
    expect(
      WebExchange.safeParse({ messageId: 'm', startedAt: 'yesterday', usageSource: 'none' })
        .success,
    ).toBe(false);
  });

  it('refuses a usage source outside the vocabulary', () => {
    // 'estimated' must stay distinguishable from 'site' downstream: the read
    // side prices only what a site actually reported.
    expect(WebUsageSource.options).toEqual(['site', 'estimated', 'none']);
    expect(
      WebExchange.safeParse({ messageId: 'm', startedAt: ISO, usageSource: 'guessed' }).success,
    ).toBe(false);
  });

  it('refuses negative and fractional token counts', () => {
    expect(WebUsage.safeParse({ inputTokens: -1 }).success).toBe(false);
    expect(WebUsage.safeParse({ inputTokens: 1.5 }).success).toBe(false);
  });
});

describe('WebToolCall', () => {
  it('requires both natural-key halves', () => {
    expect(WebToolCall.safeParse({ toolUseId: '', toolName: 'x' }).success).toBe(false);
    expect(WebToolCall.safeParse({ toolUseId: 'x', toolName: '' }).success).toBe(false);
  });
});

describe('WebCaptureStatus', () => {
  it('defaults the miss list so a healthy tab reports an empty one, never undefined', () => {
    const parsed = WebCaptureStatus.parse({
      patched: true,
      live: true,
      blind: false,
      sendsSeenDom: 2,
      exchangesSeenNet: 2,
      parseFailures: 0,
      unparsedBodies: 0,
    });
    expect(parsed.shapeMisses).toEqual([]);
  });

  it('defaults conversationEndpoints to 0 for a status from a build that predates it', () => {
    const parsed = WebCaptureStatus.parse({
      patched: true,
      live: false,
      blind: false,
      sendsSeenDom: 0,
      exchangesSeenNet: 0,
      parseFailures: 0,
      unparsedBodies: 0,
    });
    expect(parsed.conversationEndpoints).toBe(0);
  });

  it('defaults closed to false for a status from a build that predates it', () => {
    const parsed = WebCaptureStatus.parse({
      patched: true,
      live: false,
      blind: false,
      sendsSeenDom: 0,
      exchangesSeenNet: 0,
      parseFailures: 0,
      unparsedBodies: 0,
    });
    expect(parsed.closed).toBe(false);
  });

  it('carries a declared endpoint count over the wire', () => {
    const parsed = WebCaptureStatus.parse({
      patched: true,
      live: false,
      blind: false,
      sendsSeenDom: 0,
      exchangesSeenNet: 0,
      parseFailures: 0,
      unparsedBodies: 0,
      conversationEndpoints: 2,
    });
    expect(parsed.conversationEndpoints).toBe(2);
  });

  it("defaults enforcement to 'unknown' for a status from a build that predates it", () => {
    // Not 'watching'. A build that cannot report what the DOM path is doing
    // must not be read as reporting that it is doing it — that is the failure
    // this field exists to end, restated one layer up.
    const parsed = WebCaptureStatus.parse({
      patched: true,
      live: false,
      blind: false,
      sendsSeenDom: 0,
      exchangesSeenNet: 0,
      parseFailures: 0,
      unparsedBodies: 0,
    });
    expect(parsed.enforcement).toBe('unknown');
  });

  it('carries every declared enforcement state over the wire', () => {
    // Iterated inside the body rather than through `it.each`: widening the
    // vocabulary to a bare string leaves `.options` undefined, which fails
    // COLLECTION and reports "no tests" instead of naming what broke.
    const states = WebEnforcementState.options;
    expect(states.length).toBeGreaterThan(0);
    for (const state of states) {
      const parsed = WebCaptureStatus.parse({
        patched: true,
        live: false,
        blind: false,
        sendsSeenDom: 0,
        exchangesSeenNet: 0,
        parseFailures: 0,
        unparsedBodies: 0,
        enforcement: state,
      });
      expect(parsed.enforcement).toBe(state);
    }
  });

  it('refuses an enforcement state outside the vocabulary', () => {
    const parsed = WebCaptureStatus.safeParse({
      patched: true,
      live: false,
      blind: false,
      sendsSeenDom: 0,
      exchangesSeenNet: 0,
      parseFailures: 0,
      unparsedBodies: 0,
      enforcement: 'healthy',
    });
    expect(parsed.success).toBe(false);
  });

  it('names both half-resolved composers, which are the two states seen live', () => {
    // chatgpt.com resolves a composer and no send button; its anonymous build
    // resolves a send button and no composer. Collapsing the pair into one
    // 'unattached' would report both as the same fault and name neither
    // selector.
    expect(WebEnforcementState.options).toContain('composer-only');
    expect(WebEnforcementState.options).toContain('button-only');
  });
});

describe('webCaptureStatusObservedTurnPath', () => {
  // Patched, one endpoint to watch, nothing seen: what a page relays the
  // moment its tap says it patched, and what every reload therefore writes.
  const WATCHING: WebCaptureStatus = {
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 1,
    closed: false,
    enforcement: 'watching',
    // The DOM half is orthogonal to everything these two suites measure; a
    // fixed healthy value keeps it from being read as a variable here.
  };

  it('is false for a tab that is watching and has seen nothing', () => {
    expect(webCaptureStatusObservedTurnPath(WATCHING)).toBe(false);
  });

  it('is false for a tab whose only activity is sends the network has not answered', () => {
    // Between the first DOM send and the strike count that trips `blind`, a
    // tab has no verdict — it has not yet given up on those sends.
    expect(webCaptureStatusObservedTurnPath({ ...WATCHING, sendsSeenDom: 2 })).toBe(false);
  });

  it('is false for a closing tab that observed nothing', () => {
    // `closed` is a property of the report, not evidence about the site: a
    // page that is unloading having seen nothing has still tested nothing,
    // and a report that qualified on it would let every navigation clear a
    // live verdict.
    expect(webCaptureStatusObservedTurnPath({ ...WATCHING, closed: true })).toBe(false);
  });

  it.each([
    ['a parsed exchange', { exchangesSeenNet: 1 }],
    ['sends the network never answered', { blind: true }],
    ['a missing declared field', { shapeMisses: ['a.b'] }],
    ['a parse failure', { parseFailures: 1 }],
    ['a body it could not read', { unparsedBodies: 1 }],
    ['a tap that hooked neither transport', { patched: false }],
    ['a build that declares no endpoints', { conversationEndpoints: 0 }],
  ])('is true for %s', (_label, overrides) => {
    expect(webCaptureStatusObservedTurnPath({ ...WATCHING, ...overrides })).toBe(true);
  });
});

describe('pickReportedCaptureStatus', () => {
  const WATCHING: WebCaptureStatus = {
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 1,
    closed: false,
    enforcement: 'watching',
    // The DOM half is orthogonal to everything these two suites measure; a
    // fixed healthy value keeps it from being read as a variable here.
  };
  const BLIND: WebCaptureStatus = { ...WATCHING, blind: true, sendsSeenDom: 3 };
  const ACTIVE: WebCaptureStatus = { ...WATCHING, live: true, exchangesSeenNet: 1 };

  it('skips watching-only candidates ahead of a verdict', () => {
    // The reload the `blind` remediation asks for writes a WATCHING report; it
    // must not replace the report that asked for it before anything has
    // re-tested what was wrong.
    const picked = pickReportedCaptureStatus([
      { id: 'reload', status: WATCHING },
      { id: 'verdict', status: BLIND },
    ]);
    expect(picked?.id).toBe('verdict');
  });

  it('takes the newest candidate that did observe the turn path', () => {
    const picked = pickReportedCaptureStatus([
      { id: 'healthy', status: ACTIVE },
      { id: 'reload', status: WATCHING },
      { id: 'verdict', status: BLIND },
    ]);
    expect(picked?.id).toBe('healthy');
  });

  it('takes the newest candidate when none of them observed anything', () => {
    const picked = pickReportedCaptureStatus([
      { id: 'newest', status: WATCHING },
      { id: 'older', status: { ...WATCHING, sendsSeenDom: 1 } },
    ]);
    expect(picked?.id).toBe('newest');
  });

  it('answers no candidates with undefined', () => {
    const none: { id: string; status: WebCaptureStatus }[] = [];
    expect(pickReportedCaptureStatus(none)).toBeUndefined();
  });
});

describe('CaptureStatusAttributes round trip', () => {
  const FULL_STATUS: WebCaptureStatus = {
    patched: true,
    live: true,
    blind: true,
    sendsSeenDom: 4,
    exchangesSeenNet: 3,
    parseFailures: 2,
    unparsedBodies: 1,
    shapeMisses: ['message.id', 'usage.output_tokens'],
    conversationEndpoints: 3,
    closed: true,
    enforcement: 'composer-only',
  };

  it('round-trips a status with every field non-default', () => {
    const bag = toCaptureStatusAttributes(FULL_STATUS, 'claude-ai');
    expect(fromCaptureStatusAttributes(bag)).toEqual(FULL_STATUS);
  });

  it('names the tool under the canonical source_tool key', () => {
    expect(toCaptureStatusAttributes(FULL_STATUS, 'chatgpt').source_tool).toBe('chatgpt');
  });

  it('reads a bag that is not a status as null, rather than throwing', () => {
    expect(fromCaptureStatusAttributes({})).toBeNull();
    expect(fromCaptureStatusAttributes(null)).toBeNull();
    expect(fromCaptureStatusAttributes({ patched: 'yes' })).toBeNull();
  });
});

describe('the response-text cap', () => {
  it('is stated once, in bytes', () => {
    expect(RESPONSE_TEXT_MAX_BYTES).toBe(2 * 1024 * 1024);
  });
});

describe('correlation ids reach the stored attribute bag', () => {
  it('accepts the two new EventMetadata keys', () => {
    const parsed = EventMetadata.parse({ messageId: 'msg_9', conversationId: 'conv_9' });
    expect(parsed.messageId).toBe('msg_9');
    expect(parsed.conversationId).toBe('conv_9');
  });

  it('declares the two new CaptureAttributes keys as strings', () => {
    const parsed = CaptureAttributes.parse({ message_id: 'msg_9', conversation_id: 'conv_9' });
    expect(parsed.message_id).toBe('msg_9');
    expect(parsed.conversation_id).toBe('conv_9');
    // The bag ends in `.catchall(z.unknown())`, so it reads an undeclared key
    // back unchanged and the two assertions above hold with or without the
    // declarations. Refusing a wrong-typed value is the only thing declaring
    // them buys, so it is what pins them.
    expect(CaptureAttributes.safeParse({ message_id: 42 }).success).toBe(false);
    expect(CaptureAttributes.safeParse({ conversation_id: 42 }).success).toBe(false);
  });

  it('maps camelCase metadata onto the snake_case bag', () => {
    // Without this the two ids parse on both sides and are dropped in between,
    // so a response capture could never be joined to its own llm_call leaf.
    const attrs = toCaptureAttributes({
      id: '00000000-0000-4000-8000-000000000000',
      sourceTool: 'claude-ai',
      kind: 'response',
      occurredAt: ISO,
      contentHash: 'deadbeef',
      content: 'hi',
      metadata: { messageId: 'msg_9', conversationId: 'conv_9' },
    });
    expect(attrs.message_id).toBe('msg_9');
    expect(attrs.conversation_id).toBe('conv_9');
  });

  it('omits both keys when the metadata carries neither', () => {
    // Omitted, never null: every other optional key in this bag is spread
    // conditionally, and a null would land in the stored JSON as a real value.
    const attrs = toCaptureAttributes({
      id: '00000000-0000-4000-8000-000000000001',
      sourceTool: 'chatgpt',
      kind: 'prompt',
      occurredAt: ISO,
      contentHash: 'deadbeef',
      content: 'hi',
    });
    expect('message_id' in attrs).toBe(false);
    expect('conversation_id' in attrs).toBe(false);
  });
});
