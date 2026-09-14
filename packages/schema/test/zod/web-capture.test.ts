import { describe, expect, it } from 'vitest';

import { EventMetadata } from '../../src/zod/event.ts';
import { toCaptureAttributes } from '../../src/zod/local.ts';
import { CaptureAttributes } from '../../src/zod/meta.ts';
import {
  RESPONSE_TEXT_MAX_BYTES,
  WebCaptureStatus,
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
