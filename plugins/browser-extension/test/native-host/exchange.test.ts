import { bundledDetections, scanText } from '@akasecurity/plugin-sdk';
import { defaultCostModel, RESPONSE_TEXT_MAX_BYTES, WebExchange } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { TargetScanner } from '../../src/native-host/exchange.ts';
import {
  capResponseText,
  toLlmCallInput,
  toToolCallInputs,
} from '../../src/native-host/exchange.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const ISO = '2026-09-04T10:00:00.000Z';
const SESSION = 'session-1';

// The bundled rule's own example, so no secret-shaped literal is written by
// hand — same pattern as host.test.ts's secretFixture().
const RULE_ID = 'secrets/twilio-key';
function secretFixture(): string {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return example;
}
const SECRET_EXAMPLE = secretFixture();

// A minimal, schema-shaped exchange for tests that only exercise ONE field at
// a time. Not passed through WebExchange.parse() — these cases are about the
// projection's own logic, not the schema's.
function baseExchange(over: Partial<WebExchange> = {}): WebExchange {
  return {
    messageId: 'msg_1',
    startedAt: ISO,
    usageSource: 'none',
    toolCalls: [],
    truncated: false,
    ...over,
  };
}

const noopScanner: TargetScanner = (text) => ({ masked: text, findings: [] });

describe('capResponseText', () => {
  it('cuts text over the ceiling and raises truncated', () => {
    const big = 'y'.repeat(RESPONSE_TEXT_MAX_BYTES + 100);
    const capped = capResponseText(baseExchange({ responseText: big }), RESPONSE_TEXT_MAX_BYTES);
    expect(capped.responseText?.length).toBeLessThan(big.length);
    expect(capped.truncated).toBe(true);
  });

  it('leaves text at or under the ceiling untouched, and does not raise truncated', () => {
    const small = 'hello world';
    const capped = capResponseText(baseExchange({ responseText: small }), RESPONSE_TEXT_MAX_BYTES);
    expect(capped.responseText).toBe(small);
    expect(capped.truncated).toBe(false);
  });

  it('cuts on a UTF-8 character boundary', () => {
    // Four bytes per character in UTF-8, so a plain length-based cut lands
    // mid-character and a naive byte slice would store a replacement char.
    const text = '💥'.repeat(1000);
    const capped = capResponseText(baseExchange({ responseText: text }), 10);
    expect(capped.responseText ?? '').not.toContain('�');
    expect(new TextEncoder().encode(capped.responseText ?? '').byteLength).toBeLessThanOrEqual(10);
    expect(capped.truncated).toBe(true);
  });

  it('ORs an already-true truncated forward even when it cuts nothing', () => {
    const capped = capResponseText(
      baseExchange({ responseText: 'short', truncated: true }),
      RESPONSE_TEXT_MAX_BYTES,
    );
    expect(capped.truncated).toBe(true);
  });

  it('defaults to RESPONSE_TEXT_MAX_BYTES', () => {
    const big = 'z'.repeat(3 * 1024 * 1024);
    // No second argument — the ceiling must be enforced by the default alone.
    const capped = capResponseText(baseExchange({ responseText: big }));
    expect(capped.truncated).toBe(true);
    expect(new TextEncoder().encode(capped.responseText ?? '').byteLength).toBeLessThanOrEqual(
      RESPONSE_TEXT_MAX_BYTES,
    );
  });
});

describe('toLlmCallInput', () => {
  it('maps every declared WebExchange field, key by key', () => {
    // Parsed through the real schema (not just typed as one) so a field
    // deleted from WebExchange strips here too, turning this red — a literal
    // object typed as WebExchange would not notice the schema shrinking.
    const exchange = WebExchange.parse({
      messageId: 'msg_2',
      startedAt: ISO,
      model: 'claude-opus-5',
      usage: {
        inputTokens: 10,
        outputTokens: 20,
        cacheReadInputTokens: 5,
        cacheCreationInputTokens: 3,
      },
      usageSource: 'site',
      stopReason: 'end_turn',
      conversationId: 'conv_1',
      turnIndex: 4,
      toolCalls: [{ toolUseId: 'tu_1', toolName: 'web_search' }],
      responseText: 'hello',
      truncated: true,
    });

    const input = toLlmCallInput(exchange, SESSION, 'chatgpt');
    expect(input).not.toBeNull();
    const attrs = input?.attributes ?? {};

    expect(input?.sessionId).toBe(SESSION);
    expect(input?.messageId).toBe('msg_2');
    expect(input?.parentId).toBe(SESSION);
    expect(input?.rootSessionId).toBe(SESSION);
    expect(input?.startedAt).toBe(ISO);

    expect(attrs.model).toBe('claude-opus-5');
    expect(attrs.provider).toBe('chatgpt');
    expect(attrs.input_tokens).toBe(10);
    expect(attrs.output_tokens).toBe(20);
    expect(attrs.cache_read_input_tokens).toBe(5);
    expect(attrs.cache_creation_input_tokens).toBe(3);
    expect(attrs.usage_source).toBe('site');
    expect(attrs.stop_reason).toBe('end_turn');
    expect(attrs.message_id).toBe('msg_2');
    expect(attrs.run_key).toBe('conv_1');
    expect(attrs.site_conversation_id).toBe('conv_1');
    expect(attrs.turn_index).toBe(4);
    expect(attrs.response_truncated).toBe(true);
  });

  it('sets provider to the web tool id, not the vendor', () => {
    expect(toLlmCallInput(baseExchange(), SESSION, 'chatgpt')?.attributes.provider).toBe('chatgpt');
    expect(toLlmCallInput(baseExchange(), SESSION, 'claude-ai')?.attributes.provider).toBe(
      'claude-ai',
    );
  });

  it('is unpriceable at the web tool id, with a positive control at the vendor id', () => {
    const usage = { inputTokens: 1000 };
    // The web tool id is what the cost model actually sees.
    const provider = toLlmCallInput(baseExchange(), SESSION, 'chatgpt')?.attributes.provider ?? '';
    expect(defaultCostModel.costFor({ provider, model: 'gpt-4o', usage })).toBeNull();
    // Positive control: the SAME model, priced under the vendor id, is a real
    // number — proving the provider string, not the model, makes it null.
    expect(defaultCostModel.costFor({ provider: 'openai', model: 'gpt-4o', usage })).toBeTypeOf(
      'number',
    );
  });

  it("'estimated' writes only the estimated fields, leaving the priced ones absent", () => {
    const exchange = baseExchange({
      usage: {
        inputTokens: 7,
        outputTokens: 9,
        cacheReadInputTokens: 2,
        cacheCreationInputTokens: 1,
      },
      usageSource: 'estimated',
    });
    const attrs = toLlmCallInput(exchange, SESSION, 'chatgpt')?.attributes ?? {};
    expect(attrs.estimated_input_tokens).toBe(7);
    expect(attrs.estimated_output_tokens).toBe(9);
    expect('input_tokens' in attrs).toBe(false);
    expect('output_tokens' in attrs).toBe(false);
    expect('cache_read_input_tokens' in attrs).toBe(false);
    expect('cache_creation_input_tokens' in attrs).toBe(false);
  });

  it("'none' writes no count at all, priced or estimated, even when counts are present", () => {
    const exchange = baseExchange({
      usage: { inputTokens: 7, outputTokens: 9 },
      usageSource: 'none',
    });
    const attrs = toLlmCallInput(exchange, SESSION, 'chatgpt')?.attributes ?? {};
    expect('input_tokens' in attrs).toBe(false);
    expect('output_tokens' in attrs).toBe(false);
    expect('estimated_input_tokens' in attrs).toBe(false);
    expect('estimated_output_tokens' in attrs).toBe(false);
    expect(attrs.usage_source).toBe('none');
  });

  it("'site' with no counts writes usage_source and no count field", () => {
    const attrs =
      toLlmCallInput(baseExchange({ usageSource: 'site' }), SESSION, 'chatgpt')?.attributes ?? {};
    expect(attrs.usage_source).toBe('site');
    expect('input_tokens' in attrs).toBe(false);
    expect('output_tokens' in attrs).toBe(false);
  });

  it('writes usage_source for all three values', () => {
    for (const source of ['site', 'estimated', 'none'] as const) {
      const attrs =
        toLlmCallInput(baseExchange({ usageSource: source }), SESSION, 'chatgpt')?.attributes ?? {};
      expect(attrs.usage_source).toBe(source);
    }
  });

  it('omits response_truncated, rather than writing false, when truncated is false', () => {
    const attrs =
      toLlmCallInput(baseExchange({ truncated: false }), SESSION, 'chatgpt')?.attributes ?? {};
    expect('response_truncated' in attrs).toBe(false);
  });

  it('yields null for a whitespace-only message id', () => {
    expect(toLlmCallInput(baseExchange({ messageId: ' ' }), SESSION, 'chatgpt')).toBeNull();
    expect(toLlmCallInput(baseExchange({ messageId: '\t\n' }), SESSION, 'chatgpt')).toBeNull();
  });

  it('trims a padded message id consistently at the key and in the bag', () => {
    const input = toLlmCallInput(baseExchange({ messageId: '  msg_9  ' }), SESSION, 'chatgpt');
    expect(input?.messageId).toBe('msg_9');
    expect(input?.attributes.message_id).toBe('msg_9');
  });

  it('never fabricates run_key or site_conversation_id when there is no conversation id', () => {
    const attrs = toLlmCallInput(baseExchange(), SESSION, 'chatgpt')?.attributes ?? {};
    expect('run_key' in attrs).toBe(false);
    expect('site_conversation_id' in attrs).toBe(false);
  });

  it('trims a padded model, stop reason and conversation id', () => {
    // Unlike messageId, none of these three carries a .min(1) in WebExchange,
    // so a padded or blank value parses and reaches the bag as it is written.
    const attrs =
      toLlmCallInput(
        baseExchange({
          model: '  gpt-4o  ',
          stopReason: ' end_turn ',
          conversationId: '  conv_1  ',
        }),
        SESSION,
        'chatgpt',
      )?.attributes ?? {};
    expect(attrs.model).toBe('gpt-4o');
    expect(attrs.stop_reason).toBe('end_turn');
    expect(attrs.run_key).toBe('conv_1');
    expect(attrs.site_conversation_id).toBe('conv_1');
  });

  it('drops a blank model, stop reason and conversation id rather than writing ""', () => {
    // A blank run_key is durable and the read side groups on it: the activity
    // turns rollup counts a row whose run_key is '' because '' passes its
    // `IS NOT NULL` filter, so a blank id reads as a turn that is not one.
    const attrs =
      toLlmCallInput(
        baseExchange({ model: '   ', stopReason: '\t', conversationId: '  ' }),
        SESSION,
        'chatgpt',
      )?.attributes ?? {};
    expect('model' in attrs).toBe(false);
    expect('stop_reason' in attrs).toBe(false);
    expect('run_key' in attrs).toBe(false);
    expect('site_conversation_id' in attrs).toBe(false);
  });

  it('anchors parentId and rootSessionId at the session id', () => {
    const input = toLlmCallInput(baseExchange(), SESSION, 'chatgpt');
    expect(input?.parentId).toBe(SESSION);
    expect(input?.rootSessionId).toBe(SESSION);
  });
});

describe('toToolCallInputs: what a target may cost to scan', () => {
  it('hands the scanner a bounded target, however long the raw one is', () => {
    // The scan is shieldPointers + scan + redact over the whole value, and one
    // host process serves every tab in sequence, so an unbounded target stalls
    // every other tab's capture, exchange and ping behind it. The masked value
    // was already size-capped for storage; this bounds the WORK.
    let scanned = '';
    const measuring: TargetScanner = (text) => {
      scanned = text;
      return { masked: text, findings: [] };
    };
    const exchange = WebExchange.parse({
      messageId: 'msg_big_target',
      startedAt: ISO,
      usageSource: 'none',
      toolCalls: [{ toolUseId: 'tu_big', toolName: 'web_search', target: 'z'.repeat(300_000) }],
    });

    toToolCallInputs(exchange, SESSION, measuring);
    expect(scanned.length).toBeGreaterThan(0);
    expect(scanned.length).toBeLessThan(300_000);
  });

  it('scans an ordinary target whole', () => {
    // The control: the ceiling sits far above any target this can audit, so a
    // real one must reach the scanner untouched. Without this the case above
    // would pass with the target cut to nothing.
    let scanned = '';
    const measuring: TargetScanner = (text) => {
      scanned = text;
      return { masked: text, findings: [] };
    };
    const target = 'https://example.test/search?q=' + 'a'.repeat(2_000);
    const exchange = WebExchange.parse({
      messageId: 'msg_ord_target',
      startedAt: ISO,
      usageSource: 'none',
      toolCalls: [{ toolUseId: 'tu_ord', toolName: 'web_search', target }],
    });

    toToolCallInputs(exchange, SESSION, measuring);
    expect(scanned).toBe(target);
  });

  it('bounds how many tool calls one turn contributes', () => {
    // Each entry costs a scan. A five-figure list is not a turn this can
    // audit; the tail is dropped rather than the whole exchange refused, so
    // the reply, the usage and the llm_call leaf all survive.
    const exchange = WebExchange.parse({
      messageId: 'msg_many',
      startedAt: ISO,
      usageSource: 'none',
      toolCalls: Array.from({ length: 1_000 }, (_unused, i) => ({
        toolUseId: `tu_${String(i)}`,
        toolName: 'web_search',
        target: 'q',
      })),
    });

    const inputs = toToolCallInputs(exchange, SESSION, noopScanner);
    expect(inputs.length).toBeGreaterThan(0);
    expect(inputs.length).toBeLessThan(1_000);
  });
});

describe('toToolCallInputs', () => {
  it('maps every declared WebToolCall field, key by key', () => {
    // Parsed through the real schema, for the same reason the llm_call whole-
    // shape case is: a field deleted from WebToolCall must turn this red.
    const exchange = WebExchange.parse({
      messageId: 'msg_3',
      startedAt: ISO,
      usageSource: 'none',
      conversationId: 'conv_7',
      toolCalls: [
        {
          toolUseId: 'tu_1',
          toolName: 'web_search',
          target: 'weather in paris',
          isError: false,
          inputSize: 12,
          outputSize: 34,
        },
      ],
    });

    const [input] = toToolCallInputs(exchange, SESSION, noopScanner);
    expect(input).toBeDefined();
    expect(input?.sessionId).toBe(SESSION);
    expect(input?.toolUseId).toBe('tu_1');
    expect(input?.parentId).toBe(SESSION);
    expect(input?.rootSessionId).toBe(SESSION);
    expect(input?.startedAt).toBe(ISO);
    expect(input?.attributes.tool_use_id).toBe('tu_1');
    expect(input?.attributes.tool_name).toBe('web_search');
    expect(input?.attributes.target).toBe('weather in paris');
    expect(input?.attributes.is_error).toBe(false);
    expect(input?.attributes.input_size).toBe(12);
    expect(input?.attributes.output_size).toBe(34);
    expect(input?.attributes.run_key).toBe('conv_7');
  });

  it('writes is_error: false rather than omitting it', () => {
    const exchange = baseExchange({
      toolCalls: [{ toolUseId: 't1', toolName: 'x', isError: false }],
    });
    const [input] = toToolCallInputs(exchange, SESSION, noopScanner);
    expect('is_error' in (input?.attributes ?? {})).toBe(true);
    expect(input?.attributes.is_error).toBe(false);
  });

  it('drops a tool call whose toolUseId is whitespace, keeping the others', () => {
    const exchange = baseExchange({
      toolCalls: [
        { toolUseId: '  ', toolName: 'x' },
        { toolUseId: 't2', toolName: 'y' },
      ],
    });
    const inputs = toToolCallInputs(exchange, SESSION, noopScanner);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.toolUseId).toBe('t2');
  });

  it('drops a duplicate toolUseId, keeping the first', () => {
    const exchange = baseExchange({
      toolCalls: [
        { toolUseId: 't1', toolName: 'first' },
        { toolUseId: 't1', toolName: 'second' },
      ],
    });
    const inputs = toToolCallInputs(exchange, SESSION, noopScanner);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.attributes.tool_name).toBe('first');
  });

  it('keeps a tool call with a blank toolName, omitting the attribute', () => {
    const exchange = baseExchange({ toolCalls: [{ toolUseId: 't1', toolName: ' ' }] });
    const inputs = toToolCallInputs(exchange, SESSION, noopScanner);
    expect(inputs).toHaveLength(1);
    expect('tool_name' in (inputs[0]?.attributes ?? {})).toBe(false);
  });

  it('trims a padded toolName, and a padded conversation id at the leaf run_key', () => {
    const exchange = baseExchange({
      conversationId: '  conv_7  ',
      toolCalls: [{ toolUseId: 't1', toolName: '  web_search  ' }],
    });
    const attrs = toToolCallInputs(exchange, SESSION, noopScanner)[0]?.attributes ?? {};
    expect(attrs.tool_name).toBe('web_search');
    expect(attrs.run_key).toBe('conv_7');
  });

  it('drops a blank conversation id rather than writing "" to the leaf run_key', () => {
    const exchange = baseExchange({
      conversationId: '   ',
      toolCalls: [{ toolUseId: 't1', toolName: 'web_search' }],
    });
    const attrs = toToolCallInputs(exchange, SESSION, noopScanner)[0]?.attributes ?? {};
    expect('run_key' in attrs).toBe(false);
  });

  it('masks the target through the injected scanner and truncates after masking', () => {
    // The secret straddles the truncation boundary (500 chars): a raw-first
    // ordering would truncate to a partial, still-unmasked secret prefix
    // before the scanner ever ran on it, while a mask-first ordering replaces
    // the whole secret with a marker before the cut ever applies. The rule's
    // pattern is word-bounded (`\bAC[…]{32}\b`), so the fill ends in a space
    // rather than another word character — otherwise the boundary the rule
    // requires immediately before the secret would never be there.
    const prefix = `${'x'.repeat(489)} `;
    const target = `${prefix}${SECRET_EXAMPLE}`;
    const scanner: TargetScanner = (text) => scanText(text);
    const exchange = baseExchange({
      toolCalls: [{ toolUseId: 't1', toolName: 'search', target }],
    });
    const [input] = toToolCallInputs(exchange, SESSION, scanner);
    const stored = input?.attributes.target ?? '';

    // Positive control first: the surviving prefix is really there, so the
    // absence assertion below is not passing on empty bytes.
    expect(stored.startsWith('x'.repeat(50))).toBe(true);
    expect(stored).toHaveLength(501);
    expect(stored.endsWith('…')).toBe(true);
    expectNoEchoOf(stored, SECRET_EXAMPLE);
  });

  it('omits target when the mask returns the empty string', () => {
    const emptyScanner: TargetScanner = () => ({ masked: '', findings: [] });
    const exchange = baseExchange({
      toolCalls: [{ toolUseId: 't1', toolName: 'x', target: 'anything' }],
    });
    const [input] = toToolCallInputs(exchange, SESSION, emptyScanner);
    expect('target' in (input?.attributes ?? {})).toBe(false);
  });

  it('writes one inspection per finding with actionTaken log', () => {
    const scanner: TargetScanner = (text) => scanText(text);
    const exchange = baseExchange({
      toolCalls: [{ toolUseId: 't1', toolName: 'x', target: SECRET_EXAMPLE }],
    });
    const [input] = toToolCallInputs(exchange, SESSION, scanner);
    const inspections = input?.inspections ?? [];
    expect(inspections).toHaveLength(1);
    expect(inspections[0]?.ruleId).toBe(RULE_ID);
    expect(inspections[0]?.actionTaken).toBe('log');
    expect(inspections[0]?.ruleName).toBeTypeOf('string');
    expect(inspections[0]?.ruleVersion).toBeTypeOf('string');
    expect(inspections[0]?.category).toBe('secret');
    expect(inspections[0]?.severity).toBeTypeOf('string');
    expect(inspections[0]?.span).toBeDefined();
    expect(inspections[0]?.maskedMatch).toBeTypeOf('string');
    expect(inspections[0]?.confidence).toBeTypeOf('number');
  });

  it('leaves inspections empty for a tool call with no target, and never calls the scanner', () => {
    const exchange = baseExchange({ toolCalls: [{ toolUseId: 't1', toolName: 'x' }] });
    const throwingScanner: TargetScanner = () => {
      throw new Error('scanner must not be called when there is no target');
    };
    const [input] = toToolCallInputs(exchange, SESSION, throwingScanner);
    expect(input?.inspections).toEqual([]);
  });

  it('does not throw when toolCalls is absent, yielding an empty array', () => {
    // Cast rather than parsed: proves the projection itself guards this,
    // not merely that a caller upstream materialized the schema default.
    const exchange = {
      messageId: 'msg_4',
      startedAt: ISO,
      usageSource: 'none',
    } as unknown as WebExchange;
    expect(() => toToolCallInputs(exchange, SESSION, noopScanner)).not.toThrow();
    expect(toToolCallInputs(exchange, SESSION, noopScanner)).toEqual([]);
  });
});
