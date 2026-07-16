import { describe, expect, it } from 'vitest';

import { defaultCostModel } from '../../src/token/cost-model.ts';

// Assert a derived cost is a real number (not null/unknown) and narrow the type
// so downstream numeric comparisons don't need non-null assertions.
function asNumber(value: number | null): number {
  expect(value).not.toBeNull();
  if (value === null) throw new Error('expected a numeric cost, got null');
  return value;
}

describe('defaultCostModel.costFor', () => {
  it('computes a plausible cost for a known (provider, model) from a usage bag', () => {
    // Opus 4.8: $5/MTok input, $25/MTok output. Cache read is priced at 0.1×
    // input ($0.50/MTok), far below input — this asserts that relationship.
    const cost = defaultCostModel.costFor({
      provider: 'anthropic',
      model: 'claude-opus-4-8',
      usage: {
        inputTokens: 1_000_000,
        outputTokens: 1_000_000,
        cacheReadTokens: 1_000_000,
      },
    });
    // 5 (input) + 25 (output) + 0.5 (cache read) = 30.5
    expect(cost).toBeCloseTo(30.5, 6);
  });

  it('prices cache reads far below uncached input for the same token count', () => {
    const inputOnly = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-opus-4-8',
        usage: { inputTokens: 1_000_000 },
      }),
    );
    const cacheReadOnly = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-opus-4-8',
        usage: { cacheReadTokens: 1_000_000 },
      }),
    );
    // Cache read should be roughly an order of magnitude cheaper than input.
    expect(cacheReadOnly).toBeLessThan(inputOnly / 5);
  });

  it('prices 1h cache writes higher than 5m cache writes', () => {
    const write5m = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        usage: { cacheWrite5mTokens: 1_000_000 },
      }),
    );
    const write1h = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        usage: { cacheWrite1hTokens: 1_000_000 },
      }),
    );
    expect(write1h).toBeGreaterThan(write5m);
  });

  it('prices claude-sonnet-5 at the Sonnet tier ($3/$15 per MTok)', () => {
    const cost = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-sonnet-5',
        usage: { inputTokens: 1_000_000, outputTokens: 1_000_000 },
      }),
    );
    // $3 input + $15 output.
    expect(cost).toBeCloseTo(18, 6);
  });

  it('adds a per-request web-search charge on top of token cost', () => {
    const cost = defaultCostModel.costFor({
      provider: 'anthropic',
      model: 'claude-haiku-4-5',
      usage: { inputTokens: 0, webSearchRequests: 10 },
    });
    // 10 requests × $0.01 = $0.10, no token cost.
    expect(cost).toBeCloseTo(0.1, 6);
  });

  it('applies the batch service-tier discount to token cost', () => {
    const standard = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-opus-4-8',
        usage: { inputTokens: 1_000_000, serviceTier: 'standard' },
      }),
    );
    const batch = asNumber(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-opus-4-8',
        usage: { inputTokens: 1_000_000, serviceTier: 'batch' },
      }),
    );
    expect(batch).toBeCloseTo(standard * 0.5, 6);
  });

  it('returns null for an unknown (provider, model) — never a guessed figure', () => {
    expect(
      defaultCostModel.costFor({
        provider: 'openrouter',
        model: 'some-unknown-model',
        usage: { inputTokens: 1_000_000, outputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });

  it('returns null for an unknown model on a known provider', () => {
    expect(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-imaginary-9',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });

  it('returns 0 (not null) for a local provider — local inference is free, not unknown', () => {
    expect(
      defaultCostModel.costFor({
        provider: 'ollama',
        model: 'llama3:70b',
        usage: { inputTokens: 5_000_000, outputTokens: 2_000_000 },
      }),
    ).toBe(0);
    expect(
      defaultCostModel.costFor({
        provider: 'local',
        model: 'anything',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBe(0);
  });
});

describe('defaultCostModel.normalizeModelId', () => {
  it('canonicalizes a Bedrock-prefixed model id but preserves the bedrock provider', () => {
    // The model id is stripped of region + version suffixes, but the provider
    // stays `bedrock` — it is NOT collapsed to `anthropic` (Bedrock pricing ≠
    // Anthropic-direct; see the never-guess rule).
    expect(
      defaultCostModel.normalizeModelId('bedrock', 'us.anthropic.claude-opus-4-8-v1:0'),
    ).toEqual({ provider: 'bedrock', model: 'claude-opus-4-8' });
  });

  it('canonicalizes a Vertex @version model id but preserves the vertex provider', () => {
    expect(defaultCostModel.normalizeModelId('vertex', 'claude-sonnet-4-6@20260101')).toEqual({
      provider: 'vertex',
      model: 'claude-sonnet-4-6',
    });
  });

  it('strips the anthropic/ gateway prefix on the model half but preserves the gateway provider', () => {
    // The `anthropic/` prefix is a display alias on the model id, not a billing
    // provider — it is stripped, but the calling provider (here a gateway) is kept.
    expect(defaultCostModel.normalizeModelId('openrouter', 'anthropic/claude-opus-4-8')).toEqual({
      provider: 'openrouter',
      model: 'claude-opus-4-8',
    });
  });

  it('canonicalizes the model id for an anthropic-direct provider (provider unchanged)', () => {
    expect(defaultCostModel.normalizeModelId('anthropic', 'anthropic/claude-opus-4-8')).toEqual({
      provider: 'anthropic',
      model: 'claude-opus-4-8',
    });
  });

  it('collapses any local-provider model onto the wildcard zero-cost key', () => {
    expect(defaultCostModel.normalizeModelId('ollama', 'llama3:70b')).toEqual({
      provider: 'ollama',
      model: '*',
    });
  });

  it('leaves an unknown gateway provider/model unchanged (no guessing)', () => {
    expect(defaultCostModel.normalizeModelId('openrouter', 'meta-llama/llama-3-70b')).toEqual({
      provider: 'openrouter',
      model: 'meta-llama/llama-3-70b',
    });
  });

  it('returns null for a Bedrock id — canonicalized, but bedrock pricing is unknown (not Anthropic-direct)', () => {
    // The id canonicalizes to claude-opus-4-8, but `(bedrock, ...)` is not in
    // PRICE_MAP, so cost is unknown — NOT silently the Anthropic-direct $5 figure.
    expect(
      defaultCostModel.costFor({
        provider: 'bedrock',
        model: 'anthropic.claude-opus-4-8',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });

  it('returns null for a Vertex id — canonicalized, but vertex pricing is unknown', () => {
    expect(
      defaultCostModel.costFor({
        provider: 'vertex',
        model: 'claude-sonnet-4-6@20260101',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });

  it('returns null for an anthropic/-gateway id — canonicalized, but gateway pricing is unknown', () => {
    expect(
      defaultCostModel.costFor({
        provider: 'openrouter',
        model: 'anthropic/claude-opus-4-8',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });

  it('prices claude-fable-5 — the flagship, $10/$50 per MTok', () => {
    const cost = defaultCostModel.costFor({
      provider: 'anthropic',
      model: 'claude-fable-5',
      usage: { inputTokens: 1_000_000, outputTokens: 1_000_000 },
    });
    expect(asNumber(cost)).toBeCloseTo(10 + 50, 6);
  });

  it('canonicalizes a dated id so it prices: claude-haiku-4-5-20251001 → claude-haiku-4-5', () => {
    // The -YYYYMMDD suffix that Claude Code stamps on some model ids must be
    // stripped, or a real, priceable model renders "unknown" (was the haiku miss).
    expect(defaultCostModel.normalizeModelId('anthropic', 'claude-haiku-4-5-20251001')).toEqual({
      provider: 'anthropic',
      model: 'claude-haiku-4-5',
    });
    const cost = defaultCostModel.costFor({
      provider: 'anthropic',
      model: 'claude-haiku-4-5-20251001',
      usage: { inputTokens: 1_000_000, outputTokens: 1_000_000 },
    });
    expect(asNumber(cost)).toBeCloseTo(1 + 5, 6);
  });
});
