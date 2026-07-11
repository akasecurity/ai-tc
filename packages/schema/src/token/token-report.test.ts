import { describe, expect, it } from 'vitest';

import type { LlmCallAttributes } from '../zod/meta.ts';
import type { CostModel } from './cost-model.ts';
import { aggregateTokenUsage, buildTokenReports, type LlmCallLeaf } from './token-report.ts';

// A deterministic fake cost model: $1 per leaf for anthropic, `null` (unknown)
// otherwise. Keeps the aggregation tests independent of the real price map.
const fakeCost: CostModel = {
  normalizeModelId: (provider, model) => ({ provider, model }),
  costFor: ({ provider }) => (provider === 'anthropic' ? 1 : null),
};

function leaf(sessionId: string, attributes: LlmCallAttributes): LlmCallLeaf {
  return { sessionId, attributes };
}

// Assert exactly one element and return it (no non-null assertions in tests).
function only<T>(arr: readonly T[]): T {
  expect(arr).toHaveLength(1);
  const [first] = arr;
  if (first === undefined) throw new Error('expected exactly one element');
  return first;
}

describe('buildTokenReports', () => {
  it('groups leaves by (provider, model) within a session and sums every token field', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', {
          provider: 'anthropic',
          model: 'claude-sonnet-4-5',
          input_tokens: 100,
          output_tokens: 50,
          cache_read_input_tokens: 10,
        }),
        leaf('s1', {
          provider: 'anthropic',
          model: 'claude-sonnet-4-5',
          input_tokens: 200,
          output_tokens: 80,
          cache_creation_input_tokens: 20,
        }),
      ],
      fakeCost,
    );

    const report = only(reports);
    expect(report.sessionId).toBe('s1');
    const rollup = only(report.rollups);
    expect(rollup.inputTokens).toBe(300);
    expect(rollup.outputTokens).toBe(130);
    expect(rollup.cacheRead).toBe(10);
    expect(rollup.cacheCreation).toBe(20);
    expect(rollup.totalTokens).toBe(300 + 130 + 20 + 10);
    expect(rollup.estimatedCostUsd).toBe(2); // two priced leaves × $1
    expect(report.totalTokens).toBe(460);
    expect(report.estimatedCostUsd).toBe(2);
    expect(report.costIsPartial).toBe(false);
  });

  it('splits a session into one rollup per model', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', { provider: 'anthropic', model: 'claude-sonnet-4-5', input_tokens: 100 }),
        leaf('s1', { provider: 'anthropic', model: 'claude-opus-4-8', input_tokens: 50 }),
      ],
      fakeCost,
    );
    expect(only(reports).rollups).toHaveLength(2);
  });

  it('null cost for an unknown (provider, model) sets costIsPartial', () => {
    const reports = buildTokenReports(
      [leaf('s1', { provider: 'ollama', model: 'llama3', input_tokens: 100, output_tokens: 50 })],
      fakeCost,
    );
    const report = only(reports);
    expect(only(report.rollups).estimatedCostUsd).toBeNull();
    expect(report.estimatedCostUsd).toBeNull();
    expect(report.costIsPartial).toBe(true);
  });

  it('mixed priced + unpriced: session cost is the priced sum, costIsPartial true', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', { provider: 'anthropic', model: 'claude-sonnet-4-5', input_tokens: 100 }),
        leaf('s1', { provider: 'ollama', model: 'llama3', input_tokens: 999 }),
      ],
      fakeCost,
    );
    const report = only(reports);
    expect(report.estimatedCostUsd).toBe(1); // only the anthropic rollup is priced
    expect(report.costIsPartial).toBe(true);
    expect(report.rollups).toHaveLength(2);
  });

  it('defaults a missing provider/model to "unknown" (and prices it null)', () => {
    const reports = buildTokenReports([leaf('s1', { input_tokens: 10 })], fakeCost);
    const rollup = only(only(reports).rollups);
    expect(rollup.provider).toBe('unknown');
    expect(rollup.model).toBe('unknown');
    expect(rollup.estimatedCostUsd).toBeNull();
  });

  it('separates sessions and orders them by total tokens (largest first)', () => {
    const reports = buildTokenReports(
      [
        leaf('small', { provider: 'anthropic', model: 'm', input_tokens: 10 }),
        leaf('big', { provider: 'anthropic', model: 'm', input_tokens: 1000 }),
      ],
      fakeCost,
    );
    expect(reports.map((r) => r.sessionId)).toEqual(['big', 'small']);
  });

  it('returns an empty array when there are no leaves', () => {
    expect(buildTokenReports([], fakeCost)).toEqual([]);
  });
});

describe('aggregateTokenUsage', () => {
  it('collapses rollups across sessions onto one (provider, model) row with grand totals', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', {
          provider: 'anthropic',
          model: 'claude-sonnet-4-5',
          input_tokens: 100,
          output_tokens: 50,
          cache_creation_input_tokens: 10,
          cache_read_input_tokens: 20,
        }),
        leaf('s2', {
          provider: 'anthropic',
          model: 'claude-sonnet-4-5',
          input_tokens: 200,
          output_tokens: 60,
        }),
      ],
      fakeCost,
    );
    const summary = aggregateTokenUsage(reports);

    expect(summary.sessionCount).toBe(2);
    expect(summary.models).toHaveLength(1);
    const row = summary.models[0];
    expect(row?.provider).toBe('anthropic');
    expect(row?.inputTokens).toBe(300);
    expect(row?.outputTokens).toBe(110);
    expect(row?.cacheTokens).toBe(30); // 10 creation + 20 read, merged
    expect(row?.totalTokens).toBe(440);
    expect(row?.estimatedCostUsd).toBe(2); // $1/leaf × 2 anthropic leaves
    expect(summary.estimatedCostUsd).toBe(2);
    expect(summary.costIsPartial).toBe(false);
  });

  it('orders model rows by total tokens (largest first)', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', { provider: 'anthropic', model: 'small', input_tokens: 10 }),
        leaf('s1', { provider: 'anthropic', model: 'big', input_tokens: 5000 }),
      ],
      fakeCost,
    );
    const summary = aggregateTokenUsage(reports);
    expect(summary.models.map((m) => m.model)).toEqual(['big', 'small']);
  });

  it('flags a partial total and nulls an unpriced model row', () => {
    const reports = buildTokenReports(
      [
        leaf('s1', { provider: 'anthropic', model: 'm', input_tokens: 100 }),
        leaf('s1', { provider: 'ollama', model: 'llama3', input_tokens: 999 }),
      ],
      fakeCost,
    );
    const summary = aggregateTokenUsage(reports);

    expect(summary.costIsPartial).toBe(true);
    expect(summary.estimatedCostUsd).toBe(1); // only the anthropic rollup priced
    const ollama = summary.models.find((m) => m.provider === 'ollama');
    expect(ollama?.estimatedCostUsd).toBeNull();
  });

  it('returns an empty summary for no reports', () => {
    expect(aggregateTokenUsage([])).toEqual({
      models: [],
      sessionCount: 0,
      totalTokens: 0,
      estimatedCostUsd: 0,
      costIsPartial: false,
    });
  });
});
