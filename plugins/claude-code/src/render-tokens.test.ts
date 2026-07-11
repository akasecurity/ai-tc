import type { SessionTokenReport, TokenRollup } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { renderTokens } from './render.ts';

function rollup(over: Partial<TokenRollup> & { sessionId: string }): TokenRollup {
  return {
    provider: 'anthropic',
    model: 'm',
    inputTokens: 0,
    outputTokens: 0,
    cacheCreation: 0,
    cacheRead: 0,
    totalTokens: 0,
    estimatedCostUsd: null,
    ...over,
  };
}

function report(over: Partial<SessionTokenReport> & { sessionId: string }): SessionTokenReport {
  return { rollups: [], totalTokens: 0, estimatedCostUsd: null, costIsPartial: false, ...over };
}

describe('renderTokens', () => {
  it('shows an empty-state line when there are no reports', () => {
    expect(renderTokens([])).toMatch(/No token usage/);
  });

  it('renders a per-model table with thousands-formatted totals and a priced cost', () => {
    const out = renderTokens([
      report({
        sessionId: 's1',
        totalTokens: 1300,
        estimatedCostUsd: 0.42,
        rollups: [
          rollup({
            sessionId: 's1',
            model: 'claude-sonnet-4-5',
            inputTokens: 1000,
            outputTokens: 200,
            cacheCreation: 50,
            cacheRead: 50,
            totalTokens: 1300,
            estimatedCostUsd: 0.42,
          }),
        ],
      }),
    ]);
    expect(out).toContain('claude-sonnet-4-5');
    expect(out).toContain('1,300'); // locale thousands separator
    expect(out).toContain('$0.42');
    expect(out).not.toContain('≥'); // fully priced → no lower-bound marker
  });

  it('renders "—" for an unpriced row and a "≥" lower-bound total with a footnote', () => {
    const out = renderTokens([
      report({
        sessionId: 's1',
        totalTokens: 500,
        estimatedCostUsd: null,
        costIsPartial: true,
        rollups: [
          rollup({ sessionId: 's1', provider: 'ollama', model: 'llama3', totalTokens: 500 }),
        ],
      }),
    ]);
    expect(out).toContain('—');
    expect(out).toContain('≥');
    expect(out).toMatch(/unknown pricing/);
  });

  it('aggregates the same (provider, model) across sessions and sums cost', () => {
    const priced = (sessionId: string, input: number): TokenRollup =>
      rollup({ sessionId, inputTokens: input, totalTokens: input, estimatedCostUsd: 1 });
    const out = renderTokens([
      report({
        sessionId: 's1',
        totalTokens: 100,
        estimatedCostUsd: 1,
        rollups: [priced('s1', 100)],
      }),
      report({
        sessionId: 's2',
        totalTokens: 200,
        estimatedCostUsd: 1,
        rollups: [priced('s2', 200)],
      }),
    ]);
    expect(out).toContain('2 sessions');
    expect(out).toContain('300'); // 100 + 200 combined into one row
    expect(out).toContain('$2.00'); // 1 + 1 summed
  });
});
