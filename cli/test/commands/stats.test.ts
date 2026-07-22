import type { SeveritySummaryResponse, TokenUsageSummary } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { renderFindingsSummary, renderTokenUsage } from '../../src/commands/stats.ts';

describe('renderFindingsSummary', () => {
  it('shows Caught (sum of per-severity caught) and Needs remediation (top-level needsRemediation)', () => {
    const summary: SeveritySummaryResponse = {
      total: 4,
      needsRemediation: 2,
      bySeverity: [
        { severity: 'critical', count: 2, caught: 1, openAtRest: 1 },
        { severity: 'high', count: 1, caught: 1, openAtRest: 0 },
        { severity: 'medium', count: 1, caught: 0, openAtRest: 1 },
        { severity: 'low', count: 0, caught: 0, openAtRest: 0 },
      ],
    };

    const text = renderFindingsSummary(summary);
    const lines = text.split('\n');

    expect(lines[0]).toBe('Findings: 4 total');
    expect(text).toContain('critical');
    expect(text).toMatch(/Caught\s+2/);
    expect(text).toMatch(/Needs remediation\s+2/);
  });

  it('defaults missing caught/openAtRest/needsRemediation to 0 (legacy pre-resolution summary)', () => {
    const summary: SeveritySummaryResponse = {
      total: 1,
      bySeverity: [
        { severity: 'critical', count: 1 },
        { severity: 'high', count: 0 },
        { severity: 'medium', count: 0 },
        { severity: 'low', count: 0 },
      ],
    };

    const text = renderFindingsSummary(summary);

    expect(text).toMatch(/Caught\s+0/);
    expect(text).toMatch(/Needs remediation\s+0/);
  });
});

describe('renderTokenUsage', () => {
  it('summarizes sessions, tokens, cost, and the top models', () => {
    const summary: TokenUsageSummary = {
      sessionCount: 3,
      totalTokens: 1_250_000,
      estimatedCostUsd: 3.4,
      costIsPartial: false,
      models: [
        {
          provider: 'anthropic',
          model: 'claude-opus-4-8',
          inputTokens: 900_000,
          outputTokens: 60_000,
          cacheTokens: 20_000,
          totalTokens: 980_000,
          estimatedCostUsd: 3.2,
        },
        {
          provider: 'anthropic',
          model: 'claude-haiku-4-5',
          inputTokens: 250_000,
          outputTokens: 15_000,
          cacheTokens: 5_000,
          totalTokens: 270_000,
          estimatedCostUsd: 0.2,
        },
      ],
    };

    const text = renderTokenUsage(summary, '30d');
    const lines = text.split('\n');

    expect(lines[0]).toBe('Token usage (30d): 3 sessions · 1.3M tokens · $3.40');
    expect(text).toContain('anthropic/claude-opus-4-8');
    expect(text).toContain('980K');
    expect(text).toContain('$3.20');
    expect(text).not.toContain('≥'); // fully priced → no lower-bound marker
  });

  it('marks an unpriced model and a lower-bound total', () => {
    const summary: TokenUsageSummary = {
      sessionCount: 1,
      totalTokens: 500,
      estimatedCostUsd: 0,
      costIsPartial: true,
      models: [
        {
          provider: 'ollama-unknown',
          model: 'llama3',
          inputTokens: 500,
          outputTokens: 0,
          cacheTokens: 0,
          totalTokens: 500,
          estimatedCostUsd: null,
        },
      ],
    };

    const text = renderTokenUsage(summary, '7d');
    expect(text).toContain('≥ $0.00');
    expect(text).toMatch(/llama3\s+500\s+—/);
    expect(text).toContain('lower bound');
  });

  it('renders an empty state when no tokens were recorded', () => {
    const summary: TokenUsageSummary = {
      sessionCount: 0,
      totalTokens: 0,
      estimatedCostUsd: 0,
      costIsPartial: false,
      models: [],
    };
    expect(renderTokenUsage(summary, '30d')).toBe('Token usage (30d): none recorded');
  });
});
