import type { ModelTokenUsage, TokenUsageSummary } from '@akasecurity/schema';
import { renderToString } from 'ink';
import { createElement } from 'react';
import { describe, expect, it } from 'vitest';

import { Dashboard } from '../../src/tui/Dashboard.tsx';
import type { FindingStatus, HealthReport } from '../../src/tui/report.ts';

const STATUS: FindingStatus = {
  score: 90,
  unreviewed: { critical: 0, high: 0, medium: 0, low: 0 },
  openFindings: 0,
};

const REPORT: HealthReport = {
  title: 'Health',
  gauges: [],
  openFindings: 0,
  scanCoverage: 1,
  week: [],
  weekFindings: 0,
  recommendCount: 0,
  unreviewed: { critical: 0, high: 0, medium: 0, low: 0 },
  score: 90,
};

function model(over: Partial<ModelTokenUsage>): ModelTokenUsage {
  return {
    provider: 'anthropic',
    model: 'claude-sonnet-4-5',
    inputTokens: 1000,
    outputTokens: 0,
    cacheTokens: 0,
    totalTokens: 1000,
    estimatedCostUsd: 0.5,
    channel: 'api_key',
    costBasis: 'estimated',
    ...over,
  };
}

function renderHealth(tokenUsage: TokenUsageSummary): string {
  return renderToString(
    createElement(Dashboard, {
      home: '/tmp/aka-home',
      report: REPORT,
      status: STATUS,
      findings: [],
      recommendations: [],
      tokenUsage,
      initialView: 'health',
    }),
    { columns: 200 },
  );
}

describe('aka tui — token usage', () => {
  it('shows one row per channel of a model, the subscription one as API-equivalent', () => {
    const out = renderHealth({
      sessionCount: 2,
      totalTokens: 2000,
      estimatedCostUsd: 0.5,
      costIsPartial: false,
      apiEquivalentUsd: 3,
      apiEquivalentIsPartial: false,
      models: [
        model({}),
        model({ channel: 'subscription', costBasis: 'api_equivalent', estimatedCostUsd: 3 }),
      ],
    });
    expect(out).toContain('$0.50 · $3.00 API-equivalent');
    expect(out).toContain('$3.00 API-eq.');
    expect(out.match(/anthropic\/claude-sonnet-4-5/g)).toHaveLength(2);
    expect(out).toContain('not spend');
  });

  it('says which figure an unpriced row leaves a lower bound', () => {
    const out = renderHealth({
      sessionCount: 1,
      totalTokens: 2000,
      estimatedCostUsd: 0,
      costIsPartial: true,
      apiEquivalentUsd: 0,
      apiEquivalentIsPartial: true,
      models: [
        model({ estimatedCostUsd: null, costBasis: null }),
        model({ channel: 'subscription', estimatedCostUsd: null, costBasis: null }),
      ],
    });
    expect(out).toContain('cost is a lower bound');
    expect(out).toContain('API-equivalent is a lower bound');
  });
});
