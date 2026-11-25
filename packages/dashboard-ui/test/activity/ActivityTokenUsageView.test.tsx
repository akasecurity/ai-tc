import type { TokenUsageSummary } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ActivityTokenUsageView } from '../../src/activity/ActivityTokenUsageView.tsx';

function summary(over: Partial<TokenUsageSummary> = {}): TokenUsageSummary {
  return {
    models: [
      {
        provider: 'anthropic',
        model: 'claude-haiku-4-5',
        inputTokens: 1000,
        outputTokens: 0,
        cacheTokens: 0,
        totalTokens: 1000,
        estimatedCostUsd: 0.5,
        channel: 'api_key',
        costBasis: 'estimated',
      },
    ],
    sessionCount: 1,
    totalTokens: 1000,
    estimatedCostUsd: 0.5,
    costIsPartial: false,
    apiEquivalentUsd: 0,
    apiEquivalentIsPartial: false,
    ...over,
  };
}

function chip(s: TokenUsageSummary): string {
  return renderToStaticMarkup(
    <ActivityTokenUsageView summary={s} isLoading={false} error={null} />,
  );
}

describe('ActivityTokenUsageView chip', () => {
  it('shows only the spend estimate when no usage is on a subscription', () => {
    expect(chip(summary())).toContain('1K tokens · $0.50<');
  });

  it('shows the API-equivalent value apart from spend when some usage is', () => {
    const s = summary({
      apiEquivalentUsd: 12,
      models: [
        ...summary().models,
        {
          provider: 'anthropic',
          model: 'claude-opus-4-8',
          inputTokens: 5000,
          outputTokens: 0,
          cacheTokens: 0,
          totalTokens: 5000,
          estimatedCostUsd: 12,
          channel: 'subscription',
          costBasis: 'api_equivalent',
        },
      ],
    });
    expect(chip(s)).toContain('$0.50 · $12.00 API-equivalent');
  });
});
