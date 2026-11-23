import type { SessionTokenReport, TokenRollup } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { renderTokens } from '../src/render.ts';

const SPEND_NOTE = 'cost is a lower bound';
const API_EQ_NOTE = 'API-equivalent is a lower bound';

function rollup(over: Partial<TokenRollup>): TokenRollup {
  return {
    sessionId: 's1',
    provider: 'anthropic',
    model: 'm',
    inputTokens: 0,
    outputTokens: 0,
    cacheCreation: 0,
    cacheRead: 0,
    totalTokens: 100,
    estimatedCostUsd: null,
    channel: 'api_key',
    costBasis: null,
    ...over,
  };
}

function report(over: Partial<SessionTokenReport>): SessionTokenReport {
  return {
    sessionId: 's1',
    rollups: [],
    totalTokens: 100,
    estimatedCostUsd: null,
    costIsPartial: false,
    apiEquivalentUsd: null,
    apiEquivalentIsPartial: false,
    ...over,
  };
}

describe('renderTokens partial-pricing notes', () => {
  it('says only the API-equivalent figure is a lower bound when an unpriced row is a subscription', () => {
    const out = renderTokens([
      report({
        estimatedCostUsd: 0.1,
        apiEquivalentIsPartial: true,
        rollups: [
          rollup({ model: 'priced', estimatedCostUsd: 0.1, costBasis: 'estimated' }),
          rollup({ model: 'unpriced', channel: 'subscription' }),
        ],
      }),
    ]);
    expect(out).toContain(API_EQ_NOTE);
    expect(out).not.toContain(SPEND_NOTE);
  });

  it('says only spend is a lower bound when an unpriced row is per-token', () => {
    const out = renderTokens([
      report({ costIsPartial: true, rollups: [rollup({ model: 'unpriced' })] }),
    ]);
    expect(out).toContain(SPEND_NOTE);
    expect(out).not.toContain(API_EQ_NOTE);
  });
});
