// The lower-bound notes every plugin's token renderer prints, asserted once and run
// against each plugin's own `renderTokens`.
import { describe, expect, it } from 'vitest';

import type { SessionTokenReport, TokenRollup } from '../../packages/schema/src/zod/meta.ts';

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

export function describeTokenNotes(
  renderTokens: (reports: SessionTokenReport[]) => string,
  notes: { readonly spend: string; readonly apiEquivalent: string },
): void {
  describe('renderTokens lower-bound notes', () => {
    it('names the API-equivalent total alone when the unpriced row is a subscription', () => {
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
      expect(out).toContain(notes.apiEquivalent);
      expect(out).not.toContain(notes.spend);
    });

    it('names the spend total alone when the unpriced row is per-token', () => {
      const out = renderTokens([
        report({ costIsPartial: true, rollups: [rollup({ model: 'unpriced' })] }),
      ]);
      expect(out).toContain(notes.spend);
      expect(out).not.toContain(notes.apiEquivalent);
    });
  });
}
