import { describe, expect, it } from 'vitest';

import {
  API_EQUIVALENT_LOWER_BOUND_NOTE,
  API_EQUIVALENT_NOTE,
  compactNumber,
  formatCostTotal,
  formatModelCost,
  formatTokenCount,
  formatUsd,
  hasApiEquivalent,
  SPEND_LOWER_BOUND_NOTE,
  tokenCostNotes,
} from '../../src/token/format.ts';

describe('compactNumber', () => {
  it('prints exact integers under 1000', () => {
    expect(compactNumber(0)).toBe('0');
    expect(compactNumber(500)).toBe('500');
    expect(compactNumber(999)).toBe('999');
  });

  it('rolls up K → M → B → T at each 1000x boundary, dropping a trailing .0', () => {
    expect(compactNumber(1_000)).toBe('1K');
    expect(compactNumber(1_127)).toBe('1.1K');
    expect(compactNumber(12_340)).toBe('12.3K');
    expect(compactNumber(318_000)).toBe('318K');
    expect(compactNumber(1_000_000)).toBe('1M'); // 1000K rolls to 1M
    expect(compactNumber(4_500_000)).toBe('4.5M');
    expect(compactNumber(1_000_000_000)).toBe('1B'); // 1000M rolls to 1B
    expect(compactNumber(4_464_193_100)).toBe('4.5B');
    expect(compactNumber(1_500_000_000_000)).toBe('1.5T');
  });

  it('is negative-safe', () => {
    expect(compactNumber(-2_500_000)).toBe('-2.5M');
  });
});

describe('formatTokenCount', () => {
  it('is the shared compactNumber applied to a token count', () => {
    expect(formatTokenCount(999)).toBe('999');
    expect(formatTokenCount(12_340)).toBe('12.3K');
    expect(formatTokenCount(4_500_000)).toBe('4.5M');
    expect(formatTokenCount(4_464_193_100)).toBe('4.5B');
  });
});

describe('formatUsd', () => {
  it('uses 2 dp for a clean total and 4 dp for a sub-10¢ estimate', () => {
    expect(formatUsd(3.4)).toBe('$3.40');
    expect(formatUsd(0)).toBe('$0.00');
    expect(formatUsd(0.065)).toBe('$0.0650');
  });
});

describe('formatModelCost', () => {
  it('marks subscription value, and shows — for an unpriced row', () => {
    expect(formatModelCost(2.5, 'estimated')).toBe('$2.50');
    expect(formatModelCost(2.5, 'api_equivalent')).toBe('$2.50 API-eq.');
    expect(formatModelCost(null, null)).toBe('—');
  });
});

describe('tokenCostNotes', () => {
  const sub = [{ costBasis: 'api_equivalent' as const }];
  it('prints each note only for the total it qualifies', () => {
    expect(
      tokenCostNotes({ costIsPartial: false, apiEquivalentIsPartial: false, models: [] }),
    ).toEqual([]);
    expect(
      tokenCostNotes({ costIsPartial: true, apiEquivalentIsPartial: true, models: sub }),
    ).toEqual([SPEND_LOWER_BOUND_NOTE, API_EQUIVALENT_LOWER_BOUND_NOTE, API_EQUIVALENT_NOTE]);
    expect(hasApiEquivalent([{ costBasis: 'estimated' }, { costBasis: null }])).toBe(false);
  });
});

describe('formatCostTotal', () => {
  it('marks a partial total as a lower bound, else prints the plain figure', () => {
    expect(formatCostTotal(3.4, false)).toBe('$3.40');
    expect(formatCostTotal(3.4, true)).toBe('≥ $3.40');
    expect(formatCostTotal(0, true)).toBe('≥ $0.00');
  });
});
