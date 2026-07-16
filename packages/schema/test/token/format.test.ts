import { describe, expect, it } from 'vitest';

import { formatCostTotal, formatTokenCount, formatUsd } from '../../src/token/format.ts';

describe('formatTokenCount', () => {
  it('prints exact integers under 1000', () => {
    expect(formatTokenCount(0)).toBe('0');
    expect(formatTokenCount(500)).toBe('500');
    expect(formatTokenCount(999)).toBe('999');
  });

  it('rolls up k → M → B at each 1000x boundary', () => {
    expect(formatTokenCount(1_000)).toBe('1.0k');
    expect(formatTokenCount(12_340)).toBe('12.3k');
    expect(formatTokenCount(1_000_000)).toBe('1.0M'); // 1000k rolls to 1M
    expect(formatTokenCount(4_500_000)).toBe('4.5M');
    expect(formatTokenCount(1_000_000_000)).toBe('1.0B'); // 1000M rolls to 1B
    // The real-store total that used to render as "4464193.1k".
    expect(formatTokenCount(4_464_193_100)).toBe('4.5B');
  });

  it('is negative-safe', () => {
    expect(formatTokenCount(-2_500_000)).toBe('-2.5M');
  });
});

describe('formatUsd', () => {
  it('uses 2 dp for a clean total and 4 dp for a sub-10¢ estimate', () => {
    expect(formatUsd(3.4)).toBe('$3.40');
    expect(formatUsd(0)).toBe('$0.00');
    expect(formatUsd(0.065)).toBe('$0.0650');
  });
});

describe('formatCostTotal', () => {
  it('marks a partial total as a lower bound, else prints the plain figure', () => {
    expect(formatCostTotal(3.4, false)).toBe('$3.40');
    expect(formatCostTotal(3.4, true)).toBe('≥ $3.40');
    expect(formatCostTotal(0, true)).toBe('≥ $0.00');
  });
});
