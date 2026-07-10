import { describe, expect, it } from 'vitest';

import { SeveritySummaryItem, SeveritySummaryResponse } from './security.ts';

describe('SeveritySummaryResponse (resolution-aware extension)', () => {
  it('parses the legacy shape (no resolution fields)', () => {
    const result = SeveritySummaryResponse.safeParse({
      total: 3,
      bySeverity: [{ severity: 'high', count: 3 }],
    });
    expect(result.success).toBe(true);
  });

  it('parses with the new optional fields present', () => {
    const result = SeveritySummaryResponse.safeParse({
      total: 3,
      needsRemediation: 1,
      bySeverity: [{ severity: 'high', count: 3, caught: 2, openAtRest: 1 }],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.needsRemediation).toBe(1);
      expect(result.data.bySeverity[0]?.caught).toBe(2);
      expect(result.data.bySeverity[0]?.openAtRest).toBe(1);
    }
  });
});

describe('SeveritySummaryItem (resolution-aware extension)', () => {
  it('keeps count required and caught/openAtRest optional', () => {
    expect(SeveritySummaryItem.safeParse({ severity: 'low', count: 0 }).success).toBe(true);
    expect(
      SeveritySummaryItem.safeParse({ severity: 'low', count: 0, caught: 0, openAtRest: 0 })
        .success,
    ).toBe(true);
    // count is still required.
    expect(SeveritySummaryItem.safeParse({ severity: 'low' }).success).toBe(false);
  });
});
