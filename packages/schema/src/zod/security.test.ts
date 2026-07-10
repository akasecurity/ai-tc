import { describe, expect, it } from 'vitest';

import {
  MttrTrendPoint,
  MttrTrendResponse,
  RecentlyResolvedResponse,
  ResolvedFeedItem,
  SeveritySummaryItem,
  SeveritySummaryResponse,
} from './security.ts';

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

describe('MttrTrendPoint', () => {
  it('parses a valid bucket, including a null per-severity MTTR value', () => {
    const result = MttrTrendPoint.safeParse({
      timestamp: '2026-07-01',
      bySeverity: { critical: 3_600_000, high: 7_200_000, medium: null, low: 0 },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.bySeverity.medium).toBeNull();
      expect(result.data.bySeverity.critical).toBe(3_600_000);
    }
  });

  it('rejects a negative MTTR value', () => {
    const result = MttrTrendPoint.safeParse({
      timestamp: '2026-07-01',
      bySeverity: { critical: -1, high: null, medium: null, low: null },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a bySeverity map missing a required key', () => {
    const result = MttrTrendPoint.safeParse({
      timestamp: '2026-07-01',
      bySeverity: { critical: 1, high: null, medium: null },
    });
    expect(result.success).toBe(false);
  });
});

describe('MttrTrendResponse', () => {
  it('parses a valid response, mirroring FindingsTimeseriesResponse shape', () => {
    const result = MttrTrendResponse.safeParse({
      range: '30d',
      granularity: 'day',
      points: [
        {
          timestamp: '2026-07-01',
          bySeverity: { critical: null, high: null, medium: null, low: null },
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects an invalid range', () => {
    const result = MttrTrendResponse.safeParse({
      range: 'invalid',
      granularity: 'day',
      points: [],
    });
    expect(result.success).toBe(false);
  });
});

describe('ResolvedFeedItem', () => {
  it('parses a valid item', () => {
    const result = ResolvedFeedItem.safeParse({
      findingKey: 'finding_abc123',
      ruleId: 'rule_secret_aws_key',
      severity: 'high',
      path: 'src/config/secrets.ts',
      resolvedAt: 1_752_000_000_000,
      detectedAt: 1_751_000_000_000,
    });
    expect(result.success).toBe(true);
  });

  it('rejects an invalid severity', () => {
    const result = ResolvedFeedItem.safeParse({
      findingKey: 'finding_abc123',
      ruleId: 'rule_secret_aws_key',
      severity: 'urgent',
      path: 'src/config/secrets.ts',
      resolvedAt: 1_752_000_000_000,
      detectedAt: 1_751_000_000_000,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a non-numeric resolvedAt', () => {
    const result = ResolvedFeedItem.safeParse({
      findingKey: 'finding_abc123',
      ruleId: 'rule_secret_aws_key',
      severity: 'high',
      path: 'src/config/secrets.ts',
      resolvedAt: '2026-07-08T00:00:00Z',
      detectedAt: 1_751_000_000_000,
    });
    expect(result.success).toBe(false);
  });
});

describe('RecentlyResolvedResponse', () => {
  it('parses a valid response', () => {
    const result = RecentlyResolvedResponse.safeParse({
      items: [
        {
          findingKey: 'finding_abc123',
          ruleId: 'rule_secret_aws_key',
          severity: 'high',
          path: 'src/config/secrets.ts',
          resolvedAt: 1_752_000_000_000,
          detectedAt: 1_751_000_000_000,
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects an item with a wrong-typed field', () => {
    const result = RecentlyResolvedResponse.safeParse({
      items: [
        {
          findingKey: 'finding_abc123',
          ruleId: 'rule_secret_aws_key',
          severity: 'high',
          path: 'src/config/secrets.ts',
          resolvedAt: 1_752_000_000_000,
          detectedAt: 'not-a-number',
        },
      ],
    });
    expect(result.success).toBe(false);
  });
});
