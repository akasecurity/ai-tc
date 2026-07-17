import type { FindingView, HealthSummary } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  buildRecommendations,
  buildRecommendedActions,
  findingStatus,
  healthScore,
} from '../../src/security/recommendations.ts';

function summary(overrides: Partial<HealthSummary> = {}): HealthSummary {
  return {
    findings: 10,
    bySeverity: { critical: 1, high: 2, medium: 3, low: 4 },
    byAction: { block: 2, redact: 4, warn: 1, allow: 3, log: 0 },
    coverage: 0.5,
    ...overrides,
  };
}

function finding(overrides: Partial<FindingView>): FindingView {
  return {
    id: 'f1',
    eventId: 'e1',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'high',
    maskedMatch: 'A****Z',
    actionTaken: 'redact',
    confidence: 0.9,
    occurredAt: '2026-07-01T00:00:00.000Z',
    sourceTool: 'claude-code',
    kind: 'prompt',
    ...overrides,
  };
}

describe('healthScore', () => {
  it('blends coverage (60%) with the handled ratio (40%)', () => {
    // handled = 2+4+1 = 7 of 10 → 0.7; score = 100*(0.6*0.5 + 0.4*0.7) = 58
    expect(healthScore(summary())).toBe(58);
  });

  it('treats zero findings as fully handled', () => {
    expect(healthScore(summary({ findings: 0, coverage: 1 }))).toBe(100);
  });
});

describe('findingStatus', () => {
  it('carries the severity buckets and open count through', () => {
    const status = findingStatus(summary());
    expect(status.openFindings).toBe(10);
    expect(status.unreviewed).toEqual({ critical: 1, high: 2, medium: 3, low: 4 });
  });
});

describe('buildRecommendations', () => {
  it('buckets by category, keyed to the most severe rule, sorted by weight', () => {
    const recs = buildRecommendations([
      finding({ category: 'pii', severity: 'low', ruleId: 'core-pii/email' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
    ]);
    expect(recs).toHaveLength(2);
    expect(recs[0]?.severity).toBe('critical');
    expect(recs[0]?.title).toBe('Exposed secret detected');
    expect(recs[0]?.context).toBe('secrets/private-key · 2 findings');
    expect(recs[1]?.severity).toBe('low');
  });

  it('returns nothing for no findings', () => {
    expect(buildRecommendations([])).toEqual([]);
  });
});

describe('buildRecommendedActions', () => {
  it('shapes the same buckets as schema RecommendedActions with a rule subject', () => {
    const actions = buildRecommendedActions([
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
    ]);
    expect(actions).toHaveLength(1);
    const action = actions[0];
    expect(action?.severity).toBe('critical');
    expect(action?.subjects).toEqual([
      { type: 'rule', id: 'secrets/private-key', label: 'secrets/private-key · 2 findings' },
    ]);
    expect(action?.action.mode).toBe('navigate');
    expect(action?.action.href).toBe('/findings');
  });

  it('coerces an unknown severity string to low (closed enum)', () => {
    const actions = buildRecommendedActions([finding({ severity: 'bogus' })]);
    expect(actions[0]?.severity).toBe('low');
  });
});
