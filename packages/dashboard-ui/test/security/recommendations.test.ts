import type { FindingView, HealthSummary } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
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

describe('buildRecommendedActions', () => {
  it('shapes the same buckets as schema RecommendedActions with a rule subject', () => {
    const actions = buildRecommendedActions([
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
    ]);
    expect(actions).toHaveLength(1);
    const action = actions[0];
    expect(action?.severity).toBe('critical');
    // The count is the named rule's own, so the card's label and the findings URL
    // the host builds from that rule describe the same set.
    expect(action?.subjects).toEqual([
      { type: 'rule', id: 'secrets/private-key', label: 'secrets/private-key · 1 finding' },
    ]);
    expect(action?.action.mode).toBe('navigate');
    // No host builder supplied, so no destination is invented. A generic
    // `/findings` here would name the whole unfiltered list under a row reading
    // "<rule> · N findings"; the card renders a hrefless action disabled instead.
    expect(action?.action.href).toBeUndefined();
  });

  it('builds the destination the host supplies, for the rule the row names', () => {
    const actions = buildRecommendedActions(
      [finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' })],
      { hrefForRule: (ruleId) => `/findings?type=${encodeURIComponent(ruleId)}&view=flat` },
    );
    expect(actions[0]?.action.href).toBe('/findings?type=secrets%2Fprivate-key&view=flat');
  });

  it('omits the href when the host builder declines a rule', () => {
    const actions = buildRecommendedActions(
      [finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' })],
      { hrefForRule: () => undefined },
    );
    expect(actions[0]?.action.href).toBeUndefined();
  });

  it('coerces an unknown severity string to low (closed enum)', () => {
    const actions = buildRecommendedActions([finding({ severity: 'bogus' })]);
    expect(actions[0]?.severity).toBe('low');
  });
});
