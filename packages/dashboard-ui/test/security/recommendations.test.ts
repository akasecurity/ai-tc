import type { FindingView, HealthStatus, HealthSummary } from '@akasecurity/schema';
import {
  buildRecommendations as schemaBuildRecommendations,
  DetectionCategory,
  findingStatus as schemaFindingStatus,
  healthScore as schemaHealthScore,
  recommendationCopy,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { FindingStatus } from '../../src/security/recommendations.ts';
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

// The `./recommendations` subpath is a published entry point: `cli/src/tui/report.ts`
// imports the rollup and the posture score from it by name, and the maths behind
// those names now lives in `@akasecurity/schema`. So what this module owes is the
// WIRING — that each name still resolves to the one shared implementation. The
// behaviour itself is asserted against that implementation in
// `packages/schema/test/security/recommendations.test.ts`; re-asserting it here
// would re-run schema's suite through a re-export and would go green on a local
// copy that had drifted back, which is the defect the move removed.
describe('the ./recommendations re-exports', () => {
  it("names schema's own functions, not a second copy of them", () => {
    expect(buildRecommendations).toBe(schemaBuildRecommendations);
    expect(findingStatus).toBe(schemaFindingStatus);
    expect(healthScore).toBe(schemaHealthScore);
  });

  it("keeps FindingStatus as the historical name for schema's HealthStatus", () => {
    // The annotations are the assertion — an alias that stopped resolving fails the
    // build here rather than in the CLI, which is the consumer that cannot move.
    const status: FindingStatus = findingStatus(summary());
    const asSchema: HealthStatus = status;
    expect(asSchema).toBe(status);
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

  it('labels a navigate action for where it GOES, never with a remediation verb', () => {
    // The label is the text on a button that opens a list and changes nothing.
    // `recommendationCopy(category).action` is the verb — Rotate, Remove, Strip,
    // Fix — and it is right where the CLI and the three plugins print it, as
    // advice in prose. On a button it promises work the click does not do, which
    // is the same defect as the enabled-but-dead "View all" this card removed.
    //
    // Driven across every category, and each is checked against that category's
    // OWN verb rather than a list written here: a table of verbs would have to
    // be kept in step with schema's, and would pass while both drifted together.
    for (const category of DetectionCategory.options) {
      const actions = buildRecommendedActions([finding({ category, severity: 'critical' })]);
      const label = actions[0]?.action.label;
      expect(label).toBe('Review findings');
      expect(label).not.toBe(recommendationCopy(category).action);
    }
  });

  it('keeps the same label when the host supplies no destination', () => {
    // The disabled branch is where a remediation verb read worst: a row offering
    // to "Rotate" that cannot even navigate. The label must not vary with the
    // href, or the two branches make different promises.
    const withHref = buildRecommendedActions([finding({ severity: 'critical' })], {
      hrefForRule: () => '/findings?view=flat',
    });
    const without = buildRecommendedActions([finding({ severity: 'critical' })]);
    expect(without[0]?.action.label).toBe(withHref[0]?.action.label);
  });
});
