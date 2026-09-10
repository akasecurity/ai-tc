// The recommendation rollup's canonical suite.
//
// It lives here, beside the one implementation, rather than being repeated per
// renderer. Four surfaces render this — the dashboard card, `aka tui`, and three
// plugins — and while the logic was copied per surface these assertions were too:
// only one copy had cases separating the per-rule count from the category volume,
// so the same mutation was invisible in the other three.
import { describe, expect, it } from 'vitest';

import type { FindingView } from '../../src/index.ts';
import { DetectionCategory } from '../../src/index.ts';
import { buildRecommendations } from '../../src/security/recommendations.ts';

function finding(overrides: Partial<FindingView> = {}): FindingView {
  return {
    id: 'f1',
    eventId: 'e1',
    ruleId: 'r1',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA****',
    actionTaken: 'block',
    confidence: 0.9,
    occurredAt: '2026-07-01T00:00:00.000Z',
    sourceTool: 'claude-code',
    kind: 'prompt',
    ...overrides,
  };
}

describe('buildRecommendations', () => {
  it('gives every detection category a written title and advice', () => {
    // The guard that would have caught `code_flaw` and `config` falling through.
    // Both tables are keyed by plain string, so an unlisted category compiles and
    // renders a raw fallback — "code_flaw finding" with a generic "Review" — and on
    // a store where that category ranks first it is the most prominent row.
    for (const category of DetectionCategory.options) {
      const recs = buildRecommendations([finding({ category, severity: 'critical' })]);
      expect(recs, `no recommendation built for ${category}`).toHaveLength(1);
      const rec = recs[0];
      expect(rec?.title, `${category} falls back to a raw title`).not.toBe(`${category} finding`);
      expect(rec?.description, `${category} falls back to generic advice`).not.toBe(
        'Review this finding against your policy.',
      );
    }
  });

  it('buckets by category, keyed to the most severe rule, sorted by weight', () => {
    const recs = buildRecommendations([
      finding({ category: 'pii', severity: 'low', ruleId: 'core-pii/email' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
    ]);
    expect(recs).toHaveLength(2);
    expect(recs[0]?.severity).toBe('critical');
    expect(recs[0]?.title).toBe('Exposed secret detected');
    // ONE finding, because the count is the named RULE's, not its category's. The
    // label pairs the two, so a category-wide count here would read
    // "secrets/private-key · 2 findings" over a rule that fired once.
    expect(recs[0]?.context).toBe('secrets/private-key · 1 finding');
    expect(recs[1]?.severity).toBe('low');
  });

  it('ranks on the CATEGORY volume, not the named rule tally', () => {
    // The label reports one rule so it can agree with the link, but ordering is
    // about which kind of exposure matters most. Ranking on the rule would put a
    // category holding 4 critical findings below one holding 2, because the rule
    // that names the busy category fired once.
    const recs = buildRecommendations([
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'pii', severity: 'critical', ruleId: 'core-pii/ssn' }),
      finding({ category: 'pii', severity: 'critical', ruleId: 'core-pii/ssn' }),
    ]);
    expect(recs.map((r) => r.title)).toEqual([
      'Exposed secret detected',
      'Personal data in a prompt',
    ]);
    // …and the busy category still reports its NAMED rule's count, which is 1.
    expect(recs[0]?.context).toBe('secrets/private-key · 1 finding');
  });

  it('tallies a rule across every category it appears in, matching what a link can filter', () => {
    // One rule id can hold definition rows in more than one category — a pack
    // version may move it — and the findings page has no category dimension: it
    // filters on `ruleId`. So both rows must report the rule's WHOLE tally, or a row
    // showing 1 would open a list of 3.
    const recs = buildRecommendations([
      finding({ category: 'secret', severity: 'critical', ruleId: 'shared/rule' }),
      finding({ category: 'custom', severity: 'critical', ruleId: 'shared/rule' }),
      finding({ category: 'custom', severity: 'critical', ruleId: 'shared/rule' }),
    ]);
    // Two rows, one per category, both naming the same rule and the same number —
    // which is the number `?type=shared/rule` returns.
    expect(recs.map((r) => r.context)).toEqual([
      'shared/rule · 3 findings',
      'shared/rule · 3 findings',
    ]);
  });

  it('counts the rule it names, not the category it buckets by', () => {
    // Two rules in one category, the most-severe firing once and its neighbour
    // three times: a category count would report 4 against the rule that fired once.
    const recs = buildRecommendations([
      finding({ category: 'secret', severity: 'critical', ruleId: 'secrets/private-key' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
      finding({ category: 'secret', severity: 'high', ruleId: 'secrets/aws-access-key' }),
    ]);
    expect(recs).toHaveLength(1);
    expect(recs[0]?.context).toBe('secrets/private-key · 1 finding');
  });

  it('returns nothing for no findings', () => {
    expect(buildRecommendations([])).toEqual([]);
  });
});
