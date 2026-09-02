import { describe, expect, it } from 'vitest';

import type { FindingGroup } from '../../src/zod/index.ts';
import {
  addToLocation,
  compareFindingGroupOrder,
  createInstanceFacetAccumulator,
  type FlatFindingRow,
  foldGroupStatus,
  matchesInstanceFilters,
  newLocationAccumulator,
  sortFindingGroups,
  toInstanceDetail,
} from '../../src/zod/index.ts';

function row(over: Partial<FlatFindingRow> = {}): FlatFindingRow {
  return {
    id: 'f1',
    ruleId: 'aws-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA****',
    actionTaken: 'block',
    confidence: 0.9,
    occurredAt: '2026-01-02T00:00:00.000Z',
    sourceTool: 'claude-code',
    repo: 'acme/api',
    file: 'a.ts',
    eventId: 'e1',
    status: 'handled',
    ...over,
  };
}

describe('matchesInstanceFilters', () => {
  it('passes a row when no filter is set', () => {
    expect(matchesInstanceFilters(row(), {})).toBe(true);
  });

  it('matches severity, subtype, action and status on the row itself', () => {
    expect(matchesInstanceFilters(row(), { severity: ['critical'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { severity: ['low'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { subtype: ['aws-key'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { subtype: ['email'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { actions: ['blocked'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { actions: ['warned'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { statuses: ['handled'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { statuses: ['open'] })).toBe(false);
  });

  it('maps the source tool through the shared provider mapper', () => {
    expect(matchesInstanceFilters(row(), { providers: ['claudecode'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { providers: ['cursor'] })).toBe(false);
  });

  it('treats provider api as the unknown-tool catch-all', () => {
    // 'api' is what an unmapped tool reads as, so it cannot be expressed as a
    // list of known tools — the case a SQL IN-predicate would get wrong.
    const unknown = row({ sourceTool: 'some-unmapped-tool' });
    expect(matchesInstanceFilters(unknown, { providers: ['api'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { providers: ['api'] })).toBe(false);
  });

  it('matches tool, repo and file exactly', () => {
    const withTool = row({ toolName: 'Bash' });
    expect(matchesInstanceFilters(withTool, { tools: ['Bash'] })).toBe(true);
    expect(matchesInstanceFilters(withTool, { tools: ['Read'] })).toBe(false);
    // A row with no tool matches no tool filter.
    expect(matchesInstanceFilters(row(), { tools: ['Bash'] })).toBe(false);

    expect(matchesInstanceFilters(row(), { repo: 'acme/api' })).toBe(true);
    expect(matchesInstanceFilters(row(), { repo: 'acme/web' })).toBe(false);
    expect(matchesInstanceFilters(row(), { file: 'a.ts' })).toBe(true);
    expect(matchesInstanceFilters(row(), { file: 'b.ts' })).toBe(false);
  });

  it('treats an empty repo or file filter as unset', () => {
    // The URL cannot tell an absent param from an empty one, so an empty value
    // must not silently filter to the no-repo bucket.
    expect(matchesInstanceFilters(row({ repo: 'acme/api' }), { repo: '' })).toBe(true);
    expect(matchesInstanceFilters(row({ file: '' }), { file: '' })).toBe(true);
  });

  it('matches q over the rendered via-tool label, not the bare name', () => {
    const withTool = row({ toolName: 'Bash' });
    expect(matchesInstanceFilters(withTool, { q: 'via bash' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'AKIA' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'acme/api' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'nothing-here' })).toBe(false);
  });

  it('ignores the named dimension when one is excepted', () => {
    const opts = { severity: ['low'], subtype: ['aws-key'] };
    expect(matchesInstanceFilters(row(), opts)).toBe(false);
    // Excepting the failing dimension passes, since the other still matches.
    expect(matchesInstanceFilters(row(), opts, 'severity')).toBe(true);
    // Excepting a different one does not rescue it.
    expect(matchesInstanceFilters(row(), opts, 'subtype')).toBe(false);
  });
});

describe('createInstanceFacetAccumulator', () => {
  it('counts instances per dimension', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', severity: 'critical' }));
    acc.add(row({ id: 'b', severity: 'low' }));
    acc.add(row({ id: 'c', severity: 'low' }));

    const facets = acc.facets();
    expect(Object.fromEntries(facets.severity.map((f) => [f.value, f.count]))).toEqual({
      critical: 1,
      low: 2,
    });
  });

  it('excludes each dimension own filter', () => {
    const acc = createInstanceFacetAccumulator({ severity: ['critical'] });
    acc.add(row({ id: 'a', severity: 'critical', sourceTool: 'claude-code' }));
    acc.add(row({ id: 'b', severity: 'low', sourceTool: 'cursor' }));

    const facets = acc.facets();
    // Severity ignores its own filter, so the low row is still counted —
    // that is what keeps "how many if I also pick low?" answerable.
    expect(Object.fromEntries(facets.severity.map((f) => [f.value, f.count]))).toEqual({
      critical: 1,
      low: 1,
    });
    // Every other dimension honors it, so the low row's provider is not.
    expect(Object.fromEntries(facets.provider.map((f) => [f.value, f.count]))).toEqual({
      claudecode: 1,
    });
  });

  it('counts no tool bucket for a row carrying none', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', toolName: 'Bash' }));
    acc.add(row({ id: 'b' }));
    expect(acc.facets().tool).toEqual([{ value: 'Bash', count: 1 }]);
  });

  it('orders each dimension by count, then value', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', ruleId: 'b-rule' }));
    acc.add(row({ id: 'b', ruleId: 'a-rule' }));
    acc.add(row({ id: 'c', ruleId: 'a-rule' }));
    expect(acc.facets().subtype).toEqual([
      { value: 'a-rule', count: 2 },
      { value: 'b-rule', count: 1 },
    ]);
  });
});

describe('toInstanceDetail', () => {
  it('translates DB values through the shared mappers', () => {
    const detail = toInstanceDetail(row({ actionTaken: 'log', sourceTool: 'cursor' }));

    expect(detail.action).toBe('monitored');
    expect(detail.provider).toBe('cursor');
    expect(detail.groupId).toBe('aws-key');
    expect(detail.subtype).toBe('aws-key');
    expect(detail.match).toEqual({ maskedValue: 'AKIA****', contextPrefix: '' });
    // No pack names in the local store, and the policy is synthesized from the
    // category — the same shape the grouped path produces.
    expect(detail.detection).toEqual({ id: 'aws-key', name: null });
    expect(detail.policy).toEqual({ id: 'category:secret', name: 'secret' });
  });

  it('carries the event linkage and omits an absent session', () => {
    expect(toInstanceDetail(row({ sessionId: 's1' })).sessionId).toBe('s1');
    expect(toInstanceDetail(row()).sessionId).toBeUndefined();
    expect(toInstanceDetail(row()).eventId).toBe('e1');
  });

  it('carries the attributed user and omits an absent one', () => {
    const user = { id: 'u1', name: 'alice@example.com' };
    expect(toInstanceDetail(row({ user })).user).toEqual(user);
    expect(toInstanceDetail(row())).not.toHaveProperty('user');
  });
});

describe('compareFindingGroupOrder', () => {
  const group = (
    over: Partial<FindingGroup>,
  ): Pick<FindingGroup, 'severity' | 'latestDetectedAt' | 'id'> => ({
    severity: 'critical',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    id: 'a',
    ...over,
  });

  it('orders by severity, then recency', () => {
    expect(
      compareFindingGroupOrder(group({ severity: 'critical' }), group({ severity: 'low' })),
    ).toBeLessThan(0);
    expect(
      compareFindingGroupOrder(
        group({ latestDetectedAt: '2026-01-02T00:00:00.000Z' }),
        group({ latestDetectedAt: '2026-01-01T00:00:00.000Z' }),
      ),
    ).toBeLessThan(0);
  });

  it('breaks a full tie on id, making the order total', () => {
    // Without this a cursor cannot resume: "everything after this group" is
    // ambiguous when two groups compare equal.
    expect(compareFindingGroupOrder(group({ id: 'a' }), group({ id: 'b' }))).toBeLessThan(0);
    expect(compareFindingGroupOrder(group({ id: 'b' }), group({ id: 'a' }))).toBeGreaterThan(0);
    expect(compareFindingGroupOrder(group({ id: 'a' }), group({ id: 'a' }))).toBe(0);
  });

  it('ranks an unknown severity below every known one', () => {
    // A garbage cursor decodes to this and therefore sorts before the list,
    // degrading to a restart from the top rather than skipping rows.
    expect(
      compareFindingGroupOrder(
        group({ severity: 'bogus' as FindingGroup['severity'] }),
        group({ severity: 'low' }),
      ),
    ).toBeLessThan(0);
  });

  it('is the comparator sortFindingGroups uses', () => {
    const groups = [
      { severity: 'low', latestDetectedAt: '2026-01-03T00:00:00.000Z', id: 'x' },
      { severity: 'critical', latestDetectedAt: '2026-01-01T00:00:00.000Z', id: 'z' },
      { severity: 'critical', latestDetectedAt: '2026-01-01T00:00:00.000Z', id: 'y' },
    ] as FindingGroup[];
    expect(sortFindingGroups(groups).map((g) => g.id)).toEqual(['y', 'z', 'x']);
  });
});

describe('location accumulator', () => {
  it('folds count, worst severity, latest time and rule ids', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ severity: 'low', occurredAt: '2026-01-01T00:00:00.000Z' }));
    addToLocation(
      acc,
      row({ severity: 'critical', occurredAt: '2026-01-03T00:00:00.000Z', ruleId: 'email' }),
    );

    expect(acc.instanceCount).toBe(2);
    expect(acc.maxSeverity).toBe('critical');
    expect(acc.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');
    expect([...acc.ruleIds]).toEqual(['aws-key', 'email']);
  });

  it('folds status with the same precedence a group uses', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ status: 'resolved' }));
    addToLocation(acc, row({ status: 'open' }));
    // open dominates — see foldGroupStatus.
    expect(foldGroupStatus(acc.statuses)).toBe('open');
  });

  it('does not let an unknown severity pin the location', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ severity: 'not-a-severity' }));
    addToLocation(acc, row({ severity: 'high' }));
    expect(acc.maxSeverity).toBe('high');
  });
});
