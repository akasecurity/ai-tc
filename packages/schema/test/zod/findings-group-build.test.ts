import { describe, expect, it } from 'vitest';

import type { FindingStatus } from '../../src/zod/finding.ts';
import { DetectionCategory, FindingCategory } from '../../src/zod/finding.ts';
import {
  applyFindingFilters,
  buildFindingTypes,
  computeFindingFacets,
  countInstancesByStatus,
  type FindingGroupAggregate,
  type GroupableFindingRow,
  sortFindingTypes,
  toApiAction,
  toApiCategory,
  toApiProvider,
  toDbAction,
  toDbCategory,
  toDbProviderFilter,
} from '../../src/zod/findings-group-build.ts';

// ─── enum mappers (normative from the spec enum tables) ──────────────────────

describe('toApiAction', () => {
  it('maps every DB action to its API value', () => {
    expect(toApiAction('log')).toBe('monitored');
    expect(toApiAction('block')).toBe('blocked');
    expect(toApiAction('redact')).toBe('redacted');
    expect(toApiAction('warn')).toBe('warned');
    expect(toApiAction('allow')).toBe('allowed');
  });
  it('falls back to allowed for unknown values', () => {
    expect(toApiAction('whatever')).toBe('allowed');
  });
});

describe('toDbAction', () => {
  it('reverses toApiAction', () => {
    expect(toDbAction('monitored')).toBe('log');
    expect(toDbAction('blocked')).toBe('block');
    expect(toDbAction('redacted')).toBe('redact');
    expect(toDbAction('warned')).toBe('warn');
    expect(toDbAction('allowed')).toBe('allow');
  });
  it('throws on quarantined (system-assigned)', () => {
    expect(() => toDbAction('quarantined')).toThrow();
  });
});

describe('category mappers', () => {
  it('maps code_context ↔ source_code and passes others through', () => {
    expect(toApiCategory('code_context')).toBe('source_code');
    expect(toApiCategory('secret')).toBe('secret');
    expect(toDbCategory('source_code')).toBe('code_context');
    expect(toDbCategory('pii')).toBe('pii');
  });

  // The mapper is TOTAL. Derived from DetectionCategory rather than a written-out
  // list: a member added there is covered here without editing this test, which is
  // what the pass-through cast could not give. An off-enum return is not a wrong
  // label — every route returning a category Zod-validates its response body, so
  // one such row fails serialization for the WHOLE page.
  it('returns a valid FindingCategory for every DetectionCategory member', () => {
    for (const dbVal of DetectionCategory.options) {
      const parsed = FindingCategory.safeParse(toApiCategory(dbVal));
      expect(parsed.success, `${dbVal} → ${toApiCategory(dbVal)}`).toBe(true);
    }
  });

  it('round-trips code_flaw, which has its own member', () => {
    expect(toApiCategory('code_flaw')).toBe('code_flaw');
    expect(toDbCategory('code_flaw')).toBe('code_flaw');
  });

  it('falls back to custom for config, the one member with no equivalent', () => {
    expect(toApiCategory('config')).toBe('custom');
  });

  it('falls back to custom for an unrecognized value', () => {
    expect(toApiCategory('not_a_category')).toBe('custom');
    expect(toApiCategory('')).toBe('custom');
  });
});

describe('provider mappers', () => {
  it('maps sourceTool → API provider (claudecode ≠ claudedesktop)', () => {
    expect(toApiProvider('claude-code')).toBe('claudecode');
    expect(toApiProvider('claude-desktop')).toBe('claudedesktop');
    expect(toApiProvider('github-copilot')).toBe('copilot');
    expect(toApiProvider('cursor')).toBe('cursor');
    expect(toApiProvider('chatgpt')).toBe('chatgpt');
    expect(toApiProvider('codex')).toBe('codex');
    expect(toApiProvider('claude-ai')).toBe('claudeai');
    expect(toApiProvider('antigravity')).toBe('antigravity');
    expect(toApiProvider('mystery-tool')).toBe('api');
  });
  it('maps API provider → DB filter values', () => {
    expect(toDbProviderFilter('claudecode')).toEqual(['claude-code']);
    expect(toDbProviderFilter('claudedesktop')).toEqual(['claude-desktop']);
    expect(toDbProviderFilter('codex')).toEqual(['codex']);
    expect(toDbProviderFilter('claudeai')).toEqual(['claude-ai']);
    expect(toDbProviderFilter('antigravity')).toEqual(['antigravity']);
    expect(toDbProviderFilter('api')).toEqual([]);
  });
});

// ─── grouping ────────────────────────────────────────────────────────────────

/**
 * Row fixtures → the whole-type aggregate a store folds in SQL.
 *
 * The rows stay because they are the readable way to state a fixture; this
 * turns them into the shape `buildFindingTypes` actually consumes, doing the
 * same distinct/count/max folds the `GROUP BY rule_id` does. It is fixture
 * ASSEMBLY, not a second implementation of the fold under test — everything
 * asserted below (the enum mapping, the status precedence, the dedup order,
 * the haystack) happens on the far side of this.
 */
function aggregatesFrom(rows: GroupableFindingRow[]): Map<string, FindingGroupAggregate> {
  const byRule = new Map<string, GroupableFindingRow[]>();
  for (const r of rows) {
    const existing = byRule.get(r.ruleId);
    if (existing) existing.push(r);
    else byRule.set(r.ruleId, [r]);
  }
  return new Map(
    [...byRule].map(([ruleId, rs]) => [
      ruleId,
      {
        instanceCount: rs.length,
        severity: rs[0]?.severity,
        category: rs[0]?.category,
        sourceTools: [...new Set(rs.map((r) => r.sourceTool))],
        actionsTaken: [...new Set(rs.map((r) => r.actionTaken))],
        // A row with no status contributes NO input — that is what "carries no
        // status" means to the fold, and mapping it to a default would make
        // every legacy fixture read as open.
        statusInputs: rs.flatMap((r) =>
          r.status === undefined ? [] : [{ ...statusInput(r.status), count: 1 }],
        ),
        latestDetectedAt: rs.reduce((max, r) => (r.occurredAt > max ? r.occurredAt : max), ''),
        ...(rs.some((r) => r.user)
          ? {
              users: [
                ...new Map(rs.flatMap((r) => (r.user ? [[r.user.id, r.user]] : []))).values(),
              ],
            }
          : {}),
        // The store fetches this only for a request carrying `q`; the fixtures
        // always supply it so the haystack cases have whole-type text to match.
        searchText: [
          ...new Set(rs.map((r) => r.repo)),
          ...new Set(rs.map((r) => r.file)),
          ...new Set(rs.map((r) => (r.toolName ? `via ${r.toolName}` : ''))),
        ]
          .filter((t) => t !== '')
          .join(' '),
      } satisfies FindingGroupAggregate,
    ]),
  );
}

/** The deriveFindingStatus inputs that produce a given status. */
function statusInput(status: FindingStatus): {
  kind: string;
  findingKey: string | null;
  latestResolutionStatus: string | null;
} {
  // in-flight (any kind but code_change) is born handled; at-rest with no
  // finding_key is open; at-rest and tracked reads its latest resolution.
  if (status === 'handled')
    return { kind: 'prompt', findingKey: null, latestResolutionStatus: null };
  if (status === 'open')
    return { kind: 'code_change', findingKey: null, latestResolutionStatus: null };
  return { kind: 'code_change', findingKey: 'k', latestResolutionStatus: status };
}

// Rows are newest-first (as the repos return them).
const rows: GroupableFindingRow[] = [
  {
    id: 'i1',
    ruleId: 'aws-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA…1',
    actionTaken: 'block',
    confidence: 0.95,
    occurredAt: '2026-01-03T00:00:00.000Z',
    sourceTool: 'claude-code',
    repo: 'acme/api',
    file: 'a.ts',
  },
  {
    id: 'i2',
    ruleId: 'aws-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA…2',
    actionTaken: 'warn',
    confidence: 0.8,
    occurredAt: '2026-01-02T00:00:00.000Z',
    sourceTool: 'cursor',
    repo: 'acme/web',
    file: 'b.ts',
  },
  {
    id: 'i3',
    ruleId: 'email',
    category: 'code_context',
    severity: 'low',
    maskedMatch: 'j…@x.com',
    actionTaken: 'redact',
    confidence: 0.7,
    occurredAt: '2026-01-01T00:00:00.000Z',
    sourceTool: 'claude-code',
    repo: 'acme/api',
    file: 'c.ts',
  },
];

// One status-carrying row — `rows` above carry none, so the status filter and
// facet cases build their own groups from these.
const statusRow = (id: string, ruleId: string, status?: FindingStatus): GroupableFindingRow => ({
  id,
  ruleId,
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'AKIA…1',
  actionTaken: 'block',
  confidence: 0.9,
  occurredAt: '2026-01-01T00:00:00.000Z',
  sourceTool: 'claude-code',
  repo: 'acme/api',
  file: 'a.ts',
  ...(status === undefined ? {} : { status }),
});

// Three groups: one that folds to open (its handled sibling loses to
// open-dominates), one resolved, and one legacy group carrying no status.
const statusFilterRows: GroupableFindingRow[] = [
  statusRow('s1', 'open-rule', 'open'),
  statusRow('s2', 'open-rule', 'handled'),
  statusRow('s3', 'resolved-rule', 'resolved'),
  statusRow('s4', 'legacy-rule'),
];

// A finding captured from tool output (no filePath, only tool attribution).
const toolAttributedRows: GroupableFindingRow[] = [
  {
    id: 'i4',
    ruleId: 'env-kv',
    category: 'secret',
    severity: 'high',
    maskedMatch: 'API_KEY=…',
    actionTaken: 'log',
    confidence: 0.9,
    occurredAt: '2026-01-04T00:00:00.000Z',
    sourceTool: 'claude-code',
    repo: 'acme/api',
    file: '',
    toolName: 'Bash',
  },
];

describe('buildFindingTypes tool attribution', () => {
  // A type carries no instances, so tool attribution reaches it only through the
  // aggregate's search text — which is the whole point of that column.
  it('matches q against a tool label ("via Bash") from the aggregate', () => {
    const types = buildFindingTypes(aggregatesFrom(toolAttributedRows));
    expect(applyFindingFilters(types, { q: 'via bash' })).toHaveLength(1);
    expect(applyFindingFilters(types, { q: 'via webfetch' })).toHaveLength(0);
  });
});

describe('buildFindingTypes user attribution', () => {
  const alice = { id: 'u-alice', name: 'alice@example.com' };
  const bob = { id: 'u-bob', name: 'bob@example.com' };
  const attributed: GroupableFindingRow[] = [
    { ...statusRow('a1', 'aws-key'), user: alice },
    { ...statusRow('a2', 'aws-key'), user: bob },
    { ...statusRow('a3', 'aws-key'), user: alice },
  ];

  const aggregate: FindingGroupAggregate = {
    instanceCount: 40,
    severity: 'critical',
    category: 'secret',
    sourceTools: ['claude-code'],
    actionsTaken: ['block'],
    statusInputs: [],
    latestDetectedAt: '2026-01-03T00:00:00.000Z',
  };

  it('omits users when the aggregate carries none', () => {
    const types = buildFindingTypes(aggregatesFrom(rows));
    expect(types[0]).not.toHaveProperty('users');
    expect(buildFindingTypes(new Map([['aws-key', aggregate]]))[0]).not.toHaveProperty('users');
  });

  it('reads users from the aggregate, sorted by label then id', () => {
    const carol = { id: 'u-carol', name: 'carol@example.com' };
    const types = buildFindingTypes(
      new Map([['aws-key', { ...aggregate, users: [carol, bob, alice] }]]),
    );
    expect(types[0]?.users).toEqual([alice, bob, carol]);
  });

  it('matches q against the whole type’s people, not a sample of them', () => {
    const carol = { id: 'u-carol', name: 'carol@example.com' };
    const types = buildFindingTypes(
      new Map([['aws-key', { ...aggregate, users: [carol, alice] }]]),
    );
    expect(applyFindingFilters(types, { q: 'ALICE@' })).toHaveLength(1);
    expect(applyFindingFilters(types, { q: 'carol@' })).toHaveLength(1);
    expect(applyFindingFilters(types, { q: 'bob@' })).toHaveLength(0);
    expect(
      applyFindingFilters(buildFindingTypes(aggregatesFrom(attributed)), { q: 'bob@' }),
    ).toHaveLength(1);
  });
});

describe('buildFindingTypes', () => {
  const groups = buildFindingTypes(aggregatesFrom(rows));
  const awsKey = groups.find((g) => g.id === 'aws-key');
  const email = groups.find((g) => g.id === 'email');

  it('yields one type per ruleId, counting every finding', () => {
    expect(groups).toHaveLength(2);
    expect(awsKey?.instanceCount).toBe(2);
    expect(email?.instanceCount).toBe(1);
  });

  it('dedupes providers and derives latestDetectedAt', () => {
    expect(awsKey?.providers).toEqual(['claudecode', 'cursor']);
    expect(awsKey?.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');
  });

  it('sets aggregateAction to null when findings disagree, else the shared action', () => {
    expect(awsKey?.aggregateAction).toBeNull(); // blocked + warned
    expect(email?.aggregateAction).toBe('redacted');
  });

  it('maps categories to API values (code_context → source_code)', () => {
    expect(awsKey?.category).toBe('secret');
    expect(email?.category).toBe('source_code');
  });

  it('synthesizes detection/policy (no pack names → null detection name)', () => {
    expect(awsKey?.detection).toEqual({ id: 'aws-key', name: null });
    expect(email?.policy).toEqual({ id: 'category:source_code', name: 'source_code' });
  });

  it('honors a packNames map when provided', () => {
    const named = buildFindingTypes(aggregatesFrom(rows), {
      packNames: new Map([['aws-key', 'AWS Secrets']]),
    });
    expect(named.find((g) => g.id === 'aws-key')?.detection.name).toBe('AWS Secrets');
  });

  it('carries no instances and no masked value — the two the type shape omits', () => {
    expect(awsKey).not.toHaveProperty('instances');
    expect(awsKey).not.toHaveProperty('match');
  });
});

// ─── status derivation (open-dominates precedence) ────────────────────────────

describe('buildFindingTypes status derivation', () => {
  const statusRows = (statuses: (FindingStatus | undefined)[]): GroupableFindingRow[] =>
    statuses.map((status, i) => ({
      id: `s${String(i)}`,
      ruleId: 'aws-key',
      category: 'secret',
      severity: 'critical',
      maskedMatch: 'AKIA…1',
      actionTaken: 'block',
      confidence: 0.9,
      occurredAt: `2026-01-0${String(i + 1)}T00:00:00.000Z`,
      sourceTool: 'claude-code',
      repo: 'acme/api',
      file: 'a.ts',
      ...(status !== undefined ? { status } : {}),
    }));

  it('derives open when any finding is open (open dominates)', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows(['resolved', 'open', 'handled'])));
    expect(groups[0]?.status).toBe('open');
  });

  it('derives resolved when all findings are resolved', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows(['resolved', 'resolved'])));
    expect(groups[0]?.status).toBe('resolved');
  });

  it('derives handled when mixed handled + resolved (handled beats resolved)', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows(['handled', 'resolved'])));
    expect(groups[0]?.status).toBe('handled');
  });

  it('derives handled when mixed dismissed + handled (handled beats dismissed — an active enforcement must not be hidden behind a human dismissal elsewhere in the group)', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows(['dismissed', 'handled'])));
    expect(groups[0]?.status).toBe('handled');
  });

  it('derives dismissed when mixed dismissed + resolved (dismissed beats resolved)', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows(['dismissed', 'resolved'])));
    expect(groups[0]?.status).toBe('dismissed');
  });

  it('leaves type status undefined when no finding carries a status', () => {
    const groups = buildFindingTypes(aggregatesFrom(statusRows([undefined, undefined])));
    expect(groups[0]?.status).toBeUndefined();
  });
});

describe('applyFindingFilters', () => {
  const groups = buildFindingTypes(aggregatesFrom(rows));
  const ids = (gs: ReturnType<typeof buildFindingTypes>) => gs.map((g) => g.id).sort();

  it('filters by severity', () => {
    expect(ids(applyFindingFilters(groups, { severity: ['low'] }))).toEqual(['email']);
  });
  it('filters by provider (any matching instance)', () => {
    expect(ids(applyFindingFilters(groups, { providers: ['cursor'] }))).toEqual(['aws-key']);
  });
  it('filters by action (any matching instance)', () => {
    expect(ids(applyFindingFilters(groups, { actions: ['redacted'] }))).toEqual(['email']);
  });
  it('filters by subtype', () => {
    expect(ids(applyFindingFilters(groups, { subtype: ['aws-key'] }))).toEqual(['aws-key']);
  });
  it('filters by case-insensitive substring over repo/file/subtype', () => {
    expect(ids(applyFindingFilters(groups, { q: 'acme/web' }))).toEqual(['aws-key']);
    expect(ids(applyFindingFilters(groups, { q: 'EMAIL' }))).toEqual(['email']);
  });

  describe('status (the group’s own folded status, not any instance)', () => {
    const statusGroups = buildFindingTypes(aggregatesFrom(statusFilterRows));

    it('keeps only groups whose folded status is selected', () => {
      expect(ids(applyFindingFilters(statusGroups, { statuses: ['open'] }))).toEqual(['open-rule']);
      expect(ids(applyFindingFilters(statusGroups, { statuses: ['resolved'] }))).toEqual([
        'resolved-rule',
      ]);
    });

    it('keeps the union when several statuses are selected', () => {
      expect(ids(applyFindingFilters(statusGroups, { statuses: ['open', 'resolved'] }))).toEqual([
        'open-rule',
        'resolved-rule',
      ]);
    });

    it('does not match a group on an instance status the fold discarded', () => {
      // open-rule holds a handled instance, but folds to open — a "handled"
      // filter must not surface a row whose Status column reads "Open".
      expect(ids(applyFindingFilters(statusGroups, { statuses: ['handled'] }))).toEqual([]);
    });

    it('excludes a legacy group carrying no status', () => {
      expect(ids(applyFindingFilters(statusGroups, { statuses: ['open'] }))).not.toContain(
        'legacy-rule',
      );
    });

    it('returns every group unchanged for an empty selection', () => {
      expect(applyFindingFilters(statusGroups, { statuses: [] })).toEqual(statusGroups);
    });
  });
});

describe('computeFindingFacets', () => {
  const groups = buildFindingTypes(aggregatesFrom(rows));

  it('counts every dimension when no filters are applied', () => {
    const f = computeFindingFacets(groups, {});
    expect(new Map(f.severity.map((s) => [s.value, s.count]))).toEqual(
      new Map([
        ['critical', 1],
        ['low', 1],
      ]),
    );
    expect(new Map(f.provider.map((p) => [p.value, p.count]))).toEqual(
      new Map([
        ['claudecode', 2],
        ['cursor', 1],
      ]),
    );
  });

  it('excludes a dimension’s own filter (per-filter-excluded counts)', () => {
    // Filtering severity=low must NOT collapse the severity facet — it still
    // reports both levels, so the user can switch selection.
    const f = computeFindingFacets(groups, { severity: ['low'] });
    expect(f.severity.map((s) => s.value).sort()).toEqual(['critical', 'low']);
    // …but the provider facet DOES apply the severity filter (only email → claudecode).
    expect(f.provider).toEqual([{ value: 'claudecode', count: 1 }]);
  });

  describe('status facet', () => {
    const statusGroups = buildFindingTypes(aggregatesFrom(statusFilterRows));

    it('counts groups by their folded status, ignoring status-less groups', () => {
      const f = computeFindingFacets(statusGroups, {});
      // legacy-rule carries no status, so it lands in no bucket — the filter
      // cannot select it either.
      expect(new Map(f.status.map((s) => [s.value, s.count]))).toEqual(
        new Map([
          ['open', 1],
          ['resolved', 1],
        ]),
      );
    });

    it('excludes its own filter but applies the status filter to the others', () => {
      const f = computeFindingFacets(statusGroups, { statuses: ['open'] });
      expect(f.status.map((s) => s.value).sort()).toEqual(['open', 'resolved']);
      // …while the severity facet narrows to the one open group.
      expect(f.severity).toEqual([{ value: 'critical', count: 1 }]);
    });

    it('reports no statuses for groups that carry none', () => {
      expect(computeFindingFacets(groups, {}).status).toEqual([]);
    });
  });
});

describe('countInstancesByStatus', () => {
  // (kind, findingKey, latestResolutionStatus) → derived status:
  // prompt/∅/∅ → handled · code_change/key/∅ → open · code_change/key/resolved → resolved
  const inputs = [
    { kind: 'prompt', findingKey: null, latestResolutionStatus: null, count: 200 },
    { kind: 'code_change', findingKey: 'k', latestResolutionStatus: null, count: 3 },
    { kind: 'code_change', findingKey: 'k', latestResolutionStatus: 'resolved', count: 5 },
  ];

  it('sums the counts of combinations whose derived status is selected', () => {
    expect(countInstancesByStatus(inputs, ['open'])).toBe(3);
    expect(countInstancesByStatus(inputs, ['handled'])).toBe(200);
    expect(countInstancesByStatus(inputs, ['open', 'resolved'])).toBe(8);
  });

  it('returns 0 when no combination matches', () => {
    expect(countInstancesByStatus(inputs, ['dismissed'])).toBe(0);
  });

  it('returns null when a combination carries no count (caller falls back to instanceCount)', () => {
    const noCounts = [{ kind: 'prompt', findingKey: null, latestResolutionStatus: null }];
    expect(countInstancesByStatus(noCounts, ['handled'])).toBeNull();
  });
});

describe('sortFindingTypes', () => {
  it('orders by severity (critical first) then recency', () => {
    const sorted = sortFindingTypes(buildFindingTypes(aggregatesFrom(rows)));
    expect(sorted.map((g) => g.id)).toEqual(['aws-key', 'email']);
  });
});
