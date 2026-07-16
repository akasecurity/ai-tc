import { describe, expect, it } from 'vitest';

import type { FindingStatus } from '../../src/zod/finding.ts';
import {
  applyFindingFilters,
  buildFindingGroups,
  computeFindingFacets,
  type GroupableFindingRow,
  sortFindingGroups,
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
});

describe('provider mappers', () => {
  it('maps sourceTool → API provider (claudecode ≠ claudedesktop)', () => {
    expect(toApiProvider('claude-code')).toBe('claudecode');
    expect(toApiProvider('claude-desktop')).toBe('claudedesktop');
    expect(toApiProvider('github-copilot')).toBe('copilot');
    expect(toApiProvider('cursor')).toBe('cursor');
    expect(toApiProvider('chatgpt')).toBe('chatgpt');
    expect(toApiProvider('mystery-tool')).toBe('api');
  });
  it('maps API provider → DB filter values', () => {
    expect(toDbProviderFilter('claudecode')).toEqual(['claude-code']);
    expect(toDbProviderFilter('claudedesktop')).toEqual(['claude-desktop']);
    expect(toDbProviderFilter('api')).toEqual([]);
  });
});

// ─── grouping ────────────────────────────────────────────────────────────────

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

describe('buildFindingGroups', () => {
  const groups = buildFindingGroups(rows);
  const awsKey = groups.find((g) => g.id === 'aws-key');
  const email = groups.find((g) => g.id === 'email');

  it('groups rows by ruleId with an instance per row', () => {
    expect(groups).toHaveLength(2);
    expect(awsKey?.instanceCount).toBe(2);
    expect(email?.instanceCount).toBe(1);
  });

  it('dedupes providers and derives latestDetectedAt', () => {
    expect(awsKey?.providers).toEqual(['claudecode', 'cursor']);
    expect(awsKey?.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');
  });

  it('sets aggregateAction to null when instances disagree, else the shared action', () => {
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
    const named = buildFindingGroups(rows, { packNames: new Map([['aws-key', 'AWS Secrets']]) });
    expect(named.find((g) => g.id === 'aws-key')?.detection.name).toBe('AWS Secrets');
  });

  it('applies overrides ahead of the row action', () => {
    const overridden = buildFindingGroups(rows, { overrides: new Map([['i3', 'block']]) });
    expect(overridden.find((g) => g.id === 'email')?.aggregateAction).toBe('blocked');
  });
});

// ─── status derivation (open-dominates precedence) ────────────────────────────

describe('buildFindingGroups status derivation', () => {
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

  it('derives open when any instance is open (open dominates)', () => {
    const groups = buildFindingGroups(statusRows(['resolved', 'open', 'handled']));
    expect(groups[0]?.status).toBe('open');
  });

  it('derives resolved when all instances are resolved', () => {
    const groups = buildFindingGroups(statusRows(['resolved', 'resolved']));
    expect(groups[0]?.status).toBe('resolved');
  });

  it('derives handled when mixed handled + resolved (handled beats resolved)', () => {
    const groups = buildFindingGroups(statusRows(['handled', 'resolved']));
    expect(groups[0]?.status).toBe('handled');
  });

  it('derives handled when mixed dismissed + handled (handled beats dismissed — an active enforcement must not be hidden behind a human dismissal elsewhere in the group)', () => {
    const groups = buildFindingGroups(statusRows(['dismissed', 'handled']));
    expect(groups[0]?.status).toBe('handled');
  });

  it('derives dismissed when mixed dismissed + resolved (dismissed beats resolved)', () => {
    const groups = buildFindingGroups(statusRows(['dismissed', 'resolved']));
    expect(groups[0]?.status).toBe('dismissed');
  });

  it('leaves group status undefined when no instance carries a status', () => {
    const groups = buildFindingGroups(statusRows([undefined, undefined]));
    expect(groups[0]?.status).toBeUndefined();
  });

  it('propagates status onto each instance', () => {
    const groups = buildFindingGroups(statusRows(['open', 'resolved']));
    expect(groups[0]?.instances.map((i) => i.status)).toEqual(['open', 'resolved']);
  });
});

describe('applyFindingFilters', () => {
  const groups = buildFindingGroups(rows);
  const ids = (gs: ReturnType<typeof buildFindingGroups>) => gs.map((g) => g.id).sort();

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
});

describe('computeFindingFacets', () => {
  const groups = buildFindingGroups(rows);

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
});

describe('sortFindingGroups', () => {
  it('orders by severity (critical first) then recency', () => {
    const sorted = sortFindingGroups(buildFindingGroups(rows));
    expect(sorted.map((g) => g.id)).toEqual(['aws-key', 'email']);
  });
});
