import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type {
  ActionTaken,
  DetectedFinding,
  DetectedFindingWithKey,
  DetectionCategory,
  EventMetadata,
  IngestEvent,
  Severity,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../database.ts';
import { DB_FILENAME } from '../paths.ts';

// Mirrors @akasecurity/plugin-sdk's computeFindingKey formula
// (sha256(ruleId + '\0' + normalizedPath + '\0' + valueFingerprint)) —
// persistence cannot depend on plugin-sdk (plugin-sdk depends on persistence),
// so the test derives the key independently rather than importing the real
// helper. This IS the "two independent derivations agree" determinism check.
function findingKeyFor(ruleId: string, filePath: string, valueFingerprint: string): string {
  return createHash('sha256').update(`${ruleId}\0${filePath}\0${valueFingerprint}`).digest('hex');
}

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-findings-'));
  db = openLocalDatabase(dir);
});

afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

// Record one event + one finding. Distinct `occurredAt` (ISO) keeps ordering
// deterministic; repo/filePath ride in the event metadata (extracted in SQL).
function record(opts: {
  occurredAt: string;
  sourceTool: IngestEvent['sourceTool'];
  ruleId: string;
  category?: DetectionCategory;
  severity?: Severity;
  actionTaken?: ActionTaken;
  repo: string;
  filePath: string;
}): void {
  const id = randomUUID();
  const metadata: EventMetadata = { repo: opts.repo, filePath: opts.filePath };
  const event: IngestEvent = {
    id,
    sourceTool: opts.sourceTool,
    kind: 'prompt',
    occurredAt: opts.occurredAt,
    contentHash: randomUUID(),
    content: 'x',
    metadata,
  };
  const finding: DetectedFinding = {
    id: randomUUID(),
    eventId: id,
    ruleId: opts.ruleId,
    category: opts.category ?? 'secret',
    severity: opts.severity ?? 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'masked',
    actionTaken: opts.actionTaken ?? 'block',
    confidence: 0.9,
  };
  db.recordCapture(event, [finding]);
}

function seed(): void {
  record({
    occurredAt: '2026-01-03T00:00:00.000Z',
    sourceTool: 'claude-code',
    ruleId: 'aws-key',
    severity: 'critical',
    actionTaken: 'block',
    repo: 'acme/api',
    filePath: 'a.ts',
  });
  record({
    occurredAt: '2026-01-02T00:00:00.000Z',
    sourceTool: 'cursor',
    ruleId: 'aws-key',
    severity: 'critical',
    actionTaken: 'warn',
    repo: 'acme/web',
    filePath: 'b.ts',
  });
  record({
    occurredAt: '2026-01-01T00:00:00.000Z',
    sourceTool: 'claude-code',
    ruleId: 'email',
    category: 'code_context',
    severity: 'low',
    actionTaken: 'redact',
    repo: 'acme/api',
    filePath: 'c.ts',
  });
}

describe('SqliteFindingsRepository.listGroupedFindings', () => {
  it('groups findings by rule with instances, providers and totals', async () => {
    seed();
    const res = await db.findings.listGroupedFindings({});

    expect(res.totals).toEqual({ findings: 3, groups: 2 });
    // Sorted critical-first, so aws-key leads.
    expect(res.items.map((g) => g.id)).toEqual(['aws-key', 'email']);

    const awsKey = res.items[0];
    expect(awsKey?.instanceCount).toBe(2);
    expect(new Set(awsKey?.providers)).toEqual(new Set(['claudecode', 'cursor']));
    expect(awsKey?.aggregateAction).toBeNull(); // block + warn → Mixed
    expect(awsKey?.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');

    // Instances carry repo/file from the event metadata.
    const files = awsKey?.instances.map((i) => i.file).sort();
    expect(files).toEqual(['a.ts', 'b.ts']);

    // code_context maps to the API category source_code.
    expect(res.items[1]?.category).toBe('source_code');
    expect(res.items[1]?.aggregateAction).toBe('redacted');
  });

  it('applies filters and keeps per-filter-excluded facets', async () => {
    seed();
    const res = await db.findings.listGroupedFindings({ severity: ['low'] });

    expect(res.items.map((g) => g.id)).toEqual(['email']);
    expect(res.totals).toEqual({ findings: 1, groups: 1 });
    // Severity facet still reports both levels (its own filter is excluded).
    expect(res.facets.severity.map((s) => s.value).sort()).toEqual(['critical', 'low']);
  });

  it('filters by provider and free-text search over repo/file', async () => {
    seed();
    expect(
      (await db.findings.listGroupedFindings({ provider: ['cursor'] })).items.map((g) => g.id),
    ).toEqual(['aws-key']);
    expect(
      (await db.findings.listGroupedFindings({ q: 'acme/web' })).items.map((g) => g.id),
    ).toEqual(['aws-key']);
  });

  it('returns an empty result for an empty store', async () => {
    const res = await db.findings.listGroupedFindings({});
    expect(res.items).toEqual([]);
    expect(res.totals).toEqual({ findings: 0, groups: 0 });
    expect(res.nextCursor).toBeNull();
  });
});

// Record one at-rest (code_change) finding with an explicit finding_key — the
// shape @akasecurity/plugin-sdk's createPluginRuntime.capture() hands to
// recordCapture for a worktree-scan hit (see runtime.ts).
function recordAtRest(opts: {
  // Omit entirely to model a legacy pre-resolution-feature row (finding_key
  // IS NULL) — see the "legacy untracked" status test below.
  findingKey?: string;
  filePath?: string;
  ruleId?: string;
  maskedMatch?: string;
  actionTaken?: ActionTaken;
  occurredAt?: string;
}): { eventId: string; findingId: string } {
  const eventId = randomUUID();
  const findingId = randomUUID();
  const metadata: EventMetadata = { filePath: opts.filePath ?? 'src/a.ts' };
  const event: IngestEvent = {
    id: eventId,
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: opts.occurredAt ?? '2026-01-01T00:00:00.000Z',
    contentHash: randomUUID(),
    content: 'x',
    metadata,
  };
  const finding: DetectedFindingWithKey = {
    id: findingId,
    eventId,
    ruleId: opts.ruleId ?? 'aws-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: opts.maskedMatch ?? 'masked',
    actionTaken: opts.actionTaken ?? 'block',
    confidence: 0.9,
    ...(opts.findingKey !== undefined ? { findingKey: opts.findingKey } : {}),
  };
  db.recordCapture(event, [finding]);
  return { eventId, findingId };
}

// Raw findings rows for a finding_key, read over a second connection to the
// same file (mirrors resolutions.test.ts's pattern).
function findingRowsByKey(key: string): { id: string; event_id: string; action_taken: string }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  try {
    return raw
      .prepare('SELECT id, event_id, action_taken FROM findings WHERE finding_key = :key')
      .all({ key }) as unknown as { id: string; event_id: string; action_taken: string }[];
  } finally {
    raw.close();
  }
}

describe('insertFindings — finding_key upsert (re-scan reconciliation)', () => {
  it('recording the SAME finding twice (same rule+path+value) yields ONE row with a stable finding_key', () => {
    const key = findingKeyFor('aws-key', 'src/a.ts', 'fp-1');

    const first = recordAtRest({ findingKey: key });
    const rowsAfterFirst = findingRowsByKey(key);
    expect(rowsAfterFirst).toHaveLength(1);
    expect(rowsAfterFirst[0]?.id).toBe(first.findingId);

    // A second scan of the unchanged file: fresh event + finding ids, but the
    // SAME finding_key (recomputed from the same rule/path/value).
    const second = recordAtRest({ findingKey: key, occurredAt: '2026-01-02T00:00:00.000Z' });
    const rowsAfterSecond = findingRowsByKey(key);

    expect(rowsAfterSecond).toHaveLength(1); // no duplicate row
    expect(rowsAfterSecond[0]?.id).toBe(first.findingId); // original row id retained
    expect(rowsAfterSecond[0]?.event_id).toBe(second.eventId); // reconciled onto the latest scan
  });

  it('is deterministic across two independent derivations of the same inputs', () => {
    const a = findingKeyFor('aws-key', 'src/a.ts', 'fp-1');
    const b = findingKeyFor('aws-key', 'src/a.ts', 'fp-1');
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('keeps two distinct secrets in the same file as two distinct rows (differing value fingerprint)', () => {
    const keyA = findingKeyFor('aws-key', 'src/a.ts', 'fp-1');
    const keyB = findingKeyFor('aws-key', 'src/a.ts', 'fp-2');

    recordAtRest({ findingKey: keyA });
    recordAtRest({ findingKey: keyB });

    expect(findingRowsByKey(keyA)).toHaveLength(1);
    expect(findingRowsByKey(keyB)).toHaveLength(1);
  });

  it('a finding with no finding_key (in-flight) never collides with another null-keyed row', () => {
    // Two ordinary in-flight findings (no findingKey) via the existing seed
    // helper — both leave finding_key NULL, and SQLite never equates two NULLs
    // in the unique index, so both insert as distinct rows.
    record({
      occurredAt: '2026-01-01T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      repo: 'acme/api',
      filePath: 'a.ts',
    });
    record({
      occurredAt: '2026-01-02T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      repo: 'acme/api',
      filePath: 'a.ts',
    });

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    try {
      const rows = raw.prepare('SELECT id FROM findings WHERE finding_key IS NULL').all();
      expect(rows).toHaveLength(2);
    } finally {
      raw.close();
    }
  });
});

// Per-finding status derivation — mirrors SqliteSecurityRepository.severitySummary's
// atRest/latest-resolution-wins predicate (see findings.ts). Each case uses a
// distinct ruleId so its group is a single-instance group and the instance
// status equals the group status, except the final "mixed" case which checks
// group-level open-dominates precedence explicitly.
describe('SqliteFindingsRepository.listGroupedFindings — per-finding status', () => {
  it('in-flight (kind != code_change) is born handled, regardless of any resolution row', async () => {
    record({
      occurredAt: '2026-01-01T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'in-flight-rule',
      repo: 'acme/api',
      filePath: 'a.ts',
    });

    const res = await db.findings.listGroupedFindings({});
    const group = res.items.find((g) => g.id === 'in-flight-rule');
    expect(group?.instances[0]?.status).toBe('handled');
    expect(group?.status).toBe('handled');
  });

  it('at-rest, tracked, no resolution row → open', async () => {
    recordAtRest({ findingKey: 'key-open', ruleId: 'open-rule' });

    const res = await db.findings.listGroupedFindings({});
    const group = res.items.find((g) => g.id === 'open-rule');
    expect(group?.instances[0]?.status).toBe('open');
    expect(group?.status).toBe('open');
  });

  it('at-rest, tracked, latest resolution "resolved" → resolved', async () => {
    recordAtRest({ findingKey: 'key-resolved', ruleId: 'resolved-rule' });
    db.resolutions.insertResolution({
      findingKey: 'key-resolved',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: Date.parse('2026-01-02T00:00:00.000Z'),
      evidence: '',
    });

    const res = await db.findings.listGroupedFindings({});
    const group = res.items.find((g) => g.id === 'resolved-rule');
    expect(group?.instances[0]?.status).toBe('resolved');
    expect(group?.status).toBe('resolved');
  });

  // Legacy pre-resolution-feature at-rest rows (finding_key IS NULL) can never
  // attach a disposition — the resolution lifecycle is keyed by finding_key
  // (mirrors SqliteSecurityRepository's legacy exclusion comment). Unlike the
  // security summary (which drops these from caught/openAtRest entirely, since
  // it only needs a boolean bucket), the findings LIST still needs to show
  // *some* status for the row, and the finding itself still physically exists
  // and is unremediated — so it reads as 'open' (untracked, still needs
  // remediation) rather than being omitted or marked resolved/handled.
  it('at-rest, legacy untracked (finding_key IS NULL) → open', async () => {
    recordAtRest({ ruleId: 'legacy-rule' }); // no findingKey

    const res = await db.findings.listGroupedFindings({});
    const group = res.items.find((g) => g.id === 'legacy-rule');
    expect(group?.instances[0]?.status).toBe('open');
    expect(group?.status).toBe('open');
  });

  it('a group with mixed instance statuses derives its group status via open-dominates precedence', async () => {
    // Same ruleId, two instances: one in-flight (handled), one at-rest and
    // still open — the group must read 'open' even though one instance is
    // already handled (open-dominates, see buildFindingGroups).
    record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'mixed-rule',
      repo: 'acme/api',
      filePath: 'a.ts',
    });
    recordAtRest({
      findingKey: 'key-mixed-open',
      ruleId: 'mixed-rule',
      occurredAt: '2026-01-02T00:00:00.000Z',
    });

    const res = await db.findings.listGroupedFindings({});
    const group = res.items.find((g) => g.id === 'mixed-rule');
    expect(group?.instanceCount).toBe(2);
    expect(new Set(group?.instances.map((i) => i.status))).toEqual(new Set(['handled', 'open']));
    expect(group?.status).toBe('open');
  });
});

// healthSummary's per-severity tally must honor the finding_resolution
// lifecycle the same way severitySummary does (latest-resolution-wins, see
// resolution-sql.ts) — otherwise the status bar and the dashboard severity
// card disagree the moment any at-rest finding is resolved.
describe('SqliteFindingsRepository.healthSummary — resolution lifecycle', () => {
  it('drops a finding from bySeverity once its latest resolution is "resolved"', async () => {
    recordAtRest({ findingKey: 'key-open', ruleId: 'rule-open' });
    recordAtRest({ findingKey: 'key-fixed', ruleId: 'rule-fixed' });
    db.resolutions.insertResolution({
      findingKey: 'key-fixed',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: Date.parse('2026-01-02T00:00:00.000Z'),
      evidence: '',
    });

    const summary = await db.findings.healthSummary();
    expect(summary.bySeverity.critical).toBe(1); // key-open only
    // total/byAction stay whole-store historical tallies.
    expect(summary.findings).toBe(2);
    expect(summary.byAction.block).toBe(2);
  });

  it('latest-wins: a redetected "open" row supersedes an older "resolved" row', async () => {
    recordAtRest({ findingKey: 'key-back', ruleId: 'rule-back' });
    db.resolutions.insertResolution({
      findingKey: 'key-back',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: Date.parse('2026-01-02T00:00:00.000Z'),
      evidence: '',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-back',
      status: 'open',
      method: 'redetected',
      resolvedAt: Date.parse('2026-01-03T00:00:00.000Z'),
      evidence: '',
    });

    const summary = await db.findings.healthSummary();
    expect(summary.bySeverity.critical).toBe(1);
  });

  it('in-flight findings (finding_key NULL) always count', async () => {
    record({
      occurredAt: '2026-01-01T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      severity: 'critical',
      repo: 'acme/api',
      filePath: 'a.ts',
    });

    const summary = await db.findings.healthSummary();
    expect(summary.bySeverity.critical).toBe(1);
  });
});

// A store larger than any one group's instance PREVIEW. listGroupedFindings
// aggregates the group-wide numbers SQL-side, so every count/fold below must
// reflect ALL instances even though `instances` only ever carries the newest
// PREVIEW_INSTANCES_PER_GROUP of them. BULK is deliberately > the 2000-row read
// cap this path used to impose, under which totals saturated at exactly 2000.
const BULK = 2600;

// One rule, BULK instances, all on claude-code/block except the explicit
// oddities the tests below pin. Timestamps ascend so `i` doubles as a recency
// rank: instance 0 is the OLDEST and sits far outside the newest-200 preview.
function seedBulk(opts: { ruleId?: string } = {}): void {
  const ruleId = opts.ruleId ?? 'bulk-rule';
  for (let i = 0; i < BULK; i++) {
    record({
      occurredAt: new Date(Date.UTC(2026, 0, 1) + i * 60_000).toISOString(),
      // The lone cursor instance is the oldest row in the store...
      sourceTool: i === 0 ? 'cursor' : 'claude-code',
      ruleId,
      severity: 'critical',
      // ...as is the lone redacted one.
      actionTaken: i === 0 ? 'redact' : 'block',
      repo: i === 0 ? 'acme/ancient' : 'acme/api',
      filePath: `src/f${String(i)}.ts`,
    });
  }
}

describe('SqliteFindingsRepository.listGroupedFindings — stores larger than the preview', () => {
  it('counts every instance rather than saturating at the old 2000-row cap', async () => {
    seedBulk();

    const res = await db.findings.listGroupedFindings({});

    expect(res.totals).toEqual({ findings: BULK, groups: 1 });
    expect(res.items[0]?.instanceCount).toBe(BULK);
  });

  it('caps the instances preview without capping the count', async () => {
    seedBulk();

    const group = (await db.findings.listGroupedFindings({})).items[0];

    // The preview is bounded and holds the NEWEST instances...
    expect(group?.instances.length).toBeLessThan(BULK);
    expect(group?.instances[0]?.file).toBe(`src/f${String(BULK - 1)}.ts`);
    // ...while the count beside it still speaks for the whole group.
    expect(group?.instanceCount).toBe(BULK);
  });

  it('folds providers, actions and latest over instances outside the preview', async () => {
    seedBulk();

    const group = (await db.findings.listGroupedFindings({})).items[0];

    // The cursor/redact instance is the oldest row, far outside the preview —
    // only the SQL aggregate can still see it.
    expect(new Set(group?.providers)).toEqual(new Set(['claudecode', 'cursor']));
    expect(group?.aggregateAction).toBeNull(); // block + redact → Mixed
    expect(group?.latestDetectedAt).toBe(
      new Date(Date.UTC(2026, 0, 1) + (BULK - 1) * 60_000).toISOString(),
    );
  });

  it('filters and facets on an instance outside the preview', async () => {
    seedBulk();

    // Provider, action and free-text all match ONLY the oldest instance.
    expect((await db.findings.listGroupedFindings({ provider: ['cursor'] })).items).toHaveLength(1);
    expect((await db.findings.listGroupedFindings({ action: ['redacted'] })).items).toHaveLength(1);
    expect((await db.findings.listGroupedFindings({ q: 'acme/ancient' })).items).toHaveLength(1);

    const facets = (await db.findings.listGroupedFindings({})).facets;
    expect(facets.provider.map((f) => f.value).sort()).toEqual(['claudecode', 'cursor']);
    expect(facets.action.map((f) => f.value).sort()).toEqual(['blocked', 'redacted']);
  });

  it('keeps a group whose instances all sit outside the newest page of rows', async () => {
    // A second rule whose only finding is older than every bulk row: under the
    // old whole-store row cap the newest 2000 rows were all bulk-rule's, so
    // this group vanished from the list and its findings from the totals.
    record({
      occurredAt: '2025-01-01T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'buried-rule',
      severity: 'low',
      repo: 'acme/buried',
      filePath: 'old.ts',
    });
    seedBulk();

    const res = await db.findings.listGroupedFindings({});

    expect(res.items.map((g) => g.id).sort()).toEqual(['bulk-rule', 'buried-rule']);
    expect(res.totals).toEqual({ findings: BULK + 1, groups: 2 });
  });
});
