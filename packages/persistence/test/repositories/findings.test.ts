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
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { captureId } from '../../src/ids.ts';
import { DB_FILENAME } from '../../src/paths.ts';

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
// deterministic; repo/filePath/toolName/sessionId ride in the event metadata
// (extracted in SQL). filePath is omittable to model tool-output captures,
// which carry a toolName instead.
function record(opts: {
  occurredAt: string;
  sourceTool: IngestEvent['sourceTool'];
  ruleId: string;
  category?: DetectionCategory;
  severity?: Severity;
  actionTaken?: ActionTaken;
  repo: string;
  filePath?: string;
  toolName?: string;
  sessionId?: string;
}): void {
  const id = randomUUID();
  const metadata: EventMetadata = {
    repo: opts.repo,
    ...(opts.filePath === undefined ? {} : { filePath: opts.filePath }),
    ...(opts.toolName === undefined ? {} : { toolName: opts.toolName }),
    ...(opts.sessionId === undefined ? {} : { sessionId: opts.sessionId }),
  };
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

  it('carries tool attribution for captures with no filePath and matches q on it', async () => {
    record({
      occurredAt: '2026-01-04T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'env-kv',
      severity: 'high',
      actionTaken: 'log',
      repo: 'acme/api',
      toolName: 'Bash',
    });

    const res = await db.findings.listGroupedFindings({});
    const instance = res.items[0]?.instances[0];
    expect(instance?.file).toBe('');
    expect(instance?.toolName).toBe('Bash');

    expect(
      (await db.findings.listGroupedFindings({ q: 'via bash' })).items.map((g) => g.id),
    ).toEqual(['env-kv']);
    expect((await db.findings.listGroupedFindings({ q: 'via webfetch' })).items).toEqual([]);
  });
});

// The Activity page's session → findings drilldown: a sessionId scopes the
// grouped list to findings whose event metadata carries that session, so the
// same query/response shape serves both the whole-store page and the
// session-filtered deep link (/findings?session=…).
describe('SqliteFindingsRepository.listGroupedFindings — sessionId scope', () => {
  const SESSION_A = 'aaaaaaaa-1111-4111-8111-111111111111';
  const SESSION_B = 'bbbbbbbb-2222-4222-8222-222222222222';

  function seedSessions(): void {
    record({
      occurredAt: '2026-01-03T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      severity: 'critical',
      repo: 'acme/api',
      filePath: 'a.ts',
      sessionId: SESSION_A,
    });
    record({
      occurredAt: '2026-01-02T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'email',
      category: 'code_context',
      severity: 'low',
      actionTaken: 'redact',
      repo: 'acme/api',
      filePath: 'b.ts',
      sessionId: SESSION_A,
    });
    record({
      occurredAt: '2026-01-01T00:00:00.000Z',
      sourceTool: 'cursor',
      ruleId: 'aws-key',
      severity: 'critical',
      repo: 'acme/web',
      filePath: 'c.ts',
      sessionId: SESSION_B,
    });
    // A scan-derived finding with no session at all — never in a session scope.
    record({
      occurredAt: '2026-01-04T00:00:00.000Z',
      sourceTool: 'claude-code',
      ruleId: 'aws-key',
      severity: 'critical',
      repo: 'acme/scan',
      filePath: 'd.ts',
    });
  }

  it('scopes items, totals and instance counts to the session', async () => {
    seedSessions();
    const res = await db.findings.listGroupedFindings({ sessionId: SESSION_A });

    expect(res.totals).toEqual({ findings: 2, groups: 2 });
    expect(res.items.map((g) => g.id)).toEqual(['aws-key', 'email']);
    // Only the session's own instance — not session B's, not the sessionless one.
    expect(res.items[0]?.instanceCount).toBe(1);
    expect(res.items[0]?.instances.map((i) => i.file)).toEqual(['a.ts']);
    expect(res.items[0]?.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');
  });

  it('excludes findings whose events carry no sessionId', async () => {
    seedSessions();
    const res = await db.findings.listGroupedFindings({ sessionId: SESSION_B });

    expect(res.totals).toEqual({ findings: 1, groups: 1 });
    expect(res.items[0]?.instances.map((i) => i.file)).toEqual(['c.ts']);
  });

  it('returns empty for a session with no findings', async () => {
    seedSessions();
    const res = await db.findings.listGroupedFindings({ sessionId: 'no-such-session' });

    expect(res.items).toEqual([]);
    expect(res.totals).toEqual({ findings: 0, groups: 0 });
  });

  it('composes with the other filters and scopes facets to the session', async () => {
    seedSessions();
    const res = await db.findings.listGroupedFindings({
      sessionId: SESSION_B,
      severity: ['critical'],
    });

    // Session B holds one of the store's three critical aws-key instances.
    expect(res.totals).toEqual({ findings: 1, groups: 1 });
    expect(res.items[0]?.instances.map((i) => i.file)).toEqual(['c.ts']);
    // Facets honor the session scope: session B has no low finding, so the
    // severity facet (own filter excluded) lists critical only.
    expect(res.facets.severity.map((s) => s.value)).toEqual(['critical']);
  });

  it('search text scoping: a q that only matches another session finds nothing', async () => {
    seedSessions();
    // 'acme/web' belongs to session B's finding; scoped to A it must not match.
    const res = await db.findings.listGroupedFindings({ sessionId: SESSION_A, q: 'acme/web' });
    expect(res.items).toEqual([]);
  });

  // The Activity page's link label: a bare COUNT over the session's live
  // findings, not the grouped pipeline — it must not pay the whole-store
  // aggregate cost just to produce one number.
  it('sessionFindingsCount tallies the session without the grouped pipeline', async () => {
    seedSessions();
    expect(await db.findings.sessionFindingsCount(SESSION_A)).toBe(2);
    expect(await db.findings.sessionFindingsCount(SESSION_B)).toBe(1);
    expect(await db.findings.sessionFindingsCount('no-such-session')).toBe(0);
    // Sessionless findings never count toward any session.
    expect(await db.findings.sessionFindingsCount('')).toBe(0);
  });

  // Seed the OTHER finding store: a session root + tool events in audit_events,
  // with transcript-derived inspection findings attached — the rows behind the
  // Activity page's per-session "N triggered" tally. Written raw (the write
  // gateway lives in plugin-runtime, out of this package's reach).
  function seedTranscriptFirings(sessionId: string, ruleId: string, firings: number): void {
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    try {
      raw
        .prepare(
          `INSERT OR IGNORE INTO audit_events (id, event_type, started_at, content)
           VALUES (?, 'session', 0, 'seeded session')`,
        )
        .run(sessionId);
      raw
        .prepare(
          `INSERT OR IGNORE INTO inspection_definitions
             (id, rule_id, name, category, severity, definition, version)
           VALUES (?, ?, ?, 'secret', 'low', '{}', '1')`,
        )
        .run(`def-${ruleId}`, ruleId, ruleId);
      for (let i = 0; i < firings; i++) {
        const eventId = `${sessionId}-ev-${ruleId}-${String(i)}`;
        raw
          .prepare(
            `INSERT INTO audit_events (id, root_session_id, event_type, started_at, content)
             VALUES (?, ?, 'tool_call', ?, '')`,
          )
          .run(eventId, sessionId, i);
        raw
          .prepare(
            `INSERT INTO inspection_findings
               (id, audit_event_id, inspection_definition_id, span_start, span_end,
                masked_match, action_taken, confidence)
             VALUES (?, ?, ?, 0, 1, '••', 'log', 1)`,
          )
          .run(`${eventId}-f`, eventId, `def-${ruleId}`);
      }
    } finally {
      raw.close();
    }
  }

  // Session-scoped responses also carry the OTHER store's tally per rule — how
  // many times each rule fired in the session's transcript — so the findings
  // view can reconcile the Activity page's firing count with the deduped
  // groups it lists.
  it('session-scoped queries report per-rule transcript firings', async () => {
    seedSessions();
    seedTranscriptFirings(SESSION_A, 'aws-key', 3);
    seedTranscriptFirings(SESSION_A, 'transcript-only-rule', 5);

    const res = await db.findings.listGroupedFindings({ sessionId: SESSION_A });
    expect(res.sessionFirings).toEqual({ 'aws-key': 3, 'transcript-only-rule': 5 });

    // Another session's firings never leak in.
    const other = await db.findings.listGroupedFindings({ sessionId: SESSION_B });
    expect(other.sessionFirings).toEqual({});
  });

  it('unscoped queries carry no transcript firings', async () => {
    seedSessions();
    seedTranscriptFirings(SESSION_A, 'aws-key', 3);

    const res = await db.findings.listGroupedFindings({});
    expect(res.sessionFirings).toBeUndefined();
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
  // Pass the SAME contentHash to two calls to model identical bytes captured at
  // two paths: recordCapture content-addresses the audit row on (session,
  // contentHash), so both calls then resolve onto ONE audit_events row.
  contentHash?: string;
}): { eventId: string; findingId: string; auditEventId: string } {
  const eventId = randomUUID();
  const findingId = randomUUID();
  const contentHash = opts.contentHash ?? randomUUID();
  const metadata: EventMetadata = { filePath: opts.filePath ?? 'src/a.ts' };
  const event: IngestEvent = {
    id: eventId,
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: opts.occurredAt ?? '2026-01-01T00:00:00.000Z',
    contentHash,
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
  // recordCapture mints the audit_events row's own id as a content-address of
  // (sessionId, contentHash) — NOT the caller-supplied event.id — so a raw
  // read of inspection_findings.audit_event_id must be compared against this,
  // not against eventId. This helper never sets metadata.sessionId, so the
  // session component is always the null/no-session case.
  const auditEventId = captureId(null, contentHash);
  return { eventId, findingId, auditEventId };
}

// Raw inspection_findings rows for a finding_key, read over a second
// connection to the same file (mirrors resolutions.test.ts's pattern).
function findingRowsByKey(key: string): { id: string; event_id: string; action_taken: string }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  try {
    return raw
      .prepare(
        `SELECT id, audit_event_id AS event_id, action_taken
           FROM inspection_findings WHERE finding_key = :key`,
      )
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
    expect(rowsAfterSecond[0]?.event_id).toBe(second.auditEventId); // reconciled onto the latest scan
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
      const rows = raw
        .prepare('SELECT id FROM inspection_findings WHERE finding_key IS NULL')
        .all();
      expect(rows).toHaveLength(2);
    } finally {
      raw.close();
    }
  });
});

// A secret duplicated across two files (`.env` copied to `.env.local`, a config
// vendored into two packages, a fixture cloned) hashes to ONE contentHash, so
// recordCapture content-addresses both captures onto a SINGLE audit_events row.
// The two hits still carry DISTINCT finding_keys (the key is path-scoped), so
// the event-level dedup must key on finding_key: otherwise the second file's
// finding is taken for a replay of the first and silently dropped — never
// counted, tracked, or remediable.
describe('insertFindings — duplicate content at distinct paths', () => {
  it('keeps both findings when identical content at two paths collapses onto one audit event', async () => {
    const contentHash = randomUUID();
    const keyA = findingKeyFor('aws-key', 'src/a.env', 'fp-1');
    const keyB = findingKeyFor('aws-key', 'src/b.env', 'fp-1');

    recordAtRest({ contentHash, filePath: 'src/a.env', findingKey: keyA });
    recordAtRest({
      contentHash,
      filePath: 'src/b.env',
      findingKey: keyB,
      occurredAt: '2026-01-02T00:00:00.000Z',
    });

    // Both files collapse onto ONE content-addressed audit event...
    const rowsA = findingRowsByKey(keyA);
    const rowsB = findingRowsByKey(keyB);
    expect(rowsA).toHaveLength(1);
    expect(rowsB).toHaveLength(1);
    expect(rowsA[0]?.event_id).toBe(rowsB[0]?.event_id);

    // ...but each path keeps its own finding row, so neither is dropped. (The
    // displayed file path is the shared audit event's — both instances read
    // 'src/a.env' — because file_path lives on that content-collapsed row, not
    // on the finding; surfacing the second path by name is a captureId concern,
    // out of scope for this finding-level dedup fix.)
    const res = await db.findings.listGroupedFindings({});
    expect(res.totals).toEqual({ findings: 2, groups: 1 });
    expect(res.items[0]?.instanceCount).toBe(2);
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

  // The Status toolbar filter is a store-side filter like severity/provider —
  // it must narrow items, totals AND the other facets, not just the page the
  // caller already fetched.
  describe('status filter', () => {
    beforeEach(() => {
      // in-flight ⇒ handled
      record({
        occurredAt: '2026-01-01T00:00:00.000Z',
        sourceTool: 'claude-code',
        ruleId: 'handled-rule',
        repo: 'acme/api',
        filePath: 'a.ts',
      });
      // at-rest, tracked, unresolved ⇒ open
      recordAtRest({ findingKey: 'key-open', ruleId: 'open-rule' });
      // at-rest, tracked, resolved ⇒ resolved
      recordAtRest({ findingKey: 'key-resolved', ruleId: 'resolved-rule' });
      db.resolutions.insertResolution({
        findingKey: 'key-resolved',
        status: 'resolved',
        method: 'fixed-at-source',
        resolvedAt: Date.parse('2026-01-02T00:00:00.000Z'),
        evidence: '',
      });
    });

    it('keeps only groups whose derived status was requested', async () => {
      const res = await db.findings.listGroupedFindings({ status: ['open'] });
      expect(res.items.map((g) => g.id)).toEqual(['open-rule']);
    });

    it('keeps the union when several statuses are requested', async () => {
      const res = await db.findings.listGroupedFindings({ status: ['open', 'resolved'] });
      expect(res.items.map((g) => g.id).sort()).toEqual(['open-rule', 'resolved-rule']);
    });

    it('narrows totals to the filtered set (not just the fetched page)', async () => {
      expect((await db.findings.listGroupedFindings({})).totals).toEqual({
        findings: 3,
        groups: 3,
      });
      expect((await db.findings.listGroupedFindings({ status: ['open'] })).totals).toEqual({
        findings: 1,
        groups: 1,
      });
    });

    it('reports a status facet excluding its own filter, and applies it to the others', async () => {
      const res = await db.findings.listGroupedFindings({ status: ['open'] });
      // The status facet still counts every status, so the user can switch…
      expect(new Map(res.facets.status.map((f) => [f.value, f.count]))).toEqual(
        new Map([
          ['handled', 1],
          ['open', 1],
          ['resolved', 1],
        ]),
      );
      // …while the action facet DOES honor the status filter (open-rule only).
      expect(res.facets.action).toEqual([{ value: 'blocked', count: 1 }]);
    });

    it('composes with the other filters', async () => {
      const res = await db.findings.listGroupedFindings({
        status: ['open'],
        severity: ['critical'],
      });
      expect(res.items.map((g) => g.id)).toEqual(['open-rule']);
      expect(
        (await db.findings.listGroupedFindings({ status: ['open'], severity: ['low'] })).items,
      ).toEqual([]);
    });

    it('scopes totals and the instance preview to matching instances on a mixed-status group', async () => {
      // Two more in-flight (handled) instances on open-rule: the group still
      // folds to open (open dominates), but only ONE of its three instances IS
      // open — the tally and the preview must not report the other two.
      record({
        occurredAt: '2026-01-04T00:00:00.000Z',
        sourceTool: 'claude-code',
        ruleId: 'open-rule',
        repo: 'acme/api',
        filePath: 'b.ts',
      });
      record({
        occurredAt: '2026-01-05T00:00:00.000Z',
        sourceTool: 'claude-code',
        ruleId: 'open-rule',
        repo: 'acme/api',
        filePath: 'c.ts',
      });

      const res = await db.findings.listGroupedFindings({ status: ['open'] });
      const group = res.items.find((g) => g.id === 'open-rule');
      expect(group?.status).toBe('open');
      // instanceCount stays the whole-group tally; the preview and the totals
      // are status-scoped.
      expect(group?.instanceCount).toBe(3);
      expect(group?.instances.map((i) => i.status)).toEqual(['open']);
      expect(res.totals).toEqual({ findings: 1, groups: 1 });
    });

    it('keeps a group whose matching instances all sit outside the preview (empty narrowed preview)', async () => {
      // More in-flight (handled) instances than the preview holds, all NEWER
      // than open-rule's one open instance: the preview window is entirely
      // handled, yet the group folds to open on the strength of the older row.
      // The filter must keep the group, totals must count only the open
      // instance, and the narrowed preview is legitimately EMPTY — the view
      // layer renders an explicit notice for this case.
      for (let i = 0; i < 205; i++) {
        record({
          occurredAt: new Date(Date.parse('2026-02-01T00:00:00.000Z') + i * 1000).toISOString(),
          sourceTool: 'claude-code',
          ruleId: 'open-rule',
          repo: 'acme/api',
          filePath: `bulk/f${String(i)}.ts`,
        });
      }

      const res = await db.findings.listGroupedFindings({ status: ['open'] });
      const group = res.items.find((g) => g.id === 'open-rule');
      expect(group?.status).toBe('open');
      expect(group?.instanceCount).toBe(206);
      expect(group?.instances).toEqual([]);
      expect(res.totals).toEqual({ findings: 1, groups: 1 });
    });
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

/**
 * One rule, BULK in-flight instances, all on claude-code/block except the
 * explicit oddities the tests below pin. Timestamps ascend so `i` doubles as a
 * recency rank: instance 0 is the OLDEST and sits far outside the preview.
 *
 * Written over a raw handle in ONE transaction rather than through
 * recordCapture, which commits per call — BULK commits costs minutes on a
 * cold CI filesystem and starves the workers beside it. These are read-path
 * fixtures; the `record` helper above still covers the real write path.
 */
function seedBulk(intoDir: string, opts: { ruleId?: string } = {}): void {
  const ruleId = opts.ruleId ?? 'bulk-rule';
  const raw = new DatabaseSync(join(intoDir, DB_FILENAME));
  try {
    raw.exec('PRAGMA busy_timeout = 5000');
    // One shared inspection_definitions row for the rule — rule_id/category/
    // severity live there now, not on the finding row.
    raw
      .prepare(
        `INSERT OR IGNORE INTO inspection_definitions
           (id, rule_id, name, category, severity, definition, version)
         VALUES (?, ?, ?, 'secret', 'critical', '{}', '1')`,
      )
      .run(`def-${ruleId}`, ruleId, ruleId);
    const insertEvent = raw.prepare(
      `INSERT INTO audit_events (id, event_type, started_at, content, attributes)
       VALUES (?, 'prompt', ?, 'x', ?)`,
    );
    const insertFinding = raw.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, span_start, span_end,
          masked_match, action_taken, confidence, finding_key, first_detected_at)
       VALUES (?, ?, ?, 0, 1, 'masked', ?, 0.9, NULL, ?)`,
    );
    raw.exec('BEGIN');
    for (let i = 0; i < BULK; i++) {
      const eventId = `bulk-e-${String(i)}`;
      const occurredAt = Date.UTC(2026, 0, 1) + i * 60_000;
      insertEvent.run(
        eventId,
        occurredAt,
        JSON.stringify({
          // The lone cursor instance is the oldest row in the store...
          source_tool: i === 0 ? 'cursor' : 'claude-code',
          repo: i === 0 ? 'acme/ancient' : 'acme/api',
          file_path: `src/f${String(i)}.ts`,
        }),
      );
      // ...as is the lone redacted one.
      insertFinding.run(
        `bulk-f-${String(i)}`,
        eventId,
        `def-${ruleId}`,
        i === 0 ? 'redact' : 'block',
        occurredAt,
      );
    }
    raw.exec('COMMIT');
  } finally {
    raw.close();
  }
}

describe('SqliteFindingsRepository.listGroupedFindings — stores larger than the preview', () => {
  // Every assertion in this block reads the same BULK-instance store and none
  // writes, so it is seeded ONCE here rather than per test: re-seeding 2600 rows
  // seven times is enough disk traffic to time out the workers running beside
  // this file. Deliberately its own store, not the outer per-test `db`.
  let bulkDir: string;
  let bulkDb: ReturnType<typeof openLocalDatabase>;

  beforeAll(() => {
    bulkDir = mkdtempSync(join(tmpdir(), 'aka-findings-bulk-'));
    bulkDb = openLocalDatabase(bulkDir);
    seedBulk(bulkDir);
  });

  afterAll(() => {
    bulkDb.close();
    rmSync(bulkDir, { recursive: true, force: true });
  });

  it('counts every instance rather than saturating at the old 2000-row cap', async () => {
    const res = await bulkDb.findings.listGroupedFindings({});

    expect(res.totals).toEqual({ findings: BULK, groups: 1 });
    expect(res.items[0]?.instanceCount).toBe(BULK);
  });

  it('caps the instances preview without capping the count', async () => {
    const group = (await bulkDb.findings.listGroupedFindings({})).items[0];

    // The preview is bounded and holds the NEWEST instances...
    expect(group?.instances.length).toBeLessThan(BULK);
    expect(group?.instances[0]?.file).toBe(`src/f${String(BULK - 1)}.ts`);
    // ...while the count beside it still speaks for the whole group.
    expect(group?.instanceCount).toBe(BULK);
  });

  it('folds providers, actions and latest over instances outside the preview', async () => {
    const group = (await bulkDb.findings.listGroupedFindings({})).items[0];

    // The cursor/redact instance is the oldest row, far outside the preview —
    // only the SQL aggregate can still see it.
    expect(new Set(group?.providers)).toEqual(new Set(['claudecode', 'cursor']));
    expect(group?.aggregateAction).toBeNull(); // block + redact → Mixed
    expect(group?.latestDetectedAt).toBe(
      new Date(Date.UTC(2026, 0, 1) + (BULK - 1) * 60_000).toISOString(),
    );
  });

  it('filters and facets on an instance outside the preview', async () => {
    // Provider, action and free-text all match ONLY the oldest instance.
    expect(
      (await bulkDb.findings.listGroupedFindings({ provider: ['cursor'] })).items,
    ).toHaveLength(1);
    expect(
      (await bulkDb.findings.listGroupedFindings({ action: ['redacted'] })).items,
    ).toHaveLength(1);
    expect((await bulkDb.findings.listGroupedFindings({ q: 'acme/ancient' })).items).toHaveLength(
      1,
    );

    const facets = (await bulkDb.findings.listGroupedFindings({})).facets;
    expect(facets.provider.map((f) => f.value).sort()).toEqual(['claudecode', 'cursor']);
    expect(facets.action.map((f) => f.value).sort()).toEqual(['blocked', 'redacted']);
  });

  // The search text is the one aggregate that grows with the store, so it is
  // fetched ONLY for a request carrying a q. These pin both sides of that
  // switch: a q still reaches a buried instance, and no q still lists/counts.
  it('matches a buried instance on file path, and still filters when q finds nothing', async () => {
    // src/f0.ts belongs to the oldest instance — thousands of rows outside the
    // newest-200 preview.
    expect((await bulkDb.findings.listGroupedFindings({ q: 'src/f0.ts' })).items).toHaveLength(1);
    expect((await bulkDb.findings.listGroupedFindings({ q: 'no-such-repo' })).items).toEqual([]);
    expect((await bulkDb.findings.listGroupedFindings({ q: 'no-such-repo' })).totals).toEqual({
      findings: 0,
      groups: 0,
    });
  });

  it('counts and lists identically whether or not a q is supplied', async () => {
    const withoutQ = await bulkDb.findings.listGroupedFindings({});
    // 'acme' matches every instance's repo, so the filtered set is the whole
    // store — the q path must agree with the no-q path it skips the fetch on.
    const withQ = await bulkDb.findings.listGroupedFindings({ q: 'acme' });

    expect(withQ.totals).toEqual(withoutQ.totals);
    expect(withQ.items.map((g) => g.id)).toEqual(withoutQ.items.map((g) => g.id));
    expect(withQ.items[0]?.providers).toEqual(withoutQ.items[0]?.providers);
  });

  // The only case here that needs a second rule in the store, so it seeds the
  // outer per-test store rather than sharing the read-only one above.
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
    seedBulk(dir);

    const res = await db.findings.listGroupedFindings({});

    expect(res.items.map((g) => g.id).sort()).toEqual(['bulk-rule', 'buried-rule']);
    expect(res.totals).toEqual({ findings: BULK + 1, groups: 2 });
  });
});
