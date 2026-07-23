import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type {
  ActionTaken,
  DetectedFindingWithKey,
  EventKind,
  EventMetadata,
  IngestEvent,
  Severity,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { DB_FILENAME } from '../../src/paths.ts';
import { SqliteSecurityRepository } from '../../src/repositories/security.ts';

const DAY_MS = 86_400_000;
// A fixed midday clock so window/bucket math is deterministic. Its UTC day is
// 2026-06-29; windows align to UTC midnight (00:00) of that day.
const NOW = Date.parse('2026-06-29T12:00:00.000Z');

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-security-'));
  db = openLocalDatabase(dir);
});

// Raw second connections handed to repos under test — closed before rmSync
// (Windows cannot delete a directory while a DB handle is open).
const rawConnections: DatabaseSync[] = [];

afterEach(() => {
  for (const raw of rawConnections.splice(0)) raw.close();
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

// Record one event + one finding. `daysAgo` is relative to NOW (fractional ok).
// `kind` defaults to 'prompt' (in-flight); pass 'code_change' for an at-rest
// finding, with `findingKey` set so a resolution row can key onto it.
// `severity` rides the finding's inspection_definitions row (keyed on ruleId,
// content-addressed with a fixed version), not the finding row itself —
// recordCapture upserts that row with INSERT OR IGNORE, so the FIRST severity
// written under a given ruleId sticks for every later finding sharing it. A
// test that records more than one severity in the same store must therefore
// give each severity its own `ruleId` (the default is `'r'`).
function record(opts: {
  daysAgo: number;
  severity?: Severity;
  actionTaken?: ActionTaken;
  repo?: string;
  filePath?: string;
  kind?: EventKind;
  findingKey?: string;
  ruleId?: string;
}): void {
  const id = randomUUID();
  const metadata: EventMetadata | undefined =
    opts.repo || opts.filePath
      ? {
          ...(opts.repo ? { repo: opts.repo } : {}),
          ...(opts.filePath ? { filePath: opts.filePath } : {}),
        }
      : undefined;
  const event: IngestEvent = {
    id,
    sourceTool: 'claude-code',
    kind: opts.kind ?? 'prompt',
    occurredAt: new Date(NOW - opts.daysAgo * DAY_MS).toISOString(),
    contentHash: id,
    content: 'x',
    ...(metadata ? { metadata } : {}),
  };
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: id,
    ruleId: opts.ruleId ?? 'r',
    category: 'secret',
    severity: opts.severity ?? 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'x',
    actionTaken: opts.actionTaken ?? 'block',
    confidence: 0.9,
    ...(opts.findingKey ? { findingKey: opts.findingKey } : {}),
  };
  db.recordCapture(event, [finding]);
}

// A SecurityViews bound to a second read connection with the fixed clock (the
// facade's own repo uses the wall clock — window math must be pinned in tests).
function security(): SqliteSecurityRepository {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  rawConnections.push(raw);
  return new SqliteSecurityRepository(raw, () => NOW);
}

describe('severitySummary', () => {
  it('counts by severity, zero-fills every level, and totals (whole-store)', async () => {
    record({ daysAgo: 0, severity: 'critical' });
    record({ daysAgo: 400, severity: 'critical' }); // not range-scoped — still counted
    record({ daysAgo: 1, severity: 'high', ruleId: 'r-high' });

    const res = await security().severitySummary();
    // All three are in-flight (default kind 'prompt') — born handled, so every
    // row is fully caught and nothing is open-at-rest.
    expect(res.bySeverity).toEqual([
      { severity: 'critical', count: 2, caught: 2, openAtRest: 0 },
      { severity: 'high', count: 1, caught: 1, openAtRest: 0 },
      { severity: 'medium', count: 0, caught: 0, openAtRest: 0 },
      { severity: 'low', count: 0, caught: 0, openAtRest: 0 },
    ]);
    expect(res.total).toBe(3);
    expect(res.needsRemediation).toBe(0);
  });

  it('splits caught vs open-at-rest: in-flight is born caught, at-rest is caught only once resolved', async () => {
    // In-flight (kind 'prompt') — caught regardless of any resolution.
    record({ daysAgo: 1, severity: 'critical' });
    // At-rest, no resolution row — open, needs remediation.
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change', findingKey: 'key-open' });
    // At-rest, WITH a resolution row — caught.
    record({
      daysAgo: 1,
      severity: 'high',
      kind: 'code_change',
      findingKey: 'key-resolved',
      ruleId: 'r-high',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-resolved',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW,
      evidence: '',
    });
    // A second at-rest, unresolved finding at a different severity, to confirm
    // needsRemediation sums across severities.
    record({
      daysAgo: 1,
      severity: 'medium',
      kind: 'code_change',
      findingKey: 'key-open-2',
      ruleId: 'r-medium',
    });

    const res = await security().severitySummary();
    expect(res.bySeverity).toEqual([
      { severity: 'critical', count: 2, caught: 1, openAtRest: 1 },
      { severity: 'high', count: 1, caught: 1, openAtRest: 0 },
      { severity: 'medium', count: 1, caught: 0, openAtRest: 1 },
      { severity: 'low', count: 0, caught: 0, openAtRest: 0 },
    ]);
    // count/total stay exactly as before — backward compatible.
    expect(res.total).toBe(4);
    expect(res.needsRemediation).toBe(2); // sum of openAtRest: critical(1) + medium(1)
  });

  it('latest-resolution-wins: a redetected finding (resolved, then reopened) counts as open-at-rest, not caught', async () => {
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change', findingKey: 'key-redetected' });
    // First disposition: fixed-at-source.
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - DAY_MS,
      evidence: '',
    });
    // Superseding disposition: the same secret was redetected on a later scan.
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'open',
      method: 'redetected',
      resolvedAt: NOW,
      evidence: '',
    });

    const res = await security().severitySummary();
    const critical = res.bySeverity.find((s) => s.severity === 'critical');
    expect(critical).toMatchObject({ caught: 0, openAtRest: 1 });
    expect(res.needsRemediation).toBe(1);
  });

  it('excludes legacy at-rest findings with no finding_key from caught/openAtRest, but keeps them in total/count', async () => {
    // Legacy at-rest finding from a pre-branch scan: kind code_change but no
    // finding_key — the resolution lifecycle can never attach to (or clear) it.
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change' }); // no findingKey
    // A normal, trackable open at-rest finding at the same severity, to prove
    // it's still counted while the legacy one isn't.
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change', findingKey: 'key-tracked' });

    const res = await security().severitySummary();
    const critical = res.bySeverity.find((s) => s.severity === 'critical');
    expect(critical).toEqual({ severity: 'critical', count: 2, caught: 0, openAtRest: 1 });
    expect(res.total).toBe(2);
    expect(res.needsRemediation).toBe(1);
  });
});

describe('enforcementActions', () => {
  it('counts the window per kind with a period-over-period delta; excludes allow/log', async () => {
    // Current 7d window: [NOW-7d, NOW).
    record({ daysAgo: 1, actionTaken: 'block' });
    record({ daysAgo: 2, actionTaken: 'block' });
    record({ daysAgo: 3, actionTaken: 'redact' });
    record({ daysAgo: 1, actionTaken: 'warn' });
    record({ daysAgo: 1, actionTaken: 'allow' }); // not enforcement
    record({ daysAgo: 0.5, actionTaken: 'log' }); // not enforcement
    // Prior window: [NOW-14d, NOW-7d).
    record({ daysAgo: 9, actionTaken: 'block' });

    const res = await security().enforcementActions('7d');
    expect(res.range).toBe('7d');
    expect(res.actions).toEqual([
      { kind: 'blocked', count: 2, delta: 1 }, // 2 current − 1 prior
      { kind: 'redacted', count: 1, delta: 1 },
      { kind: 'warned', count: 1, delta: 1 },
    ]);
    expect(res.total).toBe(4); // allow/log excluded
  });
});

describe('findingsTimeseries', () => {
  it('buckets by day for 7d, split by severity, zero-filled, low omitted', async () => {
    record({ daysAgo: 0.1, severity: 'critical' }); // today bucket (strictly before NOW)
    record({ daysAgo: 0.1, severity: 'high', ruleId: 'r-high' });
    record({ daysAgo: 2, severity: 'medium', ruleId: 'r-medium' });
    record({ daysAgo: 2, severity: 'low', ruleId: 'r-low' }); // omitted from the series

    const res = await security().findingsTimeseries('7d');
    expect(res.granularity).toBe('day');
    expect(res.points).toHaveLength(7);
    // Window is the 7 UTC days ending 2026-06-29.
    expect(res.points[0]?.timestamp).toBe('2026-06-23');
    expect(res.points.at(-1)).toEqual({ timestamp: '2026-06-29', critical: 1, high: 1, medium: 0 });
    expect(res.points[4]).toEqual({ timestamp: '2026-06-27', critical: 0, high: 0, medium: 1 });
  });

  it('buckets by week for 3m', async () => {
    const res = await security().findingsTimeseries('3m');
    expect(res.granularity).toBe('week');
    expect(res.points).toHaveLength(Math.ceil(90 / 7));
  });
});

describe('mttrTrend', () => {
  it('buckets mean MTTR by resolved_at, split by severity, over 7d', async () => {
    // Two critical findings resolved fixed-at-source in the "today" bucket
    // (2026-06-29): MTTR = resolvedAt - occurredAt for each, averaged.
    record({ daysAgo: 5, severity: 'critical', kind: 'code_change', findingKey: 'key-a' });
    db.resolutions.insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 0.1 * DAY_MS, // today's bucket
      evidence: '',
    });
    record({ daysAgo: 6, severity: 'critical', kind: 'code_change', findingKey: 'key-b' });
    db.resolutions.insertResolution({
      findingKey: 'key-b',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 0.1 * DAY_MS, // same bucket as key-a
      evidence: '',
    });
    // One high finding resolved two days ago (2026-06-27 bucket).
    record({
      daysAgo: 3,
      severity: 'high',
      kind: 'code_change',
      findingKey: 'key-c',
      ruleId: 'r-high',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-c',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 2 * DAY_MS,
      evidence: '',
    });

    const res = await security().mttrTrend('7d');
    expect(res.range).toBe('7d');
    expect(res.granularity).toBe('day');
    expect(res.points).toHaveLength(7);
    expect(res.points[0]?.timestamp).toBe('2026-06-23');

    // key-a: (5 - 0.1) days; key-b: (6 - 0.1) days; mean = 5.4 days in ms.
    const todaysPoint = res.points.at(-1);
    expect(todaysPoint?.timestamp).toBe('2026-06-29');
    expect(todaysPoint?.bySeverity.critical).toBeCloseTo(5.4 * DAY_MS);
    expect(todaysPoint?.bySeverity.high).toBeNull();
    expect(todaysPoint?.bySeverity.medium).toBeNull();
    expect(todaysPoint?.bySeverity.low).toBeNull();

    const twoDaysAgoPoint = res.points[4];
    expect(twoDaysAgoPoint?.timestamp).toBe('2026-06-27');
    expect(twoDaysAgoPoint?.bySeverity.high).toBe(1 * DAY_MS);
    expect(twoDaysAgoPoint?.bySeverity.critical).toBeNull();

    // A bucket with no resolutions at all is entirely null.
    const emptyPoint = res.points[1];
    expect(emptyPoint?.bySeverity).toEqual({
      critical: null,
      high: null,
      medium: null,
      low: null,
    });
  });

  it('clamps an inverted row (resolution before first detection) to 0 instead of a negative mean', async () => {
    // Reachable without a bug: finding_key has no machine component, so a
    // skewed clock on one machine can stamp a first detection AFTER another
    // machine's fix. daysAgo: -1 puts first detection a day in the future.
    record({ daysAgo: -1, severity: 'critical', kind: 'code_change', findingKey: 'key-inverted' });
    db.resolutions.insertResolution({
      findingKey: 'key-inverted',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 0.1 * DAY_MS, // today's bucket, before "first detection"
      evidence: '',
    });

    const res = await security().mttrTrend('7d');
    const todaysPoint = res.points.at(-1);
    // Counted (it IS a remediation) but clamped — never a negative duration,
    // which would violate the nonnegative contract and drag bucket means down.
    expect(todaysPoint?.bySeverity.critical).toBe(0);
  });

  it('excludes a superseded (redetected) resolution — latest-resolution-wins', async () => {
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change', findingKey: 'key-redetected' });
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 0.5 * DAY_MS,
      evidence: '',
    });
    // A later row supersedes it — the finding was redetected, so it must NOT
    // count as remediated even though an earlier row was fixed-at-source.
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'open',
      method: 'redetected',
      resolvedAt: NOW - 0.1 * DAY_MS,
      evidence: '',
    });

    const res = await security().mttrTrend('7d');
    expect(res.points.every((p) => p.bySeverity.critical === null)).toBe(true);
  });

  it('excludes a resolved finding whose method is not fixed-at-source', async () => {
    record({ daysAgo: 1, severity: 'medium', kind: 'code_change', findingKey: 'key-exception' });
    db.resolutions.insertResolution({
      findingKey: 'key-exception',
      status: 'resolved',
      method: 'exception',
      resolvedAt: NOW - 0.1 * DAY_MS,
      evidence: '',
    });

    const res = await security().mttrTrend('7d');
    expect(res.points.every((p) => p.bySeverity.medium === null)).toBe(true);
  });

  it('excludes legacy at-rest findings with no finding_key (no resolution can attach)', async () => {
    record({ daysAgo: 1, severity: 'critical', kind: 'code_change' }); // no findingKey

    const res = await security().mttrTrend('7d');
    expect(res.points.every((p) => p.bySeverity.critical === null)).toBe(true);
  });

  it('multi-scan re-detection: MTTR measures from the FIRST detection, not the latest re-scan', async () => {
    // First sighting 10 days ago, then re-detected 2 days ago under the SAME
    // finding_key. The ON CONFLICT (finding_key) upsert overwrites the finding's
    // event_id to the later (2d-ago) event but must PRESERVE first_detected_at at
    // the first (10d-ago) event, so MTTR reflects time-to-remediate from first
    // sighting.
    record({ daysAgo: 10, severity: 'critical', kind: 'code_change', findingKey: 'key-multi' });
    record({ daysAgo: 2, severity: 'critical', kind: 'code_change', findingKey: 'key-multi' });
    db.resolutions.insertResolution({
      findingKey: 'key-multi',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 0.1 * DAY_MS, // today's bucket
      evidence: '',
    });

    const res = await security().mttrTrend('7d');
    const todaysPoint = res.points.at(-1);
    expect(todaysPoint?.timestamp).toBe('2026-06-29');
    // ~9.9 days (resolved ~0.1d ago − first detected 10d ago). If the fix
    // regressed and MTTR read the current (re-scanned) event, it would be ~1.9d.
    expect(todaysPoint?.bySeverity.critical).toBeCloseTo(9.9 * DAY_MS);
  });

  it('buckets by week for 3m', async () => {
    const res = await security().mttrTrend('3m');
    expect(res.granularity).toBe('week');
    expect(res.points).toHaveLength(Math.ceil(90 / 7));
  });
});

describe('topSources', () => {
  it('ranks repos by findings in the window, limited; excludes out-of-window', async () => {
    record({ daysAgo: 1, repo: 'payments-api' });
    record({ daysAgo: 2, repo: 'payments-api' });
    record({ daysAgo: 3, repo: 'payments-api' });
    record({ daysAgo: 1, repo: 'web' });
    record({ daysAgo: 1 }); // no repo — excluded
    record({ daysAgo: 45, repo: 'old-repo' }); // outside the 30d window

    const res = await security().topSources('30d', { limit: 5 });
    expect(res.items).toEqual([
      { id: 'repo_payments-api', name: 'payments-api', kind: 'repo', findingsCount: 3 },
      { id: 'repo_web', name: 'web', kind: 'repo', findingsCount: 1 },
    ]);
  });

  it('honors limit', async () => {
    record({ daysAgo: 1, repo: 'a' });
    record({ daysAgo: 1, repo: 'a' });
    record({ daysAgo: 1, repo: 'b' });
    const res = await security().topSources('30d', { limit: 1 });
    expect(res.items.map((i) => i.name)).toEqual(['a']);
  });

  it('returns no items for the user kind (OSS has no per-user attribution)', async () => {
    record({ daysAgo: 1, repo: 'a' });
    const res = await security().topSources('30d', { kind: 'user' });
    expect(res.items).toEqual([]);
  });
});

describe('recentlyResolved', () => {
  it('includes a fixed-at-source resolved finding with correct path/severity/ISO timestamps', async () => {
    record({
      daysAgo: 5,
      severity: 'high',
      kind: 'code_change',
      findingKey: 'key-a',
      filePath: 'src/config.ts',
      ruleId: 'aws-secret-key',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - DAY_MS,
      evidence: '',
    });

    const res = await security().recentlyResolved();
    expect(res.items).toHaveLength(1);
    const item = res.items[0];
    expect(item).toEqual({
      findingKey: 'key-a',
      ruleId: 'aws-secret-key',
      severity: 'high',
      path: 'src/config.ts',
      resolvedAt: new Date(NOW - DAY_MS).toISOString(),
      detectedAt: new Date(NOW - 5 * DAY_MS).toISOString(),
    });
  });

  it('excludes a finding resolved then superseded by a later redetected/open row (latest-wins)', async () => {
    record({
      daysAgo: 5,
      kind: 'code_change',
      findingKey: 'key-redetected',
      filePath: 'src/redetected.ts',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 2 * DAY_MS,
      evidence: '',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-redetected',
      status: 'open',
      method: 'redetected',
      resolvedAt: NOW - DAY_MS,
      evidence: '',
    });

    const res = await security().recentlyResolved();
    expect(res.items).toEqual([]);
  });

  it('excludes legacy at-rest findings with no finding_key', async () => {
    // Legacy finding, no findingKey — a resolution row can never key onto it.
    record({ daysAgo: 5, kind: 'code_change', filePath: 'src/legacy.ts' });

    const res = await security().recentlyResolved();
    expect(res.items).toEqual([]);
  });

  it('orders by resolvedAt DESC and respects the limit', async () => {
    record({ daysAgo: 5, kind: 'code_change', findingKey: 'key-1', filePath: 'a.ts' });
    db.resolutions.insertResolution({
      findingKey: 'key-1',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 3 * DAY_MS,
      evidence: '',
    });
    record({ daysAgo: 5, kind: 'code_change', findingKey: 'key-2', filePath: 'b.ts' });
    db.resolutions.insertResolution({
      findingKey: 'key-2',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - DAY_MS,
      evidence: '',
    });
    record({ daysAgo: 5, kind: 'code_change', findingKey: 'key-3', filePath: 'c.ts' });
    db.resolutions.insertResolution({
      findingKey: 'key-3',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - 2 * DAY_MS,
      evidence: '',
    });

    const res = await security().recentlyResolved(2);
    expect(res.items.map((i) => i.findingKey)).toEqual(['key-2', 'key-3']);
  });

  it('multi-scan re-detection: detectedAt is the FIRST detection, not the latest re-scan', async () => {
    // First sighting 10 days ago, re-detected 2 days ago under the SAME
    // finding_key (same file). The upsert overwrites event_id to the later event,
    // but detectedAt must stay pinned to the first sighting.
    record({
      daysAgo: 10,
      severity: 'high',
      kind: 'code_change',
      findingKey: 'key-multi',
      filePath: 'src/multi.ts',
      ruleId: 'aws-secret-key',
    });
    record({
      daysAgo: 2,
      severity: 'high',
      kind: 'code_change',
      findingKey: 'key-multi',
      filePath: 'src/multi.ts',
      ruleId: 'aws-secret-key',
    });
    db.resolutions.insertResolution({
      findingKey: 'key-multi',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: NOW - DAY_MS,
      evidence: '',
    });

    const res = await security().recentlyResolved();
    expect(res.items).toHaveLength(1);
    // First detection (10d ago), NOT the re-scan (2d ago).
    expect(res.items[0]?.detectedAt).toBe(new Date(NOW - 10 * DAY_MS).toISOString());
    expect(res.items[0]?.path).toBe('src/multi.ts');
  });
});

describe('scanCoverage', () => {
  it('returns the curated per-provider coverage (claude code supported)', async () => {
    const res = await security().scanCoverage('30d');
    expect(res.range).toBe('30d');
    expect(res.providers[0]).toEqual({ provider: 'claudecode', coverage: 100, supported: true });
    expect(res.providers.every((p) => (p.supported ? p.coverage > 0 : p.coverage === 0))).toBe(
      true,
    );
    expect(res.providers.map((p) => p.provider)).toEqual([
      'claudecode',
      'cursor',
      'codex',
      'chatgpt',
      'copilot',
      'api',
    ]);
  });
});
