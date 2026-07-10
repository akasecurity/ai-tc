import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, EventMetadata, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../database.ts';
import { DB_FILENAME } from '../paths.ts';
import { SqliteResolutionsRepository } from './resolutions.ts';

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-resolutions-'));
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

// A second raw connection to the same file (mirrors SqliteSecurityRepository's
// test pattern) — `now` is injectable so created_at ordering is deterministic.
function resolutions(now: () => number = () => Date.now()): SqliteResolutionsRepository {
  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  rawConnections.push(raw);
  return new SqliteResolutionsRepository(raw, now);
}

// Record one at-rest (code_change) finding for `path`, then stamp its
// finding_key directly via a raw UPDATE. insertFindings deliberately never
// populates finding_key (see findings.ts) — the correlation-key computation is
// separate, downstream work — so tests seed it directly.
function recordAtRestFinding(path: string, findingKey: string): void {
  const eventId = randomUUID();
  const metadata: EventMetadata = { filePath: path };
  const event: IngestEvent = {
    id: eventId,
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: '2026-01-01T00:00:00.000Z',
    contentHash: randomUUID(),
    content: 'x',
    metadata,
  };
  const finding: DetectedFinding = {
    id: randomUUID(),
    eventId,
    ruleId: 'aws-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'masked',
    actionTaken: 'block',
    confidence: 0.9,
  };
  db.recordCapture(event, [finding]);

  const raw = new DatabaseSync(join(dir, DB_FILENAME));
  raw.prepare('UPDATE findings SET finding_key = :findingKey WHERE id = :id').run({
    findingKey,
    id: finding.id,
  });
  raw.close();
}

describe('insertResolution / latestByKey', () => {
  it('returns the newest resolution for a key, ordered by created_at', () => {
    let clock = 1000;
    const repo = resolutions(() => clock);

    repo.insertResolution({
      findingKey: 'k1',
      status: 'handled',
      method: 'enforced-in-flight',
      resolvedAt: 1000,
      evidence: 'first pass',
    });

    clock = 2000;
    repo.insertResolution({
      findingKey: 'k1',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 2000,
      evidence: 'second pass',
    });

    expect(repo.latestByKey('k1')).toEqual({
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 2000,
      evidence: 'second pass',
    });
  });

  it('returns undefined for a key with no resolution', () => {
    expect(resolutions().latestByKey('unknown-key')).toBeUndefined();
  });
});

describe('openAtRestKeysForPath', () => {
  it('returns an at-rest finding key with no resolution, and excludes it once resolved', () => {
    recordAtRestFinding('src/a.ts', 'key-a');

    expect(resolutions().openAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);

    resolutions().insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 3000,
      evidence: 'patched',
    });

    expect(resolutions().openAtRestKeysForPath('src/a.ts')).toEqual([]);
  });

  it('is scoped to the given path — a finding on a different path is excluded', () => {
    recordAtRestFinding('src/a.ts', 'key-a');
    recordAtRestFinding('src/b.ts', 'key-b');

    expect(resolutions().openAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);
    expect(resolutions().openAtRestKeysForPath('src/b.ts')).toEqual(['key-b']);
  });

  it('returns [] for a path with no findings', () => {
    expect(resolutions().openAtRestKeysForPath('src/nowhere.ts')).toEqual([]);
  });
});

describe('resolvedAtRestKeysForPath', () => {
  it('is empty before resolution, and returns the key once its latest disposition is resolved', () => {
    recordAtRestFinding('src/a.ts', 'key-a');
    expect(resolutions().resolvedAtRestKeysForPath('src/a.ts')).toEqual([]);

    resolutions().insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 3000,
      evidence: 'patched',
    });

    expect(resolutions().resolvedAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);
  });

  it('is scoped to the given path', () => {
    recordAtRestFinding('src/a.ts', 'key-a');
    recordAtRestFinding('src/b.ts', 'key-b');
    resolutions().insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 1000,
      evidence: '',
    });
    resolutions().insertResolution({
      findingKey: 'key-b',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 1000,
      evidence: '',
    });

    expect(resolutions().resolvedAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);
    expect(resolutions().resolvedAtRestKeysForPath('src/b.ts')).toEqual(['key-b']);
  });

  it('returns [] for a path with no findings', () => {
    expect(resolutions().resolvedAtRestKeysForPath('src/nowhere.ts')).toEqual([]);
  });
});

describe('latest-resolution-wins: redetection reopens a resolved key', () => {
  it('fix -> remove -> resolved -> re-add identical: openAtRestKeysForPath and resolvedAtRestKeysForPath both flip back', () => {
    let clock = 1000;
    const repo = resolutions(() => clock);
    recordAtRestFinding('src/a.ts', 'key-a');

    // Initially open (no disposition yet).
    expect(repo.openAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);
    expect(repo.resolvedAtRestKeysForPath('src/a.ts')).toEqual([]);

    // Secret removed; the auto-resolver marks it fixed-at-source. Now it reads
    // as caught, not open — this is the state the FIX #1 bug got stuck in.
    clock = 2000;
    repo.insertResolution({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 2000,
      evidence: JSON.stringify({ deleted: true }),
    });
    expect(repo.openAtRestKeysForPath('src/a.ts')).toEqual([]);
    expect(repo.resolvedAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);

    // The identical secret is re-added at the same path: the finding row
    // re-upserts under the same finding_key (simulated directly here — the
    // findings-table upsert itself is exercised by findings.test.ts), and the
    // scanner's reopenRedetectedFindings writes a superseding 'open' row.
    clock = 3000;
    repo.insertResolution({
      findingKey: 'key-a',
      status: 'open',
      method: 'redetected',
      resolvedAt: 3000,
      evidence: JSON.stringify({ reason: 'redetected' }),
    });

    // Back to open — the live at-rest secret is no longer hidden.
    expect(repo.openAtRestKeysForPath('src/a.ts')).toEqual(['key-a']);
    expect(repo.resolvedAtRestKeysForPath('src/a.ts')).toEqual([]);
  });
});
