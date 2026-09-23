import { randomUUID } from 'node:crypto';

import type { DetectedFinding, EventMetadata, IngestEvent } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { SqliteResolutionsRepository } from '../../src/repositories/resolutions.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-resolutions-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

// A second raw connection to the same file (mirrors SqliteSecurityRepository's
// test pattern) — `now` is injectable so created_at ordering is deterministic.
function resolutions(now: () => number = () => Date.now()): SqliteResolutionsRepository {
  const raw = store.openRaw();
  return new SqliteResolutionsRepository(raw, now);
}

// Record one at-rest (code_change) finding for `path`, then stamp its
// finding_key directly via a raw UPDATE. This test's DetectedFinding carries
// no findingKey, so recordCapture inserts the inspection_findings row with a
// NULL key — the correlation-key computation is separate, downstream work —
// so tests seed it directly.
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

  const raw = store.openRaw();
  raw.prepare('UPDATE inspection_findings SET finding_key = :findingKey WHERE id = :id').run({
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

describe('a DISMISSED key is not shielded from the resolve/redetect cycle', () => {
  // The dashboard's Dismiss dialog tells the reader a later scan will not
  // reopen what they closed. That is true only while the value stays put, and
  // this is the sequence where it stops being true — pinned as BEHAVIOUR,
  // because the dialog's own suite can only assert the wording of its copy and
  // would go on passing while the product did the opposite.

  it('is counted OPEN at rest, so the removal sweep resolves it like any other', () => {
    // The load-bearing link, and the one that is easy to assume goes the other
    // way: `openAtRestKeysForPath` classifies on `IS NOT 'resolved'`, so a
    // dismissal — which is not a fix — leaves the key in the set the scanner
    // diffs against. `resolveRemovedFindings` therefore has it in `prior`.
    const repo = resolutions(() => 1000);
    recordAtRestFinding('src/b.ts', 'key-b');
    repo.insertResolution({
      findingKey: 'key-b',
      status: 'dismissed',
      method: 'acknowledged',
      resolvedAt: 1000,
      evidence: '{}',
    });

    expect(repo.openAtRestKeysForPath('src/b.ts')).toEqual(['key-b']);
    // The control: it is not in the caught set either, so what is asserted
    // above is the dismissal failing to shield it rather than a read that
    // returns every key whatever its disposition.
    expect(repo.resolvedAtRestKeysForPath('src/b.ts')).toEqual([]);
  });

  it('dismiss -> remove -> re-add identical: the key comes back OPEN', () => {
    // The whole cycle, written out because each step is individually
    // unsurprising and only the sequence shows the outcome. A reader who
    // dismissed this finding is told it will not come back; it does.
    let clock = 1000;
    const repo = resolutions(() => clock);
    recordAtRestFinding('src/c.ts', 'key-c');

    clock = 2000;
    repo.insertResolution({
      findingKey: 'key-c',
      status: 'dismissed',
      method: 'acknowledged',
      resolvedAt: 2000,
      evidence: '{}',
    });
    expect(repo.openAtRestKeysForPath('src/c.ts')).toEqual(['key-c']);

    // The secret leaves the file. It was in `prior` and is not in the scan's
    // current keys, so the removal sweep resolves it fixed-at-source — the
    // dismissal is superseded by a row nobody asked for.
    clock = 3000;
    repo.insertResolution({
      findingKey: 'key-c',
      status: 'resolved',
      method: 'fixed-at-source',
      resolvedAt: 3000,
      evidence: JSON.stringify({ deleted: true }),
    });
    expect(repo.resolvedAtRestKeysForPath('src/c.ts')).toEqual(['key-c']);

    // The identical value is re-added. It is now a currently-produced key whose
    // latest disposition reads 'resolved', which is exactly what
    // reopenRedetectedFindings exists to supersede.
    clock = 4000;
    repo.insertResolution({
      findingKey: 'key-c',
      status: 'open',
      method: 'redetected',
      resolvedAt: 4000,
      evidence: JSON.stringify({ reason: 'redetected' }),
    });

    expect(repo.openAtRestKeysForPath('src/c.ts')).toEqual(['key-c']);
    expect(repo.latestByKey('key-c')?.status).toBe('open');
  });
});
