/**
 * Local body expiry.
 *
 * The property under test is a SPLIT, and both halves matter equally: the body
 * goes, the row and its findings stay. A sweep that deleted rows would satisfy
 * every "the body is gone" assertion here while destroying the security history
 * the store exists to keep, so every case that expires anything also asserts the
 * row and the finding survived.
 */
import type { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { corpusConnection } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const DAY = 86_400_000;
const NOW = Date.parse('2026-09-01T00:00:00Z');
const CUTOFF = NOW - 30 * DAY;

interface Seed {
  readonly id: string;
  readonly kind: string;
  readonly ageDays: number;
  readonly content: string | null;
  /** null = never delivered; -1 = permanent skip; number = delivered at. */
  readonly syncedAt?: number | null;
}

function seed(raw: DatabaseSync, rows: readonly Seed[]): void {
  const event = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, content, content_hash, attributes, synced_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  const def = raw.prepare(
    `INSERT INTO inspection_definitions (id, rule_id, name, category, severity, definition, version)
     VALUES ('def-1', 'rule.one', 'one', 'secret', 'high', '{}', '1')`,
  );
  const finding = raw.prepare(
    `INSERT INTO inspection_findings
       (id, audit_event_id, inspection_definition_id, span_start, span_end, masked_match, action_taken, confidence, finding_key)
     VALUES (?, ?, 'def-1', 0, 4, 'A**E', 'block', 1.0, ?)`,
  );
  raw.exec('BEGIN');
  def.run();
  for (const r of rows) {
    event.run(
      r.id,
      r.kind,
      NOW - r.ageDays * DAY,
      r.content,
      `hash-${r.id}`,
      '{"repo":"acme/app"}',
      r.syncedAt ?? null,
    );
    finding.run(`find-${r.id}`, r.id, `key-${r.id}`);
  }
  raw.exec('COMMIT');
}

const bodyOf = (raw: DatabaseSync, id: string) =>
  raw
    .prepare(`SELECT content, content_hash, content_expired_at FROM audit_events WHERE id = ?`)
    .get(id) as {
    content: string | null;
    content_hash: string | null;
    content_expired_at: number | null;
  };

const rowCount = (raw: DatabaseSync, table: string) =>
  (raw.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

describe('body expiry', () => {
  let store: OwnedTempStore;
  let raw: DatabaseSync;

  beforeEach(() => {
    store = createTempStore('aka-body-retention-', { migrated: true });
    raw = corpusConnection(store.open());
  });
  afterEach(() => {
    store.destroy();
  });

  it('expires bodies past the horizon and leaves newer ones alone', () => {
    seed(raw, [
      { id: 'old', kind: 'code_change', ageDays: 60, content: 'x'.repeat(100) },
      { id: 'new', kind: 'code_change', ageDays: 1, content: 'y'.repeat(100) },
    ]);
    const out = store
      .open()
      .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });

    expect(out.rowsExpired).toBe(1);
    expect(out.bytesFreed).toBe(100);
    expect(bodyOf(raw, 'old').content).toBeNull();
    expect(bodyOf(raw, 'new').content).toBe('y'.repeat(100));
  });

  it('keeps the row and its finding — the whole point of expiring the body', () => {
    seed(raw, [{ id: 'old', kind: 'code_change', ageDays: 60, content: 'x'.repeat(100) }]);
    store.open().bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });

    expect(rowCount(raw, 'audit_events')).toBe(1);
    expect(rowCount(raw, 'inspection_findings')).toBe(1);
    const row = bodyOf(raw, 'old');
    // content_hash survives: it is what backfill idempotency is keyed on, and
    // clearing it would make an expired row look re-ingestable.
    expect(row.content_hash).toBe('hash-old');
    expect(row.content_expired_at).toBe(NOW);
  });

  it('leaves a never-expired row distinguishable from an expired one', () => {
    seed(raw, [
      { id: 'bodyless', kind: 'code_change', ageDays: 60, content: null },
      { id: 'expired', kind: 'code_change', ageDays: 60, content: 'x'.repeat(10) },
    ]);
    store.open().bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });

    // Both read content IS NULL; only one was expired. Without the stamp a
    // reader cannot tell "never had a body" from "had one and lost it".
    expect(bodyOf(raw, 'bodyless').content_expired_at).toBeNull();
    expect(bodyOf(raw, 'expired').content_expired_at).toBe(NOW);
  });

  it('never touches a structural row', () => {
    seed(raw, [
      { id: 'sess', kind: 'session', ageDays: 60, content: 'x'.repeat(100) },
      { id: 'llm', kind: 'llm_call', ageDays: 60, content: 'x'.repeat(100) },
    ]);
    const out = store
      .open()
      .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });

    expect(out.rowsExpired).toBe(0);
    expect(bodyOf(raw, 'sess').content).toBe('x'.repeat(100));
    expect(bodyOf(raw, 'llm').content).toBe('x'.repeat(100));
  });

  describe('the sync lane', () => {
    const laneSeed: readonly Seed[] = [
      { id: 'undelivered', kind: 'prompt', ageDays: 60, content: 'p'.repeat(50), syncedAt: null },
      {
        id: 'delivered',
        kind: 'response',
        ageDays: 60,
        content: 'r'.repeat(50),
        syncedAt: NOW - DAY,
      },
      { id: 'skipped', kind: 'tool_use', ageDays: 60, content: 't'.repeat(50), syncedAt: -1 },
      { id: 'code', kind: 'code_change', ageDays: 60, content: 'c'.repeat(50), syncedAt: null },
    ];

    it('holds back an undelivered body when the lane is not sweepable', () => {
      seed(raw, laneSeed);
      const out = store
        .open()
        .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: false, now: NOW });

      // The undelivered prompt is the row a later `aka sync-history --on` can
      // still claim, with no age bound — expiring it would silently drop data
      // the organization is entitled to.
      expect(bodyOf(raw, 'undelivered').content).toBe('p'.repeat(50));
      expect(out.rowsHeldBySync).toBe(1);

      // Delivered and permanently-skipped rows owe nothing, so both go.
      expect(bodyOf(raw, 'delivered').content).toBeNull();
      expect(bodyOf(raw, 'skipped').content).toBeNull();
      // code_change is structurally excluded from the drain, so the lane gate
      // never applies to it.
      expect(bodyOf(raw, 'code').content).toBeNull();
      expect(out.rowsExpired).toBe(3);
    });

    it('expires an undelivered body only when the caller says the lane is sweepable', () => {
      seed(raw, laneSeed);
      const out = store
        .open()
        .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });

      expect(bodyOf(raw, 'undelivered').content).toBeNull();
      expect(out.rowsExpired).toBe(4);
      expect(out.rowsHeldBySync).toBe(0);
    });
  });

  it('counts bytes past an embedded NUL', () => {
    // LENGTH() on a TEXT value stops at the first NUL; real capture bodies carry
    // them. Measured over the text form, a 1.79 MB body reported as 9 characters
    // — so a sweep reporting its own effect would under-report by orders of
    // magnitude, which is the one number a user judges this feature by.
    const body = `head\u0000${'z'.repeat(500)}`;
    seed(raw, [{ id: 'nul', kind: 'code_change', ageDays: 60, content: body }]);

    const textLen = (
      raw.prepare(`SELECT LENGTH(content) AS n FROM audit_events WHERE id = 'nul'`).get() as {
        n: number;
      }
    ).n;
    expect(textLen).toBe(4); // the trap, pinned

    const out = store
      .open()
      .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });
    expect(out.bytesFreed).toBe(505);
  });

  it('stops at the row cap and says it is not done', () => {
    seed(
      raw,
      Array.from({ length: 10 }, (_, i) => ({
        id: `e${String(i)}`,
        kind: 'code_change',
        ageDays: 60,
        content: 'x'.repeat(10),
      })),
    );
    const out = store.open().bodyRetention.expire({
      cutoff: CUTOFF,
      sweepSyncLane: true,
      now: NOW,
      maxRows: 4,
      batchSize: 2,
    });

    expect(out.rowsExpired).toBe(4);
    expect(out.done).toBe(false);
    expect(
      (
        raw.prepare(`SELECT COUNT(*) AS n FROM audit_events WHERE content IS NOT NULL`).get() as {
          n: number;
        }
      ).n,
    ).toBe(6);
  });

  it('runs to completion across batches and reports done', () => {
    seed(
      raw,
      Array.from({ length: 7 }, (_, i) => ({
        id: `e${String(i)}`,
        kind: 'code_change',
        ageDays: 60,
        content: 'x'.repeat(10),
      })),
    );
    const out = store
      .open()
      .bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW, batchSize: 3 });

    expect(out.rowsExpired).toBe(7);
    expect(out.done).toBe(true);
  });

  it('preview reports what a pass would free and changes nothing', () => {
    seed(raw, [{ id: 'old', kind: 'code_change', ageDays: 60, content: 'x'.repeat(100) }]);
    const db = store.open();
    const preview = db.bodyRetention.preview({ cutoff: CUTOFF, sweepSyncLane: true });

    expect(preview).toEqual({ rowsExpired: 1, bytesFreed: 100, rowsHeldBySync: 0 });
    expect(bodyOf(raw, 'old').content).toBe('x'.repeat(100));

    // The preview's own figures must be what the pass then does, or a dry run
    // is a different question from the thing it claims to rehearse.
    const out = db.bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });
    expect({ rowsExpired: out.rowsExpired, bytesFreed: out.bytesFreed }).toEqual({
      rowsExpired: preview.rowsExpired,
      bytesFreed: preview.bytesFreed,
    });
  });

  it('is idempotent — a second pass finds nothing', () => {
    seed(raw, [{ id: 'old', kind: 'code_change', ageDays: 60, content: 'x'.repeat(100) }]);
    const db = store.open();
    db.bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW });
    const second = db.bodyRetention.expire({ cutoff: CUTOFF, sweepSyncLane: true, now: NOW + DAY });

    expect(second.rowsExpired).toBe(0);
    // The first stamp survives — a re-sweep must not restamp a row it did not
    // touch, or the marker stops meaning "when the body went".
    expect(bodyOf(raw, 'old').content_expired_at).toBe(NOW);
  });
});
