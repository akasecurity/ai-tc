import { existsSync, writeFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import { seedEnrolledCapturesOwed } from '../src/history-backfill.ts';
import { useTempStore, withTempStore } from './helpers/temp-store.ts';

// The re-seed an enrollment runs: every unsent capture of a newly enrolled
// repository is marked owed, so the history drain can send it. Best-effort: the
// enrollment has already been written when this runs, so it reports a failure
// as "nothing queued" and never throws.

// Seeded from the migrated template: nothing here is about opening a store. The
// case that needs NO store takes a bare one of its own.
const store = useTempStore('aka-enroll-reseed-', { migrated: true });

const T0 = Date.parse('2026-10-01T00:00:00.000Z');
const at = (offsetMs: number): string => new Date(T0 + offsetMs).toISOString();
const MINUTE = 60_000;
// Past every seeded row, so the drain's read sees all of them.
const ALL = T0 + 365 * 24 * 60 * MINUTE;
const ENROLLED = 'github.com/acme/payments-api';
const OTHER = 'github.com/acme/ledger';

/** One unsent capture, stamped with `scopeKey` when one is given. */
function seedCapture(
  db: LocalDatabase,
  id: string,
  offsetMs: number,
  scopeKey: string | undefined,
): void {
  db.auditEvents.ensureSessionRoot('cap-root', at(0));
  db.auditEvents.insertAuditEvent({
    id,
    eventType: 'prompt',
    rootSessionId: 'cap-root',
    parentId: 'cap-root',
    startedAt: at(offsetMs),
    content: `text of ${id}`,
    ...(scopeKey === undefined ? {} : { attributes: { scope_key: scopeKey } }),
  });
}

/** What the history drain would send now: owed, unsent captures, oldest first. */
const owedIds = (db: LocalDatabase): string[] =>
  db.historySync.pendingCaptureRows(10, ALL).map((row) => row.id);

describe('seedEnrolledCapturesOwed', () => {
  it('marks the unsent captures of the newly enrolled keys owed, and returns how many', () => {
    const db = store.open();
    seedCapture(db, 'cap-1', MINUTE, ENROLLED);
    seedCapture(db, 'cap-2', 2 * MINUTE, ENROLLED);
    seedCapture(db, 'cap-other', 3 * MINUTE, OTHER);
    seedCapture(db, 'cap-unkeyed', 4 * MINUTE, undefined);

    expect(seedEnrolledCapturesOwed(store.dataDir, [ENROLLED])).toBe(2);
    expect(owedIds(db)).toEqual(['cap-1', 'cap-2']);
  });

  it('counts only captures it newly marked, so a repeat counts none', () => {
    const db = store.open();
    seedCapture(db, 'cap-1', MINUTE, ENROLLED);

    expect(seedEnrolledCapturesOwed(store.dataDir, [ENROLLED])).toBe(1);
    expect(seedEnrolledCapturesOwed(store.dataDir, [ENROLLED])).toBe(0);
    expect(owedIds(db)).toEqual(['cap-1']);
  });

  it('marks nothing for an empty key list', () => {
    const db = store.open();
    seedCapture(db, 'cap-1', MINUTE, ENROLLED);

    expect(seedEnrolledCapturesOwed(store.dataDir, [])).toBe(0);
    expect(owedIds(db)).toEqual([]);
  });

  it('is undefined, and creates no store, on a machine that has never run init', () => {
    // A bare store of its own: the suite's store is seeded from the template, so
    // it already has the file this case says must not appear.
    withTempStore((bare) => {
      expect(existsSync(bare.dbFile)).toBe(false);

      expect(seedEnrolledCapturesOwed(bare.dataDir, [ENROLLED])).toBeUndefined();

      expect(existsSync(bare.dbFile)).toBe(false);
    }, 'aka-enroll-reseed-bare-');
  });

  it('is undefined, not thrown, when the store exists but cannot be opened', () => {
    // Bytes SQLite rejects, past the existence check, so the open itself fails.
    writeFileSync(store.dbFile, 'not a database');

    expect(seedEnrolledCapturesOwed(store.dataDir, [ENROLLED])).toBeUndefined();
  });
});
