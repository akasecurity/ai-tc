/**
 * The test-only raw-handle seam on `LocalDatabase`.
 *
 * Everything in `test/faults/` that faults the facade rests on one claim: the
 * handle behind `UNSAFE_TEST_ONLY_RAW_HANDLE` is the connection the facade
 * really writes through, not a second one on the same file. A seam pointing at
 * a sibling connection would leave every connection-scoped fault landing on a
 * handle nothing uses — and since those faults assert that a write did NOT
 * happen, the whole suite would pass while injecting nothing at all.
 *
 * So the identity claim is pinned here, on its own, in the one form that can
 * fail: a cap set through the seam must change what the FACADE does.
 *
 * The workspace-wide half — that no product code reads the seam — is a
 * different question and lives in
 * `packages/eslint-config/test/test-only-seam.test.js`, which is where the
 * tree-wide walk and its turbo inputs already are.
 */
import { realpathSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../src/database.ts';
import { captureEvent, captureFinding } from './helpers/capture-fixtures.ts';
import { fillStore } from './helpers/fault-injection.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-raw-seam-', { migrated: true });

/** Big enough that a capture needs a new page, not free space in an old one. */
const PAGE_HUNGRY_CONTENT = 'x'.repeat(4096);
/** More captures than a zero-headroom cap can take, so the fault bounds the run. */
const MORE_CAPTURES_THAN_FIT = 64;

function countAuditEvents(db: DatabaseSync): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM audit_events').get() as { n: number }).n;
}

function capture(db: LocalDatabase): void {
  const event = captureEvent({ content: PAGE_HUNGRY_CONTENT });
  db.recordCapture(event, [captureFinding(event.id)]);
}

describe('UNSAFE_TEST_ONLY_RAW_HANDLE', () => {
  it('is a live DatabaseSync on the store the facade opened', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];

    expect(raw).toBeInstanceOf(DatabaseSync);
    expect(raw.isOpen).toBe(true);
    // Same file, not merely the same shape. Both sides go through realpath:
    // macOS resolves the temp root through a /var -> /private/var symlink, and
    // only one of the two readings has been through it.
    expect(realpathSync(raw.location() ?? '')).toBe(realpathSync(store.dbFile));
  });

  it('is the connection the facade writes through, not a sibling on the same file', () => {
    const db = store.open();
    const sibling = store.openRaw();

    const filled = fillStore(db[UNSAFE_TEST_ONLY_RAW_HANDLE], { headroomPages: 0 });
    // The cap is on pages, not on rows, so the first few captures still fit in
    // free space the store already had. What the cap decides is where that
    // stops — so the measurement is the stall, not the first refusal.
    for (let i = 0; i < MORE_CAPTURES_THAN_FIT; i += 1) capture(db);
    const stalled = countAuditEvents(sibling);
    for (let i = 0; i < MORE_CAPTURES_THAN_FIT; i += 1) capture(db);

    // The two discriminating readings. Capping a SIBLING connection — the state
    // before this seam existed — leaves the facade untouched, so `stalled`
    // would be the whole first batch and the second batch would land on top of
    // it. Neither reading can be satisfied by a seam wired to the wrong handle.
    expect(stalled).toBeLessThan(MORE_CAPTURES_THAN_FIT);
    expect(countAuditEvents(sibling)).toBe(stalled);

    filled.restore();

    // Positive control: the refusals were the cap, not something this fault did
    // permanently to the store — and not `capture()` having quietly stopped
    // writing anything at all, which would satisfy both assertions above.
    capture(db);
    expect(countAuditEvents(sibling)).toBe(stalled + 1);
  });

  it('travels with the `{ ...db }` wrappers the test helpers hand out', () => {
    // `temp-store.ts` returns a spread copy so it can track `close()`, and
    // fault tests take the seam off THAT object. Spread copies own enumerable
    // properties, symbol keys included; make this one non-enumerable or a
    // getter and the copy silently loses it.
    const db = store.open();

    expect(Object.getOwnPropertySymbols(db)).toContain(UNSAFE_TEST_ONLY_RAW_HANDLE);
    const wrapped: LocalDatabase = { ...db };
    expect(wrapped[UNSAFE_TEST_ONLY_RAW_HANDLE]).toBe(db[UNSAFE_TEST_ONLY_RAW_HANDLE]);
  });

  it('closes with the facade rather than outliving it', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];

    db.close();

    // The seam hands out the real connection, so `close()` reaches it. A seam
    // that stayed open would leak a handle per store a test opens — and on
    // Windows keep the temp tree undeletable.
    expect(raw.isOpen).toBe(false);
  });
});
