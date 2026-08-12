/**
 * Which tables the store ever deletes from on age, and which it never does.
 *
 * The audit store is a **full prompt corpus**: every prompt, every assistant
 * response and every tool-call body a hooked agent produces lands in
 * `audit_events.content`. Two tables are swept on age — `blocked_detections`
 * after 24 h and terminal `exceptions` after 90 days — and it is easy to read
 * those two constants as evidence that the store manages its own size. It does
 * not. Everything else grows for as long as the machine is used, and at the
 * measured 797.9 B/event `store-growth.test.ts` pins that is the difference between a store
 * that settles and one that reaches a gigabyte per million events and keeps going.
 *
 * This pins the split BEHAVIOURALLY rather than by reading the source. A text
 * scan for `DELETE FROM` cannot tell a retention sweep from a cascade, a
 * reconcile or the sample purge, and it says nothing about whether the sweep
 * actually fires. So the store is filled through the product's own write paths,
 * every sweep the store exposes is run with a cutoff far past every row's age,
 * and the tables are counted before and after.
 *
 * TWO ASSERTIONS, AND THE SECOND IS WHAT MAKES THE FIRST WORTH ANYTHING.
 * "Nothing was deleted from `audit_events`" is satisfied just as well by a sweep
 * that silently did nothing at all — a mistyped cutoff, a statement that never
 * ran, an empty table. So the swept pair is asserted to have LOST rows in the
 * same run that the unbounded set is asserted to have kept them. Without that
 * positive control this file would keep passing after retention was removed
 * outright.
 *
 * WHEN THIS GOES RED. Adding retention for one of the unbounded tables is the
 * good case: move the table from one list to the other, and the diff records
 * the change in behaviour where a reader will find it. Removing a sweep fails
 * the positive control. Adding a table that grows without bound and not listing
 * it is the case nothing here can catch — `UNBOUNDED_TABLES` is a claim about
 * the tables it names, not a census — which is why the row-count check below
 * refuses a table that is empty when the sweeps run: an unlisted table is
 * invisible, but a listed one can never go quietly vacuous.
 */
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  SqliteExceptionsRepository,
} from '../../src/repositories/exceptions.ts';
import { CORPUS_EPOCH_MS, corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

/**
 * Tables that accumulate for the life of the install.
 *
 * The first three are what a capture writes: the event, its findings, and the
 * rule definition each finding points at. The vault trio is what tokenization
 * writes, and carries a second concern size alone does not describe — an entry
 * nobody will ever reveal again is a ciphertext that stays decryptable for as
 * long as its key epoch survives.
 */
const UNBOUNDED_TABLES = [
  'audit_events',
  'inspection_findings',
  'inspection_definitions',
  'secret_vault',
  'secret_vault_deref',
  'secret_vault_sighting',
] as const;

/** Tables a retention sweep deletes from on age. */
const SWEPT_TABLES = ['blocked_detections', 'exceptions'] as const;

const CORPUS_EVENTS = 500;

/**
 * The retention WINDOW handed to every sweep — one millisecond, so every row in
 * the store is already outside it and no sweep can be excused for sparing
 * anything.
 *
 * Note the direction: this is a window, not a cutoff instant. RAISING it spares
 * MORE rows, which would quietly disarm the positive control below rather than
 * strengthen it.
 */
const RETENTION_WINDOW_MS = 1;

/**
 * A 64-hex fingerprint, because `DetectionException` validates the shape. Not a
 * real HMAC of anything — the retention sweep keys on timestamps and status,
 * never on this value.
 */
const PROBE_FINGERPRINT = 'a'.repeat(64);

describe('the store retention surface', () => {
  let store: OwnedTempStore;
  let db: LocalDatabase;
  let before: Record<string, number>;
  let after: Record<string, number>;

  const counts = (): Record<string, number> => {
    const raw = corpusConnection(db);
    const out: Record<string, number> = {};
    for (const table of [...UNBOUNDED_TABLES, ...SWEPT_TABLES]) {
      // The table names are this file's own literals, never input.
      const row = raw.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number };
      out[table] = row.n;
    }
    return out;
  };

  beforeAll(async () => {
    store = createTempStore('aka-retention-');
    db = store.open();

    // --- fill every table under test, through the product's write paths -----
    seedCaptureCorpus(db, { events: CORPUS_EVENTS, sessions: 10, seed: 1 });

    const pointerId = `aka_pointer_${randomUUID()}`;
    db.secretVault.upsert(
      {
        pointerId,
        valueFingerprint: PROBE_FINGERPRINT,
        fingerprintKeyVersion: 1,
        keyVersion: 1,
        category: 'secret',
        ruleId: 'secrets/aws-access-key',
        maskedMatch: 'A***9',
        ciphertext: 'Y2lwaGVy',
        nonce: 'bm9uY2U=',
        authTag: 'dGFn',
      },
      CORPUS_EPOCH_MS,
    );
    db.secretVault.recordSighting(
      { pointerId, location: 'session:probe', kind: 'prompt' },
      CORPUS_EPOCH_MS,
    );
    db.secretVault.recordDeref({
      id: randomUUID(),
      pointerId,
      at: CORPUS_EPOCH_MS,
      target: 'human',
      reason: 'display',
      outcome: 'revealed',
    });

    // The two swept tables are written through a repository whose clock is
    // pinned to the corpus epoch, so their rows are genuinely YEARS old when
    // the sweeps run. Writing them through `db.exceptions` would stamp them at
    // the wall clock, leaving them milliseconds old — inside both retention
    // windows, spared for the correct reason, and the positive control would
    // fail while the product was behaving perfectly.
    const aged = new SqliteExceptionsRepository(corpusConnection(db), () => CORPUS_EPOCH_MS);

    await aged.recordBlocked({
      reference: 'ref-retention-probe',
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      valueFingerprint: PROBE_FINGERPRINT,
      keyVersion: 1,
      maskedValue: 'A***9',
      sessionId: null,
      repo: null,
    });

    // A grant that is already TERMINAL — `sweepTerminal` spares active ones by
    // design, so an active grant would make the positive control fail for a
    // reason that is correct behaviour.
    const granted = await aged.create({
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      valueFingerprint: PROBE_FINGERPRINT,
      keyVersion: 1,
      maskedValue: 'A***9',
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
      justification: 'retention probe',
      conditions: null,
      createdBy: 'test',
      createdVia: 'cli-add',
    });
    await aged.revoke(granted.id, 'test', 'retention probe');

    before = counts();

    // --- run every sweep the store exposes ----------------------------------
    // `recordBlocked` sweeps the ledger as a side effect of writing, which is
    // the only way that sweep ever runs in the product; `sweepTerminal` is
    // called by hand at SessionStart. Both get a cutoff that spares nothing.
    await db.exceptions.sweepTerminal(RETENTION_WINDOW_MS, Date.now());
    await db.exceptions.recordBlocked({
      reference: 'ref-retention-trigger',
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      valueFingerprint: PROBE_FINGERPRINT,
      keyVersion: 1,
      maskedValue: 'A***9',
      sessionId: null,
      repo: null,
    });

    after = counts();
  });

  afterAll(() => {
    store.destroy();
  });

  it('every table under test actually holds rows, so neither claim is vacuous', () => {
    // A count of 0 cannot shrink and cannot be preserved, so it would satisfy
    // both assertions below without exercising either.
    for (const table of [...UNBOUNDED_TABLES, ...SWEPT_TABLES]) {
      expect(before[table], `${table} was empty when the sweeps ran`).toBeGreaterThan(0);
    }
  });

  it('no sweep deletes from the tables that grow with use', () => {
    for (const table of UNBOUNDED_TABLES) {
      expect(after[table], `${table} lost rows to a sweep`).toBe(before[table]);
    }
  });

  it('the two swept tables did lose their aged rows', () => {
    // The positive control, and it asserts on row IDENTITY rather than on a
    // count. The blocked-detections sweep only runs as a side effect of a
    // WRITE, so the same call that deletes the aged row inserts a fresh one and
    // the table's size is unchanged — a tally would read that as "nothing was
    // swept" and fail while the sweep worked perfectly.
    const raw = corpusConnection(db);
    const references = (
      raw.prepare(`SELECT reference FROM blocked_detections`).all() as unknown as {
        reference: string;
      }[]
    ).map((r) => r.reference);
    expect(references).toEqual(['ref-retention-trigger']);

    // Nothing re-inserts an exception, so this one is a straight count.
    expect(after.exceptions).toBe(0);
    expect(after.exceptions).toBeLessThan(before.exceptions ?? 0);
  });

  it('the blocked-detections window is the only age bound on a capture-adjacent table', () => {
    // Reading the constant here rather than restating 24h: the point is that it
    // governs the ledger and nothing else. If a second retention constant
    // appears it belongs in this file's lists, and the assertions above are
    // what will say so.
    expect(BLOCKED_DETECTIONS_RETENTION_MS).toBe(24 * 60 * 60 * 1000);
  });
});
