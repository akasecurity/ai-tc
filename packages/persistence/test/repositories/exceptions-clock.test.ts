import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import type {
  BlockedDetectionInput,
  CreateExceptionInput,
} from '../../src/repositories/exceptions.ts';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  BLOCKED_DETECTIONS_TTL_MS,
  DuplicateActiveExceptionError,
  SqliteExceptionsRepository,
} from '../../src/repositories/exceptions.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// The time-dependent half of the grant mechanism: expiry, both sweeps, and the
// terminal-collider supersede. Most cases here assert a boundary to the
// MILLISECOND, which is the whole reason the repository takes an injectable
// clock — on the wall clock those decisions can only be approached from far
// enough away that the one-millisecond discrimination (active collider vs.
// terminal collider; inside the window vs. outside) is unreachable, and the
// sibling suite has to fabricate raw row timestamps with UPDATE to get near
// them at all. The rest pin the stamping itself, and the last describe pins
// that the DEFAULT is still the wall clock.

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// A retention window for the sweep cases, and deliberately a local value that
// claims no link to the one plugin-runtime passes in production. `sweepTerminal`
// takes the window as an argument, so every assertion below drives BOTH that
// argument and the clock advance from this constant and would hold for any
// value — naming it after the production constant would promise a coupling
// nothing here can check.
const RETENTION_MS = 30 * DAY_MS;

// A named instant, not `Date.now()`. A run-dependent origin makes a boundary
// failure irreproducible, and it also stops the assertions below from
// discriminating: they pin the exact stamp, which is only decisive when the
// injected instant cannot be confused with the wall clock.
const T0 = Date.UTC(2026, 0, 15, 12, 0, 0);

let db: DatabaseSync;
let repo: SqliteExceptionsRepository;
let clock: number;
let fingerprintSeq = 0;

/** Move the injected clock to an absolute instant. */
function at(instant: number): void {
  clock = instant;
}

function iso(instant: number): string {
  return new Date(instant).toISOString();
}

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  applyMigrations(db);
  clock = T0;
  repo = new SqliteExceptionsRepository(db, () => clock);
});

afterEach(() => {
  db.close();
});

function input(overrides: Partial<CreateExceptionInput> = {}): CreateExceptionInput {
  fingerprintSeq += 1;
  return {
    ruleId: 'aws-access-key-id',
    category: 'secret',
    // Unique per call so a test only collides on the index when it means to.
    valueFingerprint: fingerprintSeq.toString(16).padStart(64, '0'),
    keyVersion: 1,
    maskedValue: 'AKIA******Q',
    scope: 'temporary',
    // An hour past the INJECTED clock, so a grant built with the default is
    // active for the cases below. The wall-clock describe builds its own input
    // instead — this default would be months stale against real time.
    expiresAt: iso(clock + HOUR_MS),
    maxUses: null,
    justification: 'temp deploy creds, rotating after infra apply',
    conditions: null,
    createdBy: 'alice',
    createdVia: 'cli-approve',
    ...overrides,
  };
}

function blockedInput(overrides: Partial<BlockedDetectionInput> = {}): BlockedDetectionInput {
  fingerprintSeq += 1;
  return {
    reference: `ref-${String(fingerprintSeq)}`,
    ruleId: 'aws-access-key-id',
    category: 'secret',
    valueFingerprint: fingerprintSeq.toString(16).padStart(64, '0'),
    keyVersion: 1,
    maskedValue: 'AKIA******Q',
    sessionId: 'session-1',
    repo: 'github.com/acme/api',
    ...overrides,
  };
}

/** Rows in storage, which is not the same question as rows a read returns. */
function rawBlockedCount(): number {
  return (db.prepare('SELECT count(*) AS c FROM blocked_detections').get() as { c: number }).c;
}

describe('SqliteExceptionsRepository — injected clock', () => {
  it('stamps every write from the injected clock, not the wall clock', async () => {
    const created = await repo.create(input({ expiresAt: iso(T0 + HOUR_MS) }));

    expect(created.createdAt).toBe(iso(T0));
    expect(created.updatedAt).toBe(iso(T0));
    expect(created.expiresAt).toBe(iso(T0 + HOUR_MS));

    // `revoke` stamps inline too. Before the injection a test could only assert
    // this was non-null; the exact instant is the new assertion.
    at(T0 + 5 * 60 * 1000);
    expect(await repo.revoke(created.id, 'alice', 'rotated early')).toBe(true);

    const revoked = await repo.getByIdPrefix(created.id);
    expect(revoked?.revokedAt).toBe(iso(T0 + 5 * 60 * 1000));
    expect(revoked?.updatedAt).toBe(iso(T0 + 5 * 60 * 1000));
  });

  it('defaults `consume` to the injected clock', async () => {
    const grant = await repo.create(input());

    at(T0 + 42);
    expect(await repo.consume(grant.id)).toBe(true);

    expect((await repo.getByIdPrefix(grant.id))?.lastUsedAt).toBe(iso(T0 + 42));
  });

  describe('expiry', () => {
    it('drops a grant from list() at the exact millisecond it expires', async () => {
      const expiry = T0 + HOUR_MS;
      const grant = await repo.create(input({ expiresAt: iso(expiry) }));

      at(expiry - 1);
      expect((await repo.list()).map((e) => e.id)).toEqual([grant.id]);

      // ACTIVE_PREDICATE is `expires_at > :now` — strictly future, so the grant
      // is terminal AT its expiry, not one millisecond after it.
      at(expiry);
      expect(await repo.list()).toEqual([]);

      // Terminal, not deleted: the row is retained as audit evidence.
      expect((await repo.list({ includeTerminal: true })).map((e) => e.id)).toEqual([grant.id]);
    });

    it('drops a grant from the bundle at the same boundary, with no explicit now', async () => {
      const expiry = T0 + HOUR_MS;
      await repo.create(input({ keyVersion: 7, expiresAt: iso(expiry) }));

      at(expiry - 1);
      expect(await repo.activeBundleEntries(7)).toHaveLength(1);

      at(expiry);
      expect(await repo.activeBundleEntries(7)).toEqual([]);
    });
  });

  describe('reveal grants', () => {
    // The stakes the suppression case does not carry: a reveal grant authorizes
    // decrypting a vaulted value, so an expiry that does not fire is the
    // difference between a time-boxed reveal and a permanent one.
    const REVEAL_FP = 'ab'.repeat(32);

    async function revealGrant(expiresAt: number) {
      return repo.create(
        input({
          capability: 'reveal_to_model',
          valueFingerprint: REVEAL_FP,
          expiresAt: iso(expiresAt),
        }),
      );
    }

    it('stops authorizing a reveal at the exact millisecond the grant expires', async () => {
      const expiry = T0 + HOUR_MS;
      const grant = await revealGrant(expiry);

      at(expiry - 1);
      expect(await repo.activeRevealGrant('aws-access-key-id', REVEAL_FP, 1)).toEqual({
        id: grant.id,
      });

      at(expiry);
      expect(await repo.activeRevealGrant('aws-access-key-id', REVEAL_FP, 1)).toBeNull();
    });

    it('stops authorizing a reveal the moment the grant is revoked', async () => {
      const grant = await revealGrant(T0 + DAY_MS);

      // Well inside the grant's life, so revocation — not expiry — is the only
      // thing that can change the answer below.
      at(T0 + 60_000);
      expect(await repo.activeRevealGrant('aws-access-key-id', REVEAL_FP, 1)).toEqual({
        id: grant.id,
      });

      expect(await repo.revoke(grant.id, 'alice')).toBe(true);
      expect(await repo.activeRevealGrant('aws-access-key-id', REVEAL_FP, 1)).toBeNull();
    });
  });

  describe('blocked-detections ledger', () => {
    it('ends the recentBlocked window exactly BLOCKED_DETECTIONS_TTL_MS after the write', async () => {
      const entry = blockedInput();
      await repo.recordBlocked(entry);

      // `blocked_at > :cutoff`, cutoff = now - windowMs: the row is in-window
      // while now < blockedAt + window.
      at(T0 + BLOCKED_DETECTIONS_TTL_MS - 1);
      expect((await repo.recentBlocked()).map((e) => e.reference)).toEqual([entry.reference]);

      at(T0 + BLOCKED_DETECTIONS_TTL_MS);
      expect(await repo.recentBlocked()).toEqual([]);

      // Out of the READ window is not out of storage — the wider lookback the
      // dashboard uses still reaches it, which is the distinction the retention
      // sweep below actually acts on.
      expect((await repo.recentBlocked(DAY_MS)).map((e) => e.reference)).toEqual([entry.reference]);
    });

    it('sweeps on write at exactly BLOCKED_DETECTIONS_RETENTION_MS, and not a millisecond earlier', async () => {
      await repo.recordBlocked(blockedInput());
      expect(rawBlockedCount()).toBe(1);

      // `blocked_at <= :cutoff`, cutoff = now - retention: one millisecond short
      // of the window, the row survives the write's sweep.
      at(T0 + BLOCKED_DETECTIONS_RETENTION_MS - 1);
      await repo.recordBlocked(blockedInput());
      expect(rawBlockedCount()).toBe(2);

      // At the boundary the first row is deleted from STORAGE. Counting raw
      // rows is load-bearing: read through `recentBlocked` and a swept row and
      // a merely out-of-window row look identical.
      at(T0 + BLOCKED_DETECTIONS_RETENTION_MS);
      await repo.recordBlocked(blockedInput());
      expect(rawBlockedCount()).toBe(2);
    });
  });

  describe('sweepTerminal', () => {
    it('holds the strict retention boundary, with no explicit now', async () => {
      const grant = await repo.create(input());
      await repo.revoke(grant.id, 'alice');

      // `updated_at < :cutoff`, cutoff = now - retention: at exactly one
      // retention window the row is NOT yet old enough.
      at(T0 + RETENTION_MS);
      expect(await repo.sweepTerminal(RETENTION_MS)).toBe(0);
      expect((await repo.list({ includeTerminal: true })).map((e) => e.id)).toEqual([grant.id]);

      at(T0 + RETENTION_MS + 1);
      expect(await repo.sweepTerminal(RETENTION_MS)).toBe(1);
    });

    it('sweeps a grant that went terminal only by expiring, never an active one', async () => {
      // Expires inside the window; nothing ever revokes or consumes it, so
      // `expires_at <= :now` is the only thing that can make it terminal.
      await repo.create(input({ expiresAt: iso(T0 + HOUR_MS) }));
      const permanent = await repo.create(input({ scope: 'permanent', expiresAt: null }));

      at(T0 + RETENTION_MS + 1);
      expect(await repo.sweepTerminal(RETENTION_MS)).toBe(1);

      // The exact surviving set, which is what says the sweep took the expired
      // row and only that one.
      const remaining = await repo.list({ includeTerminal: true });
      expect(remaining.map((e) => e.id)).toEqual([permanent.id]);
    });

    it('never sweeps an active grant, however far the clock advances', async () => {
      const grant = await repo.create(input({ scope: 'permanent', expiresAt: null }));

      at(T0 + 10 * 365 * DAY_MS);
      expect(await repo.sweepTerminal(RETENTION_MS)).toBe(0);
      expect((await repo.list()).map((e) => e.id)).toEqual([grant.id]);
    });

    /**
     * The cases above reach the expiry arm from far outside it — the clock
     * lands a whole retention window past the stamp, where `expires_at <= :now`
     * and `expires_at < :now` are the same question. So nothing pinned THIS
     * copy of the boundary: the supersede clause has a millisecond-exact pair
     * below, and the sweep had no counterpart.
     *
     * That matters because `sweepTerminal` does not read `ACTIVE_PREDICATE`; it
     * restates the complement longhand. This case asserts the two agree at the
     * one instant that can tell them apart — terminal per the sweep and inert
     * on all four readers of the predicate, at the same millisecond. A sweep
     * that drifted to `<` would leave a row every active surface has already
     * disowned.
     */
    it('sweeps at exactly the millisecond of expiry, agreeing with all four active surfaces', async () => {
      // Expiry a retention window past T0, so the row is ALREADY old enough
      // when the clock reaches the stamp. Nearer than that and `updated_at <
      // :cutoff` is what decides the case, leaving the expiry comparison
      // unreached — which is exactly how the boundary went unpinned above.
      const expiry = T0 + RETENTION_MS + 1;
      const SWEEP_FP = 'ef'.repeat(32);
      const expiring = await repo.create(
        input({
          // So the reveal surface is askable of this same row; the other three
          // do not filter on capability.
          capability: 'reveal_to_model',
          valueFingerprint: SWEEP_FP,
          expiresAt: iso(expiry),
        }),
      );
      // The control: equally old, never expires. Without it a sweep deleting
      // every row past the cutoff passes this test.
      const permanent = await repo.create(input({ scope: 'permanent', expiresAt: null }));

      at(expiry);

      // Inert on all four readers of the predicate. `consume` is asked BEFORE
      // the sweep: once the row is deleted it returns false whatever the
      // predicate says, and the assertion would hold vacuously.
      expect((await repo.list()).map((e) => e.id)).toEqual([permanent.id]);
      expect((await repo.activeBundleEntries(1)).map((e) => e.id)).toEqual([permanent.id]);
      expect(await repo.activeRevealGrant('aws-access-key-id', SWEEP_FP, 1)).toBeNull();
      expect(await repo.consume(expiring.id)).toBe(false);

      // ...and terminal per the sweep, at that same instant.
      expect(await repo.sweepTerminal(RETENTION_MS)).toBe(1);
      expect((await repo.list({ includeTerminal: true })).map((e) => e.id)).toEqual([permanent.id]);
    });
  });

  describe('terminal-collider supersede', () => {
    // Same triple, so the second insert always hits `uq_exceptions_active`.
    // Which branch it takes is decided purely by the clock.
    const TRIPLE = {
      ruleId: 'aws-access-key-id',
      valueFingerprint: 'cd'.repeat(32),
      keyVersion: 1,
    } as const;

    it('supersedes a collider that expires at exactly the injected instant', async () => {
      const expiry = T0 + HOUR_MS;
      const first = await repo.create(input({ ...TRIPLE, expiresAt: iso(expiry) }));

      // The supersede UPDATE matches `expires_at <= :now`.
      at(expiry);
      const second = await repo.create(input({ ...TRIPLE, expiresAt: iso(expiry + HOUR_MS) }));

      // The slot is the assertion: createSync mints a fresh UUID whichever
      // branch it took, so only the surviving active set says the supersede
      // fired.
      expect((await repo.list()).map((e) => e.id)).toEqual([second.id]);

      const superseded = await repo.getByIdPrefix(first.id);
      expect(superseded?.revokedAt).toBe(iso(expiry));
      expect(superseded?.revokeReason).toMatch(/superseded/);
    });

    it('refuses a collider one millisecond short of expiry — it is genuinely active', async () => {
      const expiry = T0 + HOUR_MS;
      const first = await repo.create(input({ ...TRIPLE, expiresAt: iso(expiry) }));

      at(expiry - 1);
      await expect(
        repo.create(input({ ...TRIPLE, expiresAt: iso(expiry + HOUR_MS) })),
      ).rejects.toThrow(DuplicateActiveExceptionError);

      // The refusal left the collider untouched — not revoked as superseded.
      const untouched = await repo.getByIdPrefix(first.id);
      expect(untouched?.revokedAt).toBeNull();
      expect((await repo.list()).map((e) => e.id)).toEqual([first.id]);
    });
  });
});

describe('SqliteExceptionsRepository — default clock', () => {
  // The injection must not have moved the product off the wall clock. Two
  // separate properties, and neither is asserted as an elapsed time: a
  // millisecond bracket sampled around the write is a flake on a loaded runner
  // (Date.now() is not guaranteed monotonic) and it cannot see the failure that
  // matters anyway.
  //
  // That failure is a clock read ONCE and reused — `((t) => () => t)(Date.now())`
  // — which a window bracketing its own construction satisfies by definition.
  // web-ui/app/lib/db.ts memoizes LocalDatabase on globalThis.__akaDb across
  // every request, so a repository built once and reused for hours is the
  // product's normal shape: a frozen clock there stops list() ever expiring a
  // grant and leaves activeRevealGrant authorizing model reveals past expiry.
  // Only a second read at a later instant separates the two.
  const store = useTempStore('aka-exceptions-clock-', { migrated: true });

  // Anchored to real time, not to `clock` — these repositories never see the
  // injected timeline, and a T0-anchored expiry would be months stale.
  function wallInput(): CreateExceptionInput {
    return input({ expiresAt: new Date(Date.now() + HOUR_MS).toISOString() });
  }

  /** Spin until the wall clock strictly advances — sub-millisecond in practice. */
  function tick(): void {
    const start = Date.now();
    while (Date.now() <= start) {
      /* the shortest wait that guarantees the next read is a different ms */
    }
  }

  /** Two creates through one repository, separated by a real millisecond. */
  async function stamps(repo: SqliteExceptionsRepository): Promise<[number, number]> {
    const first = await repo.create(wallInput());
    tick();
    const second = await repo.create(wallInput());
    return [Date.parse(first.createdAt), Date.parse(second.createdAt)];
  }

  it('reads the wall clock, freshly, when constructed without one', async () => {
    // Constructed OUTSIDE any measurement, so a clock frozen at construction
    // gets no free pass from a window it was built inside.
    const [first, second] = await stamps(new SqliteExceptionsRepository(db));

    // Months of margin instead of a millisecond bracket: this separates real
    // time from T0 decisively and cannot be moved by scheduler jitter.
    expect(first).toBeGreaterThan(T0 + 30 * DAY_MS);
    // Read per call, not once at construction. `not.toBe` rather than a
    // comparison, so a clock that steps BACKWARDS still reads as live.
    expect(second).not.toBe(first);
  });

  it('reads the wall clock, freshly, through openLocalDatabase', async () => {
    const [first, second] = await stamps(store.open().exceptions);

    expect(first).toBeGreaterThan(T0 + 30 * DAY_MS);
    expect(second).not.toBe(first);
  });
});
