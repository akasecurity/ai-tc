import { DatabaseSync } from 'node:sqlite';

import type { DetectionException } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import type {
  BlockedDetectionInput,
  CreateExceptionInput,
} from '../../src/repositories/exceptions.ts';
import {
  AmbiguousExceptionIdError,
  BLOCKED_DETECTIONS_RETENTION_MS,
  BLOCKED_DETECTIONS_TTL_MS,
  DuplicateActiveExceptionError,
  SqliteExceptionsRepository,
} from '../../src/repositories/exceptions.ts';
import { errorFrom } from '../helpers/errors.ts';
import { lockStore, primaryCode, SQLITE_BUSY } from '../helpers/fault-injection.ts';
import { withTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';
import { withTwoWriters, withWriters } from '../helpers/with-two-writers.ts';

let db: DatabaseSync;
let repo: SqliteExceptionsRepository;
let fingerprintSeq = 0;

// The repository's clock. Every "is this grant still active" question is a
// comparison against it, so a test that moves it can reach the far side of a
// 30-minute, 24-hour or 90-day window without fabricating a raw row timestamp
// — which is what fabricating one costs: the row stops having been written by
// the code under test, and the window it lands in stops being evidence about
// the write path. It starts at the wall clock and only the tests that mean to
// move time touch it, so a test that says nothing about time behaves exactly as
// it did before the seam existed.
let clock = 0;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  applyMigrations(db);
  clock = Date.now();
  repo = new SqliteExceptionsRepository(db, () => clock);
});

afterEach(() => {
  db.close();
});

const HOUR_MS = 60 * 60 * 1000;

function input(overrides: Partial<CreateExceptionInput> = {}): CreateExceptionInput {
  fingerprintSeq += 1;
  return {
    ruleId: 'aws-access-key-id',
    category: 'secret',
    // Unique per call so tests don't trip the one-active-grant index by accident.
    valueFingerprint: fingerprintSeq.toString(16).padStart(64, '0'),
    keyVersion: 1,
    maskedValue: 'AKIA******Q',
    scope: 'temporary',
    expiresAt: new Date(clock + HOUR_MS).toISOString(),
    maxUses: null,
    justification: 'temp deploy creds, rotating after infra apply',
    conditions: null,
    createdBy: 'alice',
    createdVia: 'cli-approve',
    ...overrides,
  };
}

/** An ISO stamp `ms` from the repository's current clock. */
function at(ms: number): string {
  return new Date(clock + ms).toISOString();
}

// Insert a row with a caller-controlled id (create() mints random UUIDs, so
// prefix-collision cases need direct inserts).
function insertRawException(id: string): void {
  const now = Date.now();
  fingerprintSeq += 1;
  db.prepare(
    `INSERT INTO exceptions (
       id, rule_id, category, value_fingerprint, key_version, masked_value, scope,
       expires_at, max_uses, use_count, justification, created_by, created_via,
       created_at, updated_at
     ) VALUES (:id, 'r', 'secret', :fp, 1, 'x***y', 'permanent', NULL, NULL, 0, 'why', 'me', 'cli-add', :now, :now)`,
  ).run({ id, fp: fingerprintSeq.toString(16).padStart(64, '0'), now });
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

describe('SqliteExceptionsRepository', () => {
  it('round-trips create → list with ISO timestamps mapped from ms-epoch columns', async () => {
    const expiresAt = new Date(Date.now() + HOUR_MS).toISOString();
    const created = await repo.create(input({ expiresAt, conditions: { repo: 'acme/api' } }));

    expect(created.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(created.useCount).toBe(0);
    expect(created.lastUsedAt).toBeNull();
    expect(created.revokedAt).toBeNull();
    // The column stores ms-epoch; the contract shape carries UTC ISO strings.
    expect(created.expiresAt).toBe(expiresAt);
    expect(created.createdAt).toMatch(/Z$/);
    expect(created.updatedAt).toBe(created.createdAt);

    const listed = await repo.list();
    expect(listed).toEqual([created]);
  });

  it('lists newest-first and hides terminal rows unless includeTerminal is set', async () => {
    const expired = await repo.create(
      input({ expiresAt: new Date(Date.now() - 1000).toISOString() }),
    );
    const revoked = await repo.create(input());
    await repo.revoke(revoked.id, 'alice');
    const exhausted = await repo.create(input({ scope: 'once', maxUses: 1 }));
    await repo.consume(exhausted.id);
    const active = await repo.create(input());

    const activeOnly = await repo.list();
    expect(activeOnly.map((e) => e.id)).toEqual([active.id]);

    const everything = await repo.list({ includeTerminal: true });
    expect(everything.map((e) => e.id)).toEqual([active.id, exhausted.id, revoked.id, expired.id]);
  });

  it('skips malformed rows instead of failing the read', async () => {
    const ok = await repo.create(input());
    insertRawException('deadbeef-0000-4000-8000-000000000000');
    db.prepare('UPDATE exceptions SET category = :c WHERE id LIKE :p').run({
      c: 'not-a-category',
      p: 'deadbeef%',
    });

    const listed = await repo.list();
    expect(listed.map((e) => e.id)).toEqual([ok.id]);
  });

  describe('consume', () => {
    it('decrements the use budget: maxUses=1 consumes exactly once', async () => {
      const grant = await repo.create(input({ scope: 'once', maxUses: 1 }));
      const now = Date.now();

      expect(await repo.consume(grant.id, now)).toBe(true);
      expect(await repo.consume(grant.id, now)).toBe(false);

      const after = await repo.getByIdPrefix(grant.id);
      expect(after?.useCount).toBe(1);
      expect(after?.lastUsedAt).toBe(new Date(now).toISOString());
      expect(after?.updatedAt).toBe(new Date(now).toISOString());
    });

    it('counts uses without a budget when maxUses is null', async () => {
      const grant = await repo.create(input({ maxUses: null }));
      expect(await repo.consume(grant.id)).toBe(true);
      expect(await repo.consume(grant.id)).toBe(true);
      expect((await repo.getByIdPrefix(grant.id))?.useCount).toBe(2);
    });

    it('enforces the expiry boundary: expires_at must be strictly in the future', async () => {
      const boundary = Date.now() + HOUR_MS;
      const grant = await repo.create(input({ expiresAt: new Date(boundary).toISOString() }));

      expect(await repo.consume(grant.id, boundary)).toBe(false); // expired AT the boundary
      expect(await repo.consume(grant.id, boundary - 1)).toBe(true);
    });

    it('returns false for an expired grant, which list() omits but includeTerminal shows', async () => {
      const grant = await repo.create(
        input({ expiresAt: new Date(Date.now() - 1000).toISOString() }),
      );

      expect(await repo.consume(grant.id)).toBe(false);
      expect(await repo.list()).toEqual([]);
      expect((await repo.list({ includeTerminal: true })).map((e) => e.id)).toEqual([grant.id]);
    });

    it('returns false for an unknown id', async () => {
      expect(await repo.consume('no-such-id')).toBe(false);
    });
  });

  /**
   * "Active" is DERIVED — `ACTIVE_PREDICATE` is its single definition, and no
   * column stores it — but FOUR surfaces ask the question independently:
   * `list()`, `activeBundleEntries()` (what rides the policy bundle to the
   * hook), `activeRevealGrant()` (what authorizes decrypting a vaulted value
   * for the model) and `consume()` (the claim itself). A predicate that drifts
   * on any one of them is a grant that goes on applying somewhere after the
   * user believed it was spent — silently, because every surface returns a
   * well-formed answer either way.
   *
   * So each case here asks all four OF ONE GRANT and asserts them together: a
   * per-surface test can be individually correct while the set disagrees, and
   * the disagreement is the bug. Every grant is minted `reveal_to_model` with
   * no conditions purely so the reveal surface is askable of the same row as
   * the other three — the capability and condition gates are separate
   * properties, pinned in their own block below.
   *
   * `consume()` is asked LAST because it is the one that mutates: it claims a
   * use, so probing it first would change the state the other three report on.
   */
  describe('the active-state predicate, on every surface that asks', () => {
    interface Surfaces {
      listed: boolean;
      inBundle: boolean;
      revealable: boolean;
      consumable: boolean;
    }

    const ACTIVE: Surfaces = {
      listed: true,
      inBundle: true,
      revealable: true,
      consumable: true,
    };
    const INERT: Surfaces = {
      listed: false,
      inBundle: false,
      revealable: false,
      consumable: false,
    };

    function revealGrant(
      overrides: Partial<CreateExceptionInput> = {},
    ): Promise<DetectionException> {
      return repo.create(input({ capability: 'reveal_to_model', ...overrides }));
    }

    async function probe(grant: DetectionException): Promise<Surfaces> {
      const listed = (await repo.list()).some((e) => e.id === grant.id);
      const inBundle = (await repo.activeBundleEntries(grant.keyVersion)).some(
        (e) => e.id === grant.id,
      );
      const reveal = await repo.activeRevealGrant(
        grant.ruleId,
        grant.valueFingerprint,
        grant.keyVersion,
      );
      return {
        listed,
        inBundle,
        revealable: reveal?.id === grant.id,
        consumable: await repo.consume(grant.id),
      };
    }

    it('an unexpired grant under its budget is active on all four', async () => {
      expect(await probe(await revealGrant())).toEqual(ACTIVE);
    });

    it('an expired grant is inert on all four', async () => {
      const grant = await revealGrant({ expiresAt: at(HOUR_MS) });
      clock += HOUR_MS;
      expect(await probe(grant)).toEqual(INERT);
    });

    it('expiry is exclusive: active through the last millisecond, inert at the stamp', async () => {
      const grant = await revealGrant({ expiresAt: at(HOUR_MS) });

      clock += HOUR_MS - 1;
      expect(await probe(grant)).toEqual(ACTIVE);

      // The probe above claimed a use, but `maxUses` is null here, so the only
      // thing that can have changed between these two assertions is the clock.
      clock += 1;
      expect(await probe(grant)).toEqual(INERT);
    });

    it('a budget-exhausted grant is inert on all four', async () => {
      const grant = await revealGrant({ scope: 'once', maxUses: 1 });
      expect(await repo.consume(grant.id)).toBe(true); // 1 of 1 spent
      expect(await probe(grant)).toEqual(INERT);
    });

    it('the budget is exclusive too: the last use inside it still applies', async () => {
      const grant = await revealGrant({ maxUses: 2 });
      expect(await probe(grant)).toEqual(ACTIVE); // useCount 0 -> 1
      expect(await probe(grant)).toEqual(ACTIVE); // useCount 1 -> 2
      expect(await probe(grant)).toEqual(INERT); // 2 >= 2
    });

    it('maxUses null is unlimited — the budget clause is skipped, never defaulted', async () => {
      const grant = await revealGrant({ maxUses: null });

      expect(await probe(grant)).toEqual(ACTIVE);
      expect(await probe(grant)).toEqual(ACTIVE);
      expect(await probe(grant)).toEqual(ACTIVE);

      // Uses are still COUNTED without a budget; what is absent is the ceiling.
      expect((await repo.getByIdPrefix(grant.id))?.useCount).toBe(3);
    });

    it('a revoked grant is inert on all four', async () => {
      const grant = await revealGrant();
      expect(await repo.revoke(grant.id, 'alice')).toBe(true);
      expect(await probe(grant)).toEqual(INERT);
    });
  });

  /**
   * The bundle entry carries `useCount`, and the hook pre-filters on it before
   * asking the store. That number is a SNAPSHOT taken when the bundle was
   * built: the hook, the CLI and the dashboard each hold their own connection
   * to one `aka.db`, so by the time the hook acts on it another process may
   * have spent the budget. The pre-filter is an optimization; `consume` is the
   * authority.
   */
  describe('the bundle useCount is a snapshot, not the authority', () => {
    it('a stale snapshot still reads under budget after the store has refused', async () => {
      const grant = await repo.create(input({ scope: 'once', maxUses: 1 }));
      const [snapshot] = await repo.activeBundleEntries(grant.keyVersion);
      expect(snapshot).toMatchObject({ id: grant.id, maxUses: 1, useCount: 0 });

      // Another crossing spends the single use.
      expect(await repo.consume(grant.id)).toBe(true);

      // The entry in hand is a value, not a view, so it still reads as
      // applicable — a pre-filter trusting it would apply this grant twice...
      expect(snapshot?.useCount).toBe(0);
      // ...and the store is what refuses.
      expect(await repo.consume(grant.id)).toBe(false);
      // A bundle rebuilt now no longer carries it at all.
      expect(await repo.activeBundleEntries(grant.keyVersion)).toEqual([]);
    });
  });

  /**
   * `consume` is the fail-secure primitive: the budget check and the claim ride
   * ONE conditional UPDATE, so no window exists between them. What that buys is
   * a budget that holds across the processes the product actually runs in — a
   * hook, the CLI and the dashboard each open their own handle on one `aka.db`,
   * with WAL and `busy_timeout` between them and nothing else.
   *
   * `node:sqlite` is synchronous, so handles on one thread interleave rather
   * than collide. These cases pin that N independent claimants share ONE
   * budget, which is the property the product depends on. They do NOT
   * demonstrate a read/read/write/write interleaving — that is unreachable from
   * one thread and would need a seam inside `consume` — so do not read them as
   * proof of that.
   */
  describe('consume across independent handles', () => {
    it('two handles, one use: exactly one of them claims it', () =>
      withTwoWriters(async (a, b) => {
        const grant = await a.exceptions.create(input({ scope: 'once', maxUses: 1 }));

        const claims = [await a.exceptions.consume(grant.id), await b.exceptions.consume(grant.id)];

        expect(claims).toEqual([true, false]);
        // Read back through the OTHER handle: one claim, counted once.
        expect((await b.exceptions.getByIdPrefix(grant.id))?.useCount).toBe(1);
      }));

    it('four handles share one budget of two', () =>
      withWriters(4, async (writers) => {
        const [w0, w1, w2, w3] = writers;
        if (!w0 || !w1 || !w2 || !w3) throw new Error('expected four handles');
        const grant = await w0.exceptions.create(input({ maxUses: 2 }));

        const claims = [
          await w0.exceptions.consume(grant.id),
          await w1.exceptions.consume(grant.id),
          await w2.exceptions.consume(grant.id),
          await w3.exceptions.consume(grant.id),
        ];

        expect(claims).toEqual([true, true, false, false]);
        expect((await w3.exceptions.getByIdPrefix(grant.id))?.useCount).toBe(2);
      }));

    it('a contended claim refuses by throwing, and spends nothing', () =>
      withTempStore(async (store) => {
        const seed = store.open();
        const grant = await seed.exceptions.create(input({ scope: 'once', maxUses: 1 }));

        // A repository over a handle the TEST owns: `LocalDatabase` exposes no
        // accessor for the connection it opened, and the connection that meets
        // the contention is the one the assertions below have to inspect.
        // Both handles are taken BEFORE the lock — opening one while the write
        // lock is held fails, because opening writes on the way in.
        const raw = store.openRaw();
        const contended = new SqliteExceptionsRepository(raw);

        // Hold the write lock from a worker; a handle on this thread would
        // interleave rather than contend.
        const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
        // `consume` is deliberately NOT wrapped in try/catch, so contention
        // surfaces as a throw. Captured outside its own catch — inside one, a
        // `consume` that stopped throwing would satisfy the assertion below.
        //
        // `errorFrom` is a SYNCHRONOUS try/catch, and it reaches this throw
        // only because `consume` returns `Promise.resolve(...)` rather than
        // being `async`: the statement runs on the calling stack, before any
        // promise exists. Marking it `async` — a refactor its return type
        // invites — turns the throw into a rejection this cannot see, and the
        // assertion below then fails on `undefined` with an unhandled
        // rejection beside it.
        const err = errorFrom(() => contended.consume(grant.id));
        lock.release();

        expect(primaryCode(err)).toBe(SQLITE_BUSY);
        // The refusal cost nothing: the use is unspent...
        expect((await seed.exceptions.getByIdPrefix(grant.id))?.useCount).toBe(0);
        // ...which is what makes the throw a refusal rather than a loss — the
        // one use is still there to claim once the lock is gone.
        expect(await contended.consume(grant.id)).toBe(true);
        // A forward guard rather than a live one: `consume` is a single
        // autocommit statement, so there is no envelope to strand today. It
        // goes live the moment one is added around it.
        assertNoOpenTransaction(raw);
      }));
  });

  describe('revoke', () => {
    it('is terminal: a revoked grant no longer consumes', async () => {
      const grant = await repo.create(input());

      expect(await repo.revoke(grant.id, 'alice', 'no longer needed')).toBe(true);
      expect(await repo.consume(grant.id)).toBe(false);

      const revoked = await repo.getByIdPrefix(grant.id);
      expect(revoked?.revokedAt).not.toBeNull();
      expect(revoked?.revokedBy).toBe('alice');
      expect(revoked?.revokeReason).toBe('no longer needed');
    });

    it('returns false when already revoked or unknown', async () => {
      const grant = await repo.create(input());
      await repo.revoke(grant.id, 'alice');

      expect(await repo.revoke(grant.id, 'alice')).toBe(false);
      expect(await repo.revoke('no-such-id', 'alice')).toBe(false);
    });
  });

  describe('unique active grant per (rule, fingerprint, keyVersion)', () => {
    it('rejects a duplicate active grant with a tagged error', async () => {
      const first = input();
      await repo.create(first);

      await expect(
        repo.create(
          input({
            ruleId: first.ruleId,
            valueFingerprint: first.valueFingerprint,
            keyVersion: first.keyVersion,
          }),
        ),
      ).rejects.toThrow(DuplicateActiveExceptionError);
      await expect(
        repo.create(
          input({
            ruleId: first.ruleId,
            valueFingerprint: first.valueFingerprint,
            keyVersion: first.keyVersion,
          }),
        ),
      ).rejects.toThrow(/duplicate-active-exception/);
    });

    it('allows a re-grant after revocation (the index is partial on revoked_at IS NULL)', async () => {
      const first = input();
      const created = await repo.create(first);
      await repo.revoke(created.id, 'alice');

      const again = await repo.create(
        input({
          ruleId: first.ruleId,
          valueFingerprint: first.valueFingerprint,
          keyVersion: first.keyVersion,
        }),
      );
      expect(again.id).not.toBe(created.id);
      expect((await repo.list()).map((e) => e.id)).toEqual([again.id]);
    });

    it('supersedes a budget-exhausted collider: re-grant after a consumed once just works', async () => {
      const first = input({ scope: 'once', maxUses: 1 });
      const created = await repo.create(first);
      expect(await repo.consume(created.id)).toBe(true); // terminal: 1/1 used

      const again = await repo.create(
        input({
          ruleId: first.ruleId,
          valueFingerprint: first.valueFingerprint,
          keyVersion: first.keyVersion,
          scope: 'once',
          maxUses: 1,
        }),
      );
      expect(again.id).not.toBe(created.id);
      // The consumed collider was auto-revoked as superseded — audit retained.
      const all = await repo.list({ includeTerminal: true });
      const old = all.find((e) => e.id === created.id);
      expect(old?.revokedAt).not.toBeNull();
      expect(old?.revokeReason).toMatch(/superseded/);
      expect((await repo.list()).map((e) => e.id)).toEqual([again.id]);
    });

    it('supersedes a naturally-expired collider', async () => {
      const past = new Date(Date.now() - HOUR_MS).toISOString();
      const first = input({ expiresAt: past });
      const created = await repo.create(first);

      const again = await repo.create(
        input({
          ruleId: first.ruleId,
          valueFingerprint: first.valueFingerprint,
          keyVersion: first.keyVersion,
        }),
      );
      expect(again.id).not.toBe(created.id);
      const old = (await repo.list({ includeTerminal: true })).find((e) => e.id === created.id);
      expect(old?.revokedAt).not.toBeNull();
    });

    it('defers to an outer transaction: a throw after the retry rolls back both the revoke and the insert', async () => {
      // A maxUses:1 grant, consumed once, occupies the partial-index slot as
      // a terminal (not active) row.
      const first = input({ scope: 'once', maxUses: 1 });
      const created = await repo.create(first);
      expect(await repo.consume(created.id)).toBe(true);

      const colliding = input({
        ruleId: first.ruleId,
        valueFingerprint: first.valueFingerprint,
        keyVersion: first.keyVersion,
        scope: 'once',
        maxUses: 1,
      });

      // BEGIN/ROLLBACK on the same handle the repo is bound to.
      db.exec('BEGIN');
      try {
        await expect(
          (async () => {
            await repo.create(colliding);
            throw new Error('outer rollback');
          })(),
        ).rejects.toThrow('outer rollback');
      } finally {
        db.exec('ROLLBACK');
      }

      // Both the supersede UPDATE and the retry INSERT rolled back.
      const all = await repo.list({ includeTerminal: true });
      expect(all.map((e) => e.id)).toEqual([created.id]);
      expect(all[0]?.revokedAt).toBeNull();
      expect(all[0]?.revokeReason).toBeNull();
      expect(all[0]?.useCount).toBe(1);
      expect(all[0]?.maxUses).toBe(1);
    });

    // The expiry stamp itself — where `ACTIVE_PREDICATE`'s `expires_at > :now`
    // and the supersede clause's `expires_at <= :now` must stay complements —
    // is pinned in exceptions-clock.test.ts, which drives both sides of that
    // millisecond off the injected clock.

    /**
     * The supersede and the re-insert run inside ONE transaction so "two
     * concurrent creates cannot both claim the freed slot". This is that
     * invariant seen from outside: the second arrival meets an ACTIVE collider
     * — the grant the first one just made — and is refused, rather than finding
     * a half-freed slot and superseding a live grant.
     *
     * What it does NOT do is distinguish `IMMEDIATE` from `DEFERRED`. Nothing
     * reachable from a test can, in this code shape: the first statement inside
     * the transaction is already a write, so both modes take the write lock at
     * the same moment, both surface contention as `SQLITE_BUSY`, and
     * `withTransaction` rolls back either way. Swap the mode and this file stays
     * green — knowingly. The mode is a belt-and-braces choice about WHEN the
     * lock is taken, and the invariant it protects is what is asserted here.
     */
    it('two handles cannot both claim the slot a terminal collider frees', () =>
      withTwoWriters(async (a, b) => {
        const first = input({ scope: 'once', maxUses: 1 });
        const created = await a.exceptions.create(first);
        expect(await a.exceptions.consume(created.id)).toBe(true); // terminal: 1/1 spent

        const collider = (): CreateExceptionInput =>
          input({
            ruleId: first.ruleId,
            valueFingerprint: first.valueFingerprint,
            keyVersion: first.keyVersion,
            scope: 'once',
            maxUses: 1,
          });

        // The first arrival supersedes the spent grant and takes the slot.
        const claimed = await a.exceptions.create(collider());
        // The second finds it occupied by a live grant, not freed.
        await expect(b.exceptions.create(collider())).rejects.toThrow(
          DuplicateActiveExceptionError,
        );

        // Read back through the other handle: one active grant, one supersede.
        expect((await b.exceptions.list()).map((e) => e.id)).toEqual([claimed.id]);
        expect(await b.exceptions.list({ includeTerminal: true })).toHaveLength(2);
      }));

    it('rejects a provider condition (no capture fact carries one yet)', async () => {
      await expect(repo.create(input({ conditions: { provider: 'anthropic' } }))).rejects.toThrow(
        /provider conditions are not supported/,
      );
    });
  });

  describe('getByIdPrefix', () => {
    it('matches an exact id and a unique prefix', async () => {
      const grant = await repo.create(input());

      expect((await repo.getByIdPrefix(grant.id))?.id).toBe(grant.id);
      expect((await repo.getByIdPrefix(grant.id.slice(0, 8)))?.id).toBe(grant.id);
    });

    it('returns undefined for an unknown or empty prefix', async () => {
      await repo.create(input());
      expect(await repo.getByIdPrefix('ffffffff')).toBeUndefined();
      expect(await repo.getByIdPrefix('')).toBeUndefined();
    });

    it('throws a tagged error for an ambiguous prefix', async () => {
      insertRawException('aaaa1111-0000-4000-8000-000000000000');
      insertRawException('aaaa2222-0000-4000-8000-000000000000');

      await expect(repo.getByIdPrefix('aaaa')).rejects.toThrow(AmbiguousExceptionIdError);
      await expect(repo.getByIdPrefix('aaaa')).rejects.toThrow(/ambiguous-exception-id/);
      expect((await repo.getByIdPrefix('aaaa1111'))?.id).toBe(
        'aaaa1111-0000-4000-8000-000000000000',
      );
    });

    it('matches LIKE metacharacters literally, never as wildcards', async () => {
      insertRawException('aaaa1111-0000-4000-8000-000000000000');
      insertRawException('aaaa2222-0000-4000-8000-000000000000');

      // Unescaped, '%' would match an arbitrary row (or trip the ambiguity
      // error) and '_aaa' would one-char-wildcard onto both rows.
      expect(await repo.getByIdPrefix('%')).toBeUndefined();
      expect(await repo.getByIdPrefix('_aaa')).toBeUndefined();
      expect(await repo.getByIdPrefix('\\aaaa')).toBeUndefined();
    });
  });

  describe('activeBundleEntries', () => {
    it('returns the evaluation subset of active grants under the given key version', async () => {
      const active = await repo.create(input({ keyVersion: 1, maxUses: 3 }));
      await repo.create(input({ keyVersion: 2 })); // rotated-away key
      const revoked = await repo.create(input({ keyVersion: 1 }));
      await repo.revoke(revoked.id, 'alice');

      const entries = await repo.activeBundleEntries(1);
      expect(entries).toEqual([
        {
          id: active.id,
          ruleId: active.ruleId,
          valueFingerprint: active.valueFingerprint,
          keyVersion: 1,
          capability: 'suppress',
          expiresAt: active.expiresAt,
          maxUses: 3,
          useCount: 0,
          conditions: null,
        },
      ]);
    });
  });

  /**
   * Rotation is invalidation — for suppression. `activeBundleEntries` is
   * `WHERE key_version = :keyVersion` and the hook asks it with the CURRENT
   * key, so a grant written under a rotated-away epoch stops riding the bundle.
   *
   * Reveal grants are deliberately EXEMPT, and the exemption reads like a bug
   * unless it is written down. `activeRevealGrant` takes the key version as an
   * ARGUMENT, and its caller passes the vault row's own — the triple the
   * pointer was minted under, not whatever is current now. So the very grant
   * the bundle has dropped still authorizes the reveal it was granted for.
   * That is correct: the row's fingerprint was never recomputed under the new
   * key, so refusing on the current key would refuse a grant that does enforce.
   *
   * Both halves are asserted of ONE grant, because the asymmetry is the point.
   * Split across two tests, each half reads like an oversight in the other.
   */
  describe('key-version scoping, and the reveal grant exempt from it', () => {
    const ROTATED_AWAY = 1;
    const CURRENT = 2;

    it('the bundle drops a rotated-away grant that activeRevealGrant still honours', async () => {
      const grant = await repo.create(
        input({ keyVersion: ROTATED_AWAY, capability: 'reveal_to_model' }),
      );

      // The hook builds its bundle under the current key: the grant is gone.
      expect(await repo.activeBundleEntries(CURRENT)).toEqual([]);
      // Its own epoch still carries it — the predicate SCOPES, it does not expire.
      expect((await repo.activeBundleEntries(ROTATED_AWAY)).map((e) => e.id)).toEqual([grant.id]);

      // The crossing asks with the vault row's own triple, and is answered.
      expect(
        await repo.activeRevealGrant(grant.ruleId, grant.valueFingerprint, ROTATED_AWAY),
      ).toEqual({ id: grant.id });
      // Asked under the current key it matches nothing, so this is scoping too
      // — an exemption from what the CURRENT key is, not from the key at all.
      expect(
        await repo.activeRevealGrant(grant.ruleId, grant.valueFingerprint, CURRENT),
      ).toBeNull();
    });

    it('a suppression grant never authorizes a reveal, even on its own key version', async () => {
      const grant = await repo.create(input({ capability: 'suppress' }));

      expect((await repo.activeBundleEntries(grant.keyVersion)).map((e) => e.id)).toEqual([
        grant.id,
      ]);
      expect(
        await repo.activeRevealGrant(grant.ruleId, grant.valueFingerprint, grant.keyVersion),
      ).toBeNull();
    });

    it('a conditioned reveal grant fails closed — the reveal path evaluates no conditions', async () => {
      const grant = await repo.create(
        input({ capability: 'reveal_to_model', conditions: { repo: 'acme/api' } }),
      );

      // It still rides the suppression bundle, which DOES evaluate conditions...
      expect((await repo.activeBundleEntries(grant.keyVersion)).map((e) => e.id)).toEqual([
        grant.id,
      ]);
      // ...but the reveal crossing, which ignores them, refuses rather than
      // honouring a narrowed grant as though it had been granted unconditionally.
      expect(
        await repo.activeRevealGrant(grant.ruleId, grant.valueFingerprint, grant.keyVersion),
      ).toBeNull();
    });
  });

  describe('blocked-detections ledger', () => {
    function rawBlockedCount(): number {
      return (db.prepare('SELECT count(*) AS c FROM blocked_detections').get() as { c: number }).c;
    }

    function insertRawBlocked(reference: string, blockedAt: number): void {
      db.prepare(
        `INSERT INTO blocked_detections (reference, rule_id, category, value_fingerprint, key_version, masked_value, session_id, repo, blocked_at)
         VALUES (:reference, 'r', 'secret', 'fp', 1, 'x***y', NULL, NULL, :blockedAt)`,
      ).run({ reference, blockedAt });
    }

    function rawReferences(): string[] {
      return (
        db.prepare('SELECT reference FROM blocked_detections').all() as { reference: string }[]
      )
        .map((r) => r.reference)
        .sort();
    }

    /**
     * Both windows are product decisions about how long evidence lives, and
     * both are reachable only by moving the clock. The VALUE pin and the
     * BOUNDARY case below are different guards and neither implies the other:
     * a boundary case derived from the constant follows it wherever it goes, so
     * it proves the window the code applies is the window the constant names
     * while saying nothing about what that number should be. Shrink the
     * constant with only the boundary case in place and every assertion moves
     * with it, green the whole way.
     */
    it('the ledger windows are 30 minutes and 24 hours', () => {
      expect(BLOCKED_DETECTIONS_TTL_MS).toBe(30 * 60 * 1000);
      expect(BLOCKED_DETECTIONS_RETENTION_MS).toBe(24 * 60 * 60 * 1000);
      // The read window has to be the narrower of the two, or the picker offers
      // rows the sweep may already have taken.
      expect(BLOCKED_DETECTIONS_TTL_MS).toBeLessThan(BLOCKED_DETECTIONS_RETENTION_MS);
    });

    // Both window EDGES — `blocked_at > :cutoff` for the read and
    // `blocked_at <= :cutoff` for the sweep — are pinned off the injected clock
    // in exceptions-clock.test.ts. What is left here is the pair of properties
    // that file does not reach: the constants' own values, and the fact that
    // only a write collects.

    it('the sweep runs on EVERY write, not on a read', async () => {
      const stale = blockedInput();
      await repo.recordBlocked(stale);
      clock += BLOCKED_DETECTIONS_RETENTION_MS;

      // Reading past the retention window hides the row without removing it:
      // nothing on the read path deletes.
      expect(await repo.recentBlocked(BLOCKED_DETECTIONS_RETENTION_MS * 2)).toHaveLength(1);
      expect(rawReferences()).toEqual([stale.reference]);

      // The next write is what collects it.
      const fresh = blockedInput();
      await repo.recordBlocked(fresh);
      expect(rawReferences()).toEqual([fresh.reference]);
    });

    it('round-trips recordBlocked → recentBlocked, newest-first with ISO blockedAt', async () => {
      const older = blockedInput();
      await repo.recordBlocked(older);
      const newer = blockedInput({ sessionId: null, repo: null });
      await repo.recordBlocked(newer);

      const recent = await repo.recentBlocked();
      expect(recent.map((e) => e.reference)).toEqual([newer.reference, older.reference]);
      expect(recent[1]).toEqual({ ...older, blockedAt: recent[1]?.blockedAt });
      expect(recent[0]?.sessionId).toBeNull();
      expect(recent[0]?.repo).toBeNull();
      expect(Date.parse(recent[0]?.blockedAt ?? '')).not.toBeNaN();
    });

    it('recordBlocked is idempotent per reference (best-effort hook write must not throw)', async () => {
      const entry = blockedInput();
      await repo.recordBlocked(entry);
      await expect(repo.recordBlocked({ ...entry, maskedValue: 'y***z' })).resolves.toBeUndefined();
      const recent = await repo.recentBlocked();
      expect(recent.filter((e) => e.reference === entry.reference)).toHaveLength(1);
    });

    it('excludes entries outside the window', async () => {
      const fresh = blockedInput();
      await repo.recordBlocked(fresh);
      // Inserted after the write so the sweep-on-write doesn't remove it.
      insertRawBlocked('stale', Date.now() - 31 * 60 * 1000);

      expect((await repo.recentBlocked()).map((e) => e.reference)).toEqual([fresh.reference]);
      // A wider window reaches further back.
      expect((await repo.recentBlocked(HOUR_MS)).map((e) => e.reference)).toEqual([
        fresh.reference,
        'stale',
      ]);
    });

    it('sweeps rows older than the 24-hour retention window on every write', async () => {
      insertRawBlocked('stale', Date.now() - 25 * HOUR_MS);
      insertRawBlocked('recent', Date.now() - 31 * 60 * 1000);
      expect(rawBlockedCount()).toBe(2);

      await repo.recordBlocked(blockedInput());
      expect(rawBlockedCount()).toBe(2); // stale deleted, recent + new kept
      // 'recent' is outside the default 30-minute TTL but still in storage —
      // reachable with a wider window (the dashboard's longer lookback filters).
      expect((await repo.recentBlocked()).map((e) => e.reference)).not.toContain('stale');
      expect((await repo.recentBlocked(HOUR_MS)).map((e) => e.reference)).not.toContain('stale');
    });
  });

  describe('sweepTerminal', () => {
    const DAY_MS = 24 * HOUR_MS;

    function backdateUpdatedAt(id: string, ms: number): void {
      db.prepare('UPDATE exceptions SET updated_at = :t WHERE id = :id').run({
        t: Date.now() - ms,
        id,
      });
    }

    it('removes only terminal rows past retention, never active ones', async () => {
      const activeOld = await repo.create(input());
      backdateUpdatedAt(activeOld.id, 100 * DAY_MS);

      const revokedOld = await repo.create(input());
      await repo.revoke(revokedOld.id, 'alice');
      backdateUpdatedAt(revokedOld.id, 100 * DAY_MS);

      const expiredOld = await repo.create(
        input({ expiresAt: new Date(Date.now() - DAY_MS).toISOString() }),
      );
      backdateUpdatedAt(expiredOld.id, 100 * DAY_MS);

      const exhaustedOld = await repo.create(input({ scope: 'once', maxUses: 1 }));
      await repo.consume(exhaustedOld.id);
      backdateUpdatedAt(exhaustedOld.id, 100 * DAY_MS);

      const revokedRecent = await repo.create(input());
      await repo.revoke(revokedRecent.id, 'alice');

      expect(await repo.sweepTerminal(90 * DAY_MS)).toBe(3);

      const remaining = await repo.list({ includeTerminal: true });
      expect(remaining.map((e) => e.id).sort()).toEqual([activeOld.id, revokedRecent.id].sort());
    });

    it('is a no-op when nothing is terminal and old', async () => {
      await repo.create(input());
      expect(await repo.sweepTerminal(90 * DAY_MS)).toBe(0);
      expect(await repo.list()).toHaveLength(1);
    });

    // The `updated_at < :cutoff` edge, and the grant that goes terminal by
    // EXPIRY alone, are pinned off the injected clock in
    // exceptions-clock.test.ts. The third way a grant goes terminal without
    // anyone revoking it — spending its budget — is only reachable here,
    // because it needs a consume rather than a clock move.
    it('sweeps a grant that went terminal by budget alone', async () => {
      const spent = await repo.create(input({ scope: 'once', maxUses: 1 }));
      expect(await repo.consume(spent.id)).toBe(true);
      // The control: equally old, never spent, and it must survive. Without it
      // a sweep that deletes every row past the cutoff passes this test.
      const permanent = await repo.create(input({ scope: 'permanent', expiresAt: null }));

      clock += 1;
      // Terminal by the budget alone — `revoked_at` is still null, which is the
      // case a sweep keyed only on revocation would leave behind forever.
      expect((await repo.getByIdPrefix(spent.id))?.revokedAt).toBeNull();

      expect(await repo.sweepTerminal(0)).toBe(1);
      // The exact surviving set, which is what says the sweep took the spent
      // grant and only it.
      expect((await repo.list({ includeTerminal: true })).map((e) => e.id)).toEqual([permanent.id]);
    });
  });
});
