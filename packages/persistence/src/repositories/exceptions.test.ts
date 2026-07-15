import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../migrations.ts';
import type { BlockedDetectionInput, CreateExceptionInput } from './exceptions.ts';
import {
  AmbiguousExceptionIdError,
  DuplicateActiveExceptionError,
  SqliteExceptionsRepository,
} from './exceptions.ts';

let db: DatabaseSync;
let repo: SqliteExceptionsRepository;
let fingerprintSeq = 0;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  applyMigrations(db);
  repo = new SqliteExceptionsRepository(db);
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
    expiresAt: new Date(Date.now() + HOUR_MS).toISOString(),
    maxUses: null,
    justification: 'temp deploy creds, rotating after infra apply',
    conditions: null,
    createdBy: 'alice',
    createdVia: 'cli-approve',
    ...overrides,
  };
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
      // Same terminal-collider setup as the budget-exhausted supersede test
      // above: a maxUses:1 grant, consumed once, occupies the partial-index
      // slot as a TERMINAL (not active) row.
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

      // Drive an outer transaction directly on the same handle the repo is
      // bound to — the same BEGIN/COMMIT/ROLLBACK boundary db.transaction()
      // opens on a LocalDatabase.
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

      // The outer rollback must undo BOTH the collision-retry's supersede
      // UPDATE and its retry INSERT — createSync detected db.isTransaction
      // and skipped its own BEGIN/COMMIT, so only the outer boundary applies.
      const all = await repo.list({ includeTerminal: true });
      expect(all.map((e) => e.id)).toEqual([created.id]);
      expect(all[0]?.revokedAt).toBeNull();
    });

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
          expiresAt: active.expiresAt,
          maxUses: 3,
          useCount: 0,
          conditions: null,
        },
      ]);
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
  });
});
