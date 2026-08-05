import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../src/database.ts';
import { captureId } from '../src/ids.ts';
import { backupBeforeLegacyDrop } from '../src/migrations.ts';
import { descriptorProbe } from './helpers/descriptors.ts';
import { corruptStore } from './helpers/fault-injection.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-persistence-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const MASKED = 'AKIA…MPLE';

function event(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: 'hash',
    content: 'here is a key <redacted>',
    ...overrides,
  };
}

function finding(eventId: string, overrides: Partial<DetectedFinding> = {}): DetectedFinding {
  return {
    id: randomUUID(),
    eventId,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 14, end: 34 },
    maskedMatch: MASKED,
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

describe('openLocalDatabase — open / migrate / seed', () => {
  it('applies the schema and is safe to open repeatedly (idempotent migrations)', async () => {
    const d1 = openLocalDatabase(dir);
    // First open seeds the default policies into the tenant-free store.
    const seeded = await d1.policies.readPolicies();
    expect(seeded.length).toBeGreaterThan(0);
    d1.close();

    // Re-opening applies no migration twice and does not re-seed (the seed guard
    // is "table is empty"), so the policy count is unchanged — no error, no churn.
    const d2 = openLocalDatabase(dir);
    const reopened = await d2.policies.readPolicies();
    expect(reopened.length).toBe(seeded.length);
    d2.close();
  });

  it('seeds one enabled policy per default category', async () => {
    const db = openLocalDatabase(dir);
    const policies = await db.policies.readPolicies();
    db.close();

    const categories = policies
      .map((p) => ('category' in p.target ? p.target.category : null))
      .filter(Boolean);
    // Derived from DEFAULT_ACTIONS so a new category (e.g. 'config') extends
    // the seed without a hand-maintained duplicate here.
    expect(new Set(categories)).toEqual(new Set(Object.keys(DEFAULT_ACTIONS)));
    expect(policies.every((p) => p.enabled)).toBe(true);
  });

  it('writes the db file owner-only (0600) where POSIX modes apply', () => {
    const db = openLocalDatabase(dir);
    db.close();
    if (process.platform === 'win32') return;
    const mode = statSync(join(dir, 'aka.db')).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('writes the -wal/-shm sidecars owner-only (0600) while the store is open', () => {
    // The sidecars hold prompt/file content just like the main db, so they must
    // carry the same 0600 mode. They exist only while a WAL-mode handle is open
    // (a clean close checkpoints and removes them), so assert before closing.
    const db = openLocalDatabase(dir);
    const dbFile = join(dir, 'aka.db');
    try {
      if (process.platform === 'win32') return;
      // WAL mode creates exactly the -wal/-shm pair (no rollback -journal).
      for (const sidecar of [`${dbFile}-wal`, `${dbFile}-shm`]) {
        expect(existsSync(sidecar)).toBe(true);
        expect(statSync(sidecar).mode & 0o777).toBe(0o600);
      }
    } finally {
      db.close();
    }
  });

  it('re-tightens the db and its recreated -wal/-shm sidecars to 0600 on reopen (steady-state)', () => {
    // Every hook after the first init reopens an already-migrated store. The
    // sidecars are removed on close and recreated by the reopen's writes; SQLite
    // gives a new sidecar the main db's mode, so a store loosened out of band
    // must be re-tightened on open — not only at first creation.
    openLocalDatabase(dir).close();
    const file = join(dir, 'aka.db');
    if (process.platform !== 'win32') chmodSync(file, 0o644); // simulate a loosened store

    const db = openLocalDatabase(dir);
    try {
      if (process.platform === 'win32') return;
      expect(statSync(file).mode & 0o777).toBe(0o600);
      for (const sidecar of [`${file}-wal`, `${file}-shm`]) {
        expect(existsSync(sidecar)).toBe(true);
        expect(statSync(sidecar).mode & 0o777).toBe(0o600);
      }
    } finally {
      db.close();
    }
  });

  it('backs up and recreates an incompatible legacy tenant-bearing aka.db instead of silently failing writes', async () => {
    // Simulate an old (tenant-bearing) store this lineage can't migrate
    // forward: a `tenants` table + a tenant_id column, with a bumped user_version
    // so the applier would otherwise skip it entirely.
    const file = join(dir, 'aka.db');
    const legacy = new DatabaseSync(file);
    legacy.exec('CREATE TABLE tenants (id TEXT PRIMARY KEY)');
    legacy.exec('CREATE TABLE events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)');
    legacy.exec('PRAGMA user_version = 10');
    legacy.close();

    // Opening detects the foreign lineage, backs it up, and starts fresh — so a
    // write now succeeds (the old schema would have thrown NOT NULL tenant_id,
    // swallowed fail-open).
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    expect(await db.findings.recentFindings()).toHaveLength(1);
    db.close();

    // The old store is preserved (recoverable), not destroyed.
    const backups = readdirSync(dir).filter((f) => f.includes('.legacy.'));
    expect(backups).toHaveLength(1);
    // The backup is a full copy of the prompt corpus, so it must carry the same
    // 0600 as the live store — the pre-tightened legacy file was 0644.
    const [backupName] = backups;
    if (process.platform !== 'win32' && backupName !== undefined) {
      expect(statSync(join(dir, backupName)).mode & 0o777).toBe(0o600);
    }
  });

  it('preserves committed WAL frames in the legacy backup when no close checkpoint runs', (ctx) => {
    // Regression: the legacy backup used to rename the main file aside and delete
    // the -wal/-shm sidecars. SQLite checkpoints only when the LAST connection
    // closes, so with a concurrent opener holding the store — the documented
    // multi-process model — no close-time checkpoint runs at all and committed
    // frames sit only in the -wal, which the delete then destroyed. The
    // "recoverable" backup silently lost the store's newest writes. The snapshot
    // now goes through VACUUM INTO, which folds committed WAL frames in without
    // needing a checkpoint.
    if (process.platform === 'win32') {
      // The reproduction keeps a second connection open across the backup, and
      // clearing an open store file is a sharing violation on Windows — a
      // separate platform limitation, not the data loss this guards.
      ctx.skip('a second open connection blocks clearing the store file on Windows');
      return;
    }

    const file = join(dir, 'aka.db');

    // A tenant-bearing (foreign-lineage) store in WAL mode. autocheckpoint = 0
    // plus a never-closed writer keep every write — the schema included — stranded
    // in the -wal, never folded into the main file.
    const writer = new DatabaseSync(file);
    writer.exec('PRAGMA journal_mode = WAL');
    writer.exec('PRAGMA wal_autocheckpoint = 0');
    writer.exec('CREATE TABLE tenants (id TEXT PRIMARY KEY)');
    writer.exec('CREATE TABLE events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)');
    writer.exec('PRAGMA user_version = 10');
    writer.exec("INSERT INTO tenants (id) VALUES ('wal-only-tenant')");
    writer.exec("INSERT INTO events (id, tenant_id) VALUES ('e1', 'wal-only-tenant')");

    try {
      // Opening detects the foreign lineage and backs the store up while the
      // writer still holds the un-checkpointed WAL.
      openLocalDatabase(dir).close();
    } finally {
      writer.close();
    }

    const backups = readdirSync(dir).filter((f) => f.includes('.legacy.'));
    expect(backups).toHaveLength(1);
    // The snapshot is published by renaming a `.partial` into place, so a
    // completed backup leaves no partial file beside it.
    expect(readdirSync(dir).filter((f) => f.endsWith('.partial'))).toEqual([]);
    const [backupName] = backups;
    const backup = new DatabaseSync(join(dir, backupName ?? ''));
    // The WAL-only rows survived into the backup — a bare rename + sidecar
    // delete would have dropped them (the rows, and even the tables themselves,
    // lived only in the -wal that the delete destroyed). Both tables are
    // checked: the whole snapshot has to survive, not one table of it.
    const tenants = backup.prepare('SELECT id FROM tenants').all();
    const events = backup.prepare('SELECT id, tenant_id FROM events').all();
    backup.close();
    expect(tenants).toEqual([{ id: 'wal-only-tenant' }]);
    expect(events).toEqual([{ id: 'e1', tenant_id: 'wal-only-tenant' }]);
  });

  it('still resets a legacy store the snapshot cannot copy, keeping the original intact', async () => {
    // A corrupt page fails VACUUM INTO but leaves page 1 readable, so the
    // foreign-lineage probe still fires: the store must be reset or every write
    // dies on NOT NULL tenant_id, swallowed fail-open. A snapshot is impossible
    // here, so the whole store is moved aside instead — the reset still happens,
    // and the damaged original is preserved rather than destroyed.
    //
    // The fixture stays at two tables and one row deliberately: the schema alone
    // already spans the several pages corruptStore('page') needs, and this store
    // is in rollback-journal mode, where a loop of per-row commits is a loop of
    // fsyncs — slow enough on Windows CI to reach the per-test timeout by itself.
    const file = join(dir, 'aka.db');
    const legacy = new DatabaseSync(file);
    legacy.exec('CREATE TABLE tenants (id TEXT PRIMARY KEY)');
    legacy.exec('CREATE TABLE events (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)');
    legacy.exec('PRAGMA user_version = 10');
    legacy.exec("INSERT INTO tenants (id) VALUES ('doomed-tenant')");
    legacy.close();
    const beforeSize = statSync(file).size;
    corruptStore(file, 'page');

    // The reset completes: the fresh store takes a write the legacy schema
    // would have rejected.
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    expect(await db.findings.recentFindings()).toHaveLength(1);
    db.close();

    const backups = readdirSync(dir).filter((f) => f.includes('.legacy.'));
    expect(backups).toHaveLength(1);
    // Nothing partial is left to mistake for a backup.
    expect(readdirSync(dir).filter((f) => f.endsWith('.partial'))).toEqual([]);
    // The moved-aside file is the damaged original, whole — not a truncated or
    // re-created one. NOT byte-for-byte: `PRAGMA journal_mode = WAL` runs on the
    // open before the copy fails and rewrites the header (4 bytes, the file
    // format versions among them). So pin the two properties that do hold — the
    // full length, and that the damage is still in it.
    const moved = join(dir, backups[0] ?? '');
    expect(statSync(moved).size).toBe(beforeSize);
    const check = new DatabaseSync(moved);
    const integrity = check.prepare('PRAGMA integrity_check').get() as { integrity_check: string };
    check.close();
    expect(integrity.integrity_check).not.toBe('ok');
  });

  it('writes the pre-drop VACUUM INTO backup owner-only (0600), not the umask default', () => {
    // The legacy events/findings drop snapshots the whole store via VACUUM INTO,
    // which creates a brand-new file at the process umask (typically 0644). That
    // backup is a full copy of the prompt corpus, so it must be tightened to the
    // store's own 0600.
    const file = join(dir, 'aka.db');
    const raw = new DatabaseSync(file);
    raw.exec('PRAGMA journal_mode = WAL');
    raw.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
    raw.exec("INSERT INTO t (v) VALUES ('prompt corpus')");
    if (process.platform !== 'win32') chmodSync(file, 0o600); // the live store is already tightened

    const backup = backupBeforeLegacyDrop(raw, file);
    raw.close();

    expect(existsSync(backup)).toBe(true);
    if (process.platform === 'win32') return;
    expect(statSync(backup).mode & 0o777).toBe(0o600);
  });
});

describe('recordCapture', () => {
  it('persists one event + N findings exactly as given (already masked)', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);

    const findings = await db.findings.recentFindings();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.maskedMatch).toBe(MASKED);
    expect(findings[0]?.actionTaken).toBe('block');
    expect(findings[0]?.occurredAt).toBe(ev.occurredAt);
    db.close();
  });

  it('dedupes a finding repeated across surfaces within one session', async () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    // Same value flagged on the prompt, then again when written to a file — one
    // logical action across two surfaces, sharing a session id. Distinct
    // contentHash per surface (real prompt text vs. a real file diff never
    // hash the same) so each capture gets its own content-addressed audit
    // event — the dedup under test is the session-scoped one, not a
    // coincidental collapse onto a single event.
    const prompt = event({ kind: 'prompt', metadata: { sessionId }, contentHash: 'hash-prompt' });
    const write = event({
      kind: 'code_change',
      metadata: { sessionId },
      contentHash: 'hash-write',
    });
    db.recordCapture(prompt, [
      finding(prompt.id, { ruleId: 'core-pii/email', maskedMatch: 'j*@example.com' }),
      finding(prompt.id, { ruleId: 'core-pii/ssn', maskedMatch: '1******9' }),
    ]);
    db.recordCapture(write, [
      finding(write.id, { ruleId: 'core-pii/email', maskedMatch: 'j*@example.com' }),
      finding(write.id, { ruleId: 'core-pii/ssn', maskedMatch: '1******9' }),
    ]);

    // Two distinct (rule, value) findings — not four — and both still link to
    // the first surface that recorded them (the prompt's own content-addressed
    // audit event, not the write's) since the write's repeats were dropped.
    const findings = await db.findings.recentFindings();
    expect(findings).toHaveLength(2);
    const promptAuditEventId = captureId(sessionId, 'hash-prompt');
    expect(findings.every((f) => f.eventId === promptAuditEventId)).toBe(true);
    expect(new Set(findings.map((f) => f.ruleId))).toEqual(
      new Set(['core-pii/email', 'core-pii/ssn']),
    );
    db.close();
  });

  it('keeps distinct values, and the same value in a different session', async () => {
    const db = openLocalDatabase(dir);
    const s1 = randomUUID();
    const s2 = randomUUID();
    // Two different emails in one session → both kept (different masked value).
    const e1 = event({ metadata: { sessionId: s1 } });
    db.recordCapture(e1, [
      finding(e1.id, { ruleId: 'core-pii/email', maskedMatch: 'a*@example.com' }),
      finding(e1.id, { ruleId: 'core-pii/email', maskedMatch: 'b*@example.com' }),
    ]);
    // The same value as e1, but a different session → kept (dedup is per session).
    const e2 = event({ metadata: { sessionId: s2 } });
    db.recordCapture(e2, [
      finding(e2.id, { ruleId: 'core-pii/email', maskedMatch: 'a*@example.com' }),
    ]);

    expect(await db.findings.recentFindings()).toHaveLength(3);
    db.close();
  });

  it('is fail-open: a duplicate event id is swallowed, never thrown', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    // Same id again → PK violation inside the txn → rolled back, not thrown.
    expect(() => {
      db.recordCapture(ev, [finding(ev.id)]);
    }).not.toThrow();
    expect(await db.findings.recentFindings()).toHaveLength(1);
    db.close();
  });
});

describe('read surfaces', () => {
  it('healthSummary counts by action and severity and reports full coverage on a fresh store', async () => {
    const db = openLocalDatabase(dir);
    const e1 = event();
    const e2 = event();
    db.recordCapture(e1, [finding(e1.id, { actionTaken: 'block', severity: 'critical' })]);
    // A distinct ruleId (not just a distinct severity): severity/category now
    // live on the shared inspection_definitions row for a ruleId (mirroring
    // the detection engine, where a rule's severity is fixed — see
    // packages/detections/src/engine.ts), so two DIFFERENT severities can only
    // come from two DIFFERENT rules, never from the same rule firing twice.
    db.recordCapture(e2, [
      finding(e2.id, {
        ruleId: 'core-pii/email',
        category: 'pii',
        actionTaken: 'warn',
        severity: 'low',
      }),
    ]);

    const health = await db.findings.healthSummary();
    expect(health.findings).toBe(2);
    expect(health.byAction.block).toBe(1);
    expect(health.byAction.warn).toBe(1);
    // Whole-store per-severity tally that powers the status bar; sums to findings.
    expect(health.bySeverity).toEqual({ critical: 1, high: 0, medium: 0, low: 1 });
    expect(health.coverage).toBe(1);
    db.close();
  });

  it('activityByDay returns a continuous window with today populated', async () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id, { actionTaken: 'block' })]);

    const days = await db.findings.activityByDay(7);
    expect(days).toHaveLength(7);
    const today = new Date().toISOString().slice(0, 10);
    const todayBucket = days.find((d) => d.day === today);
    expect(todayBucket?.total).toBe(1);
    expect(todayBucket?.blocked).toBe(1);
    db.close();
  });
});

describe('transaction', () => {
  it('commits every write inside fn atomically', async () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'warn');
    await db.transaction(() => {
      db.policies.upsertCategoryAction('secret', 'block');
      db.policies.upsertCategoryAction('pii', 'block');
    });
    expect(db.policies.getCategoryAction('secret')).toBe('block');
    expect(db.policies.getCategoryAction('pii')).toBe('block');
    db.close();
  });

  it('rolls back every write inside fn on throw', async () => {
    const db = openLocalDatabase(dir);
    db.policies.upsertCategoryAction('secret', 'warn');
    await expect(
      db.transaction(() => {
        db.policies.upsertCategoryAction('secret', 'block');
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    db.close();
  });

  it('rolls back a nested exceptions.create() collision-retry when the outer fn throws', async () => {
    const db = openLocalDatabase(dir);
    const grant = {
      ruleId: 'aws-access-key-id',
      category: 'secret' as const,
      valueFingerprint: 'a'.repeat(64),
      keyVersion: 1,
      maskedValue: 'AKIA******Q',
      scope: 'once' as const,
      expiresAt: null,
      maxUses: 1,
      justification: 'test grant',
      conditions: null,
      createdBy: 'alice',
      createdVia: 'cli-approve' as const,
    };
    const created = await db.exceptions.create(grant);
    expect(await db.exceptions.consume(created.id)).toBe(true);

    await expect(
      db.transaction(async () => {
        await db.exceptions.create(grant);
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');

    const all = await db.exceptions.list({ includeTerminal: true });
    expect(all.map((e) => e.id)).toEqual([created.id]);
    expect(all[0]?.revokedAt).toBeNull();
    expect(all[0]?.useCount).toBe(1);
    db.close();
  });
});

describe('a failed open leaves no handle behind', () => {
  // SQLite does not read the file until a statement runs, so a store that is not
  // a database opens cleanly and fails on the first PRAGMA — with the OS handle
  // already ours. Leaking it keeps the file locked for the life of the process
  // on Windows, and the dashboard server memoizes its handle only on success, so
  // a corrupt store would leak one more on every attempt.
  //
  // The proof is in two parts, and neither is platform-split any more.
  //
  // On POSIX the leak is COUNTED: `descriptorProbe` reads this process's
  // descriptor table around a synchronous window, so an escaped handle is a
  // number here rather than an inference. That is what stops the guard being
  // Windows-only — an unlink on POSIX succeeds whether or not a handle is open,
  // so the removal below proves nothing on this leg and never did.
  //
  // On Windows the removal in `afterEach` is still the assertion: it FAILS with
  // EPERM while a handle is open, and there is no `/dev/fd` to count instead, so
  // the probe reports itself unusable and the counting cases skip with a reason.
  //
  // Each fault below reaches a DIFFERENT guard, and they are kept apart on
  // purpose: a corrupt store fails at the first PRAGMA, inside `openWithPragmas`
  // and its own catch, while a dropped table fails later in a repository
  // constructor and is caught only by the one try around the whole sequence.
  // Measured by removing each guard in turn: with the pragma guard gone the
  // corrupt case leaks 5 and the dropped-table case leaks 0; with the sequence
  // guard gone those numbers swap to 0 and 11. One fixture would have pinned one
  // guard and left the other free to regress.
  const ATTEMPTS = 5;

  function corruptTheStore(): string {
    const file = join(dir, 'aka.db');
    openLocalDatabase(dir).close(); // a real store first, so this is damage not absence
    for (const sidecar of ['aka.db-wal', 'aka.db-shm']) {
      rmSync(join(dir, sidecar), { force: true });
    }
    writeFileSync(file, 'this is not a SQLite database at all\n');
    return file;
  }

  // Several repositories `db.prepare(...)` in their constructor, which runs after
  // migrations have reported success. Dropping a table from an already-migrated
  // store reproduces that: the ledger still says applied, so the next open skips
  // the applier and goes straight to the constructors.
  function dropAMigratedTable(): void {
    openLocalDatabase(dir).close();
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    try {
      raw.exec('DROP TABLE installed_packs');
    } finally {
      raw.close();
    }
  }

  it('throws rather than returning a half-open store', () => {
    corruptTheStore();
    expect(() => openLocalDatabase(dir)).toThrow();
  });

  it('stays throwing across repeated attempts, without accumulating handles', () => {
    // The shape the dashboard produces: the caller returns an error to the user,
    // the user retries, and each retry opens again. Any handle kept here is one
    // per attempt.
    corruptTheStore();
    for (let i = 0; i < ATTEMPTS; i += 1) {
      expect(() => openLocalDatabase(dir)).toThrow();
    }
    // afterEach removes the tree — on Windows that is the assertion.
  });

  it('leaks no descriptor when the first PRAGMA throws', (ctx) => {
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');
    corruptTheStore();

    // Counted inside the window and asserted outside it, so the window holds
    // nothing but the opens — and so a run where nothing threw cannot pass as
    // a run that leaked nothing.
    let threw = 0;
    const leaked = probe.leakedBy(() => {
      for (let i = 0; i < ATTEMPTS; i += 1) {
        try {
          openLocalDatabase(dir);
        } catch {
          threw += 1;
        }
      }
    });

    expect(threw).toBe(ATTEMPTS);
    expect(leaked).toBe(0);
  });

  it('closes the handle when a REPOSITORY CONSTRUCTOR throws, not just the open', () => {
    // The real-world shape this stands in for: a store written by a NEWER binary
    // leaves `user_version` ahead, so the applier skips and the constructors'
    // prepares meet columns that are not there. This region sat outside the
    // guard until the whole sequence was brought under one try.
    dropAMigratedTable();

    for (let i = 0; i < ATTEMPTS; i += 1) {
      expect(() => openLocalDatabase(dir)).toThrow(/no such table/);
    }
    // Measured on macOS while this was unguarded: five attempts leaked twelve
    // descriptors. afterEach is what catches it on Windows.
  });

  it('leaks no descriptor when a repository constructor throws', (ctx) => {
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');
    dropAMigratedTable();

    let threw = 0;
    const leaked = probe.leakedBy(() => {
      for (let i = 0; i < ATTEMPTS; i += 1) {
        try {
          openLocalDatabase(dir);
        } catch {
          threw += 1;
        }
      }
    });

    expect(threw).toBe(ATTEMPTS);
    expect(leaked).toBe(0);
  });
});

describe('store hygiene', () => {
  it('does not write the WAL/SHM secret to a separate plaintext copy', () => {
    const db = openLocalDatabase(dir);
    const ev = event();
    db.recordCapture(ev, [finding(ev.id)]);
    db.close();

    // inspection_findings holds only the masked value handed in — never a raw one.
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    const masked = raw.prepare('SELECT masked_match FROM inspection_findings').all() as {
      masked_match: string;
    }[];
    raw.close();
    expect(masked).toEqual([{ masked_match: MASKED }]);
  });
});
