import { spawn } from 'node:child_process';
import { chmodSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { readStorePosture } from '../../src/attached/posture-snapshot';

const FIXTURE_DDL = `
CREATE TABLE installed_packs (
  id TEXT PRIMARY KEY, namespace TEXT NOT NULL, pack_id TEXT NOT NULL,
  version TEXT NOT NULL, name TEXT, rules_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1, policy_id TEXT,
  created_at INTEGER, updated_at INTEGER, UNIQUE (namespace, pack_id)
);
CREATE TABLE policies (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, target TEXT NOT NULL,
  action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, custom_keywords TEXT
);
CREATE TABLE audit_events (id TEXT PRIMARY KEY, event_type TEXT NOT NULL, started_at INTEGER);
CREATE TABLE inspection_definitions (id TEXT PRIMARY KEY);
CREATE TABLE inspection_findings (
  id TEXT PRIMARY KEY, audit_event_id TEXT NOT NULL, inspection_definition_id TEXT,
  first_detected_at INTEGER
);
PRAGMA user_version = 14;
`;

function makeFixtureDb(dir: string): string {
  const path = join(dir, 'aka.db');
  const db = new DatabaseSync(path);
  db.exec(FIXTURE_DDL);
  db.exec(`INSERT INTO installed_packs (id, namespace, pack_id, version, enabled, updated_at)
           VALUES ('1','aka','secrets','1.4.0',1,1779000000000), ('2','aka','pii','0.9.0',0,NULL)`);
  db.exec(`INSERT INTO policies (id, scope, target, action, enabled) VALUES
           ('p1','global','secrets','block',1), ('p2','global','pii','warn',0), ('p3','global','net','warn',1)`);
  db.exec(`INSERT INTO audit_events (id, event_type) VALUES ('e1','prompt'), ('e2','session')`);
  db.exec(`INSERT INTO inspection_findings (id, audit_event_id, first_detected_at) VALUES
           ('f1','e1',1700000000000), ('f2','e1',1779000000000), ('f3','e2',1650000000000)`);
  db.close();
  return path;
}

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aka-posture-snapshot-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('readStorePosture', () => {
  it('reads packs, policy counts, and findings aggregates from a real store', () => {
    const out = readStorePosture(makeFixtureDb(dir));
    expect(out.storePresent).toBe(true);
    expect(out.schemaVersion).toBe(14);
    expect(out.packs).toEqual([
      { packId: 'aka/pii', version: '0.9.0', enabled: false, updatedAt: null },
      { packId: 'aka/secrets', version: '1.4.0', enabled: true, updatedAt: '1779000000000' },
    ]);
    expect(out.policyCounts).toEqual({
      total: 3,
      disabled: 1,
      byAction: { warn: 2, redact: 0, block: 1, allow: 0, log: 0 },
    });
    // f3 hangs off a 'session' event — excluded by the capture-event-type filter
    expect(out.findingsTotal).toBe(2);
    expect(out.findingsFirstAt).toBe(1_700_000_000_000);
    expect(out.findingsLastAt).toBe(1_779_000_000_000);
  });

  it('missing db file → storePresent false with empty/zero readout', () => {
    const out = readStorePosture(join(dir, 'nope', 'aka.db'));
    expect(out).toEqual({
      storePresent: false,
      schemaVersion: null,
      findingsTotal: 0,
      findingsFirstAt: null,
      findingsLastAt: null,
      packs: [],
      policyCounts: {
        total: 0,
        disabled: 0,
        byAction: { warn: 0, redact: 0, block: 0, allow: 0, log: 0 },
      },
      // A genuinely missing file is a MEASUREMENT, not a read failure — this is
      // the wipe the channel exists to catch, so it must still be reported.
      readError: false,
    });
  });

  it('corrupt db file → storePresent false, never throws', () => {
    const path = join(dir, 'aka.db');
    writeFileSync(path, 'this is not a sqlite file at all, definitely');
    expect(readStorePosture(path).storePresent).toBe(false);
  });

  it('an unreadable but PRESENT store sets readError, unlike a missing one', () => {
    // The distinction the reporter gates on. Both readouts carry the same
    // zeroed literal; only readError says whether those zeros were measured.
    // Without it a healthy store that loses the SQLite lock race reports
    // "no store, no packs, no policies" and the backend scores it as a wipe.
    const path = join(dir, 'aka.db');
    writeFileSync(path, 'not a database');
    const unreadable = readStorePosture(path);
    expect(unreadable.readError).toBe(true);
    expect(unreadable.storePresent).toBe(false);

    const missing = readStorePosture(join(dir, 'gone', 'aka.db'));
    expect(missing.readError).toBe(false);
    expect(missing.storePresent).toBe(false);
  });

  // Root bypasses directory permission checks entirely, which would make this
  // assert the opposite of what it's testing.
  it.skipIf(process.getuid?.() === 0)(
    'a permission-denied parent directory is a read error, not a false "absent"',
    async () => {
      // existsSync (the old check) returns false for ANY failure to look, not
      // just absence — so a locked-down parent dir was indistinguishable from
      // a genuinely missing store and got reported as a measured wipe.
      const lockedDir = join(dir, 'locked');
      const path = join(lockedDir, 'aka.db');
      await mkdir(lockedDir);
      makeFixtureDb(lockedDir);
      chmodSync(lockedDir, 0o000);
      try {
        const out = readStorePosture(path);
        expect(out.readError).toBe(true);
        expect(out.storePresent).toBe(false);
      } finally {
        chmodSync(lockedDir, 0o700);
      }
    },
  );

  it('a PRESENT store with no aka tables is a measurement, not a read error', () => {
    // A valid SQLite file that opened cleanly and only lacks the aka schema —
    // a pre-migration store, or a wiped ~/.aka/data that something recreated
    // empty before the next SessionStart. That is "store present, not yet
    // migrated": measured, not failed.
    //
    // Classifying it as readError suppressed the report entirely, so a wipe
    // followed by any store recreation went silent until the backend's 72h
    // freshness grader tripped — losing the immediate signal in exactly the
    // sequence this channel exists to catch.
    const path = join(dir, 'aka.db');
    const db = new DatabaseSync(path);
    db.exec('CREATE TABLE unrelated (x TEXT); PRAGMA user_version = 0;');
    db.close();

    const readout = readStorePosture(path);
    expect(readout.readError).toBe(false);
    expect(readout.storePresent).toBe(true);
    expect(readout.findingsTotal).toBe(0);
    expect(readout.packs).toEqual([]);
    expect(readout.policyCounts.total).toBe(0);
  });

  it('a store missing only the findings tables still reports its REAL packs and policies', () => {
    // A device with 2 packs and 3 policies but no inspection_findings/
    // audit_events table yet (a store that lagged behind the migration that
    // added capture tracking) used to have its ALREADY-MEASURED packs and
    // policies discarded and replaced with fabricated zeros, because only
    // schemaVersion was hoisted out of the try block — reporting a real
    // device as if it had nothing installed at all.
    const path = join(dir, 'aka.db');
    const db = new DatabaseSync(path);
    db.exec(`
      CREATE TABLE installed_packs (
        id TEXT PRIMARY KEY, namespace TEXT NOT NULL, pack_id TEXT NOT NULL,
        version TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER
      );
      CREATE TABLE policies (
        id TEXT PRIMARY KEY, scope TEXT NOT NULL, target TEXT NOT NULL,
        action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
      );
      PRAGMA user_version = 9;
    `);
    db.exec(`INSERT INTO installed_packs (id, namespace, pack_id, version, enabled, updated_at)
             VALUES ('1','aka','secrets','1.4.0',1,1779000000000), ('2','aka','pii','0.9.0',0,NULL)`);
    db.exec(`INSERT INTO policies (id, scope, target, action, enabled) VALUES
             ('p1','global','secrets','block',1), ('p2','global','pii','warn',0), ('p3','global','net','warn',1)`);
    db.close();

    const readout = readStorePosture(path);
    expect(readout.readError).toBe(false);
    expect(readout.storePresent).toBe(true);
    expect(readout.schemaVersion).toBe(9);
    expect(readout.packs).toHaveLength(2);
    expect(readout.policyCounts.total).toBe(3);
    expect(readout.policyCounts.disabled).toBe(1);
    // Genuinely not measured — the tables don't exist yet.
    expect(readout.findingsTotal).toBe(0);
  });

  it('a store missing only the policies table still reports its REAL packs and findings', () => {
    // The mirror case: a device with a 3-finding baseline but no policies
    // table used to report findingsTotal: 0 — a false wipe alarm on a store
    // that never lost anything, because the aggregate scan runs AFTER the
    // policies query and never got the chance to populate findingsTotal
    // before the shared catch discarded everything already collected.
    const path = join(dir, 'aka.db');
    const db = new DatabaseSync(path);
    db.exec(`
      CREATE TABLE installed_packs (
        id TEXT PRIMARY KEY, namespace TEXT NOT NULL, pack_id TEXT NOT NULL,
        version TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER
      );
      CREATE TABLE audit_events (id TEXT PRIMARY KEY, event_type TEXT NOT NULL, started_at INTEGER);
      CREATE TABLE inspection_findings (
        id TEXT PRIMARY KEY, audit_event_id TEXT NOT NULL, first_detected_at INTEGER
      );
      PRAGMA user_version = 11;
    `);
    db.exec(`INSERT INTO installed_packs (id, namespace, pack_id, version, enabled, updated_at)
             VALUES ('1','aka','secrets','1.4.0',1,1779000000000)`);
    db.exec(`INSERT INTO audit_events (id, event_type) VALUES ('e1','prompt')`);
    db.exec(`INSERT INTO inspection_findings (id, audit_event_id, first_detected_at) VALUES
             ('f1','e1',1700000000000), ('f2','e1',1750000000000), ('f3','e1',1779000000000)`);
    db.close();

    const readout = readStorePosture(path);
    expect(readout.readError).toBe(false);
    expect(readout.storePresent).toBe(true);
    expect(readout.packs).toHaveLength(1);
    expect(readout.findingsTotal).toBe(3);
    expect(readout.findingsFirstAt).toBe(1_700_000_000_000);
    expect(readout.findingsLastAt).toBe(1_779_000_000_000);
    // Genuinely not measured — the table doesn't exist yet.
    expect(readout.policyCounts.total).toBe(0);
  });

  it('garbage bytes stay a read error even though they also fail at query time', () => {
    // Guards the discriminator itself. SQLite opens lazily: a garbage file
    // passes `new DatabaseSync(...)` and only throws on the first statement,
    // exactly like a missing table does. So splitting on the PHASE (open vs
    // query) would classify shredded bytes as an empty-but-healthy store and
    // report a fabricated storePresent:true. The split is on the error —
    // "no such table" alone means schema-absent.
    const path = join(dir, 'aka.db');
    writeFileSync(path, 'not a database');
    const readout = readStorePosture(path);
    expect(readout.readError).toBe(true);
    expect(readout.storePresent).toBe(false);
  });

  it('a policies row with an unknown action still counts in total, not in byAction', () => {
    const path = makeFixtureDb(dir);
    const db = new DatabaseSync(path);
    db.exec(
      `INSERT INTO policies (id, scope, target, action, enabled) VALUES ('px','global','x','explode',1)`,
    );
    db.close();
    const out = readStorePosture(path);
    expect(out.policyCounts.total).toBe(4);
    expect(Object.values(out.policyCounts.byAction).reduce((a, b) => a + b, 0)).toBe(3);
  });

  it('waits out a brief writer lock instead of reporting a healthy store absent', async () => {
    // The reader sets busy_timeout (matching the canonical opener's 2000ms);
    // without it the default of 0 turned any concurrent writer into an
    // immediate SQLITE_BUSY → emptyReadout() → storePresent:false for a
    // perfectly healthy store. The writer must be another PROCESS: in-process
    // the synchronous reader would block the only thread and nothing could
    // ever release the lock.
    const path = makeFixtureDb(dir);
    const sentinel = join(dir, 'lock-held');
    const script = `
      const { DatabaseSync } = require('node:sqlite');
      const { writeFileSync } = require('node:fs');
      const db = new DatabaseSync(${JSON.stringify(path)});
      db.exec('BEGIN EXCLUSIVE');
      writeFileSync(${JSON.stringify(sentinel)}, 'held');
      setTimeout(() => { db.exec('COMMIT'); db.close(); }, 400);
    `;
    const child = spawn(process.execPath, ['-e', script], { stdio: 'ignore' });
    try {
      await vi.waitFor(
        () => {
          if (!existsSync(sentinel)) throw new Error('writer lock not held yet');
        },
        { timeout: 5000, interval: 20 },
      );
      // The lock is provably held here, so against a 0 busy timeout this read
      // fails instantly; with the 2s timeout it rides out the 400ms hold.
      const out = readStorePosture(path);
      expect(out.storePresent).toBe(true);
      expect(out.findingsTotal).toBe(2);
    } finally {
      child.kill();
    }
  });

  it('never writes: the file mtime and size are unchanged by a read', () => {
    const path = makeFixtureDb(dir);
    const before = statSync(path);
    readStorePosture(path);
    const after = statSync(path);
    expect(after.size).toBe(before.size);
    expect(after.mtimeMs).toBe(before.mtimeMs);
  });
});
