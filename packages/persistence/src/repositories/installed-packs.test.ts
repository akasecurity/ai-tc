import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { InstalledPackInput, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../database.ts';
import { DB_FILENAME } from '../paths.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-packs-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function rule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'x', flags: 'g' },
  };
}

function pack(packId: string, version: string, ruleIds: string[]): InstalledPackInput {
  return { namespace: 'aka', packId, version, name: packId, rules: ruleIds.map(rule) };
}

describe('SqliteInstalledPacksRepository (via LocalDatabase.installedPacks)', () => {
  it('records the inventory and rolls up detections / rules / active counts', async () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh']),
      pack('core-pii', '2.0.0', ['core-pii/email']),
    ]);
    expect(await db.installedPacks.counts()).toEqual({ packs: 2, rules: 3, enabled: 2 });
    db.close();
  });

  it('NEVER auto-updates an installed pack — a newer inventory only refreshes the available mirror', async () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    // A binary upgrade re-records with a newer version + more rules…
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);

    // …but the INSTALLED snapshot is untouched (updates are manual).
    const counts = await db.installedPacks.counts();
    expect(counts.packs).toBe(1);
    expect(counts.rules).toBe(1); // still the v2.0.0 single-rule snapshot

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const installed = raw
      .prepare(`SELECT version FROM installed_packs WHERE pack_id = 'secrets'`)
      .get() as { version: string };
    const available = raw
      .prepare(`SELECT version FROM available_packs WHERE pack_id = 'secrets'`)
      .get() as { version: string };
    raw.close();
    expect(installed.version).toBe('2.0.0');
    expect(available.version).toBe('2.5.0'); // the mirror tracks the binary
    db.close();
  });

  it('auto-installs a pack the user does not have yet (insert-only)', async () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    // A later release ships a brand-new pack alongside the existing one.
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws']),
      pack('core-phi', '1.0.0', ['core-phi/mrn']),
    ]);
    const counts = await db.installedPacks.counts();
    expect(counts.packs).toBe(2);
    expect(counts.enabled).toBe(2); // new packs install enabled (monitor default)
    db.close();
  });

  it('applyUpdate copies the available snapshot onto the installed pack, preserving user state', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.setEnabled('aka', 'secrets', false);
    db.installedPacks.setPolicy('aka', 'secrets', 'redact');
    // Binary upgrade: mirror moves ahead, installed stays.
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);

    expect(db.installedPacks.applyUpdate('aka', 'secrets')).toBe(true);

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const row = raw
      .prepare(
        `SELECT version, enabled, policy_id AS policyId, json_array_length(rules_json) AS rules
         FROM installed_packs WHERE pack_id = 'secrets'`,
      )
      .get() as { version: string; enabled: number; policyId: string; rules: number };
    raw.close();
    expect(row.version).toBe('2.5.0');
    expect(row.rules).toBe(2);
    expect(row.enabled).toBe(0); // user's disable survives the update
    expect(row.policyId).toBe('redact'); // and so does the policy assignment
    db.close();
  });

  it('applyUpdate returns false for an unknown pack or one with no available counterpart', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    expect(db.installedPacks.applyUpdate('aka', 'nope')).toBe(false);

    // A foreign installed row with no available mirror row: not updatable.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('x', 'aka', 'foreign', '1.0.0', 'Foreign', '[]', 1, 0, 0)`,
      )
      .run();
    raw.close();
    expect(db.installedPacks.applyUpdate('aka', 'foreign')).toBe(false);
    db.close();
  });

  it('prunes available rows for packs the binary no longer ships', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws']),
      pack('legacy', '1.0.0', ['legacy/a']),
    ]);
    db.installedPacks.recordInventory([pack('secrets', '2.1.0', ['secrets/aws'])]);

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const rows = raw.prepare(`SELECT pack_id AS packId FROM available_packs`).all() as {
      packId: string;
    }[];
    raw.close();
    expect(rows.map((r) => r.packId)).toEqual(['secrets']);
    db.close();
  });

  it('persists the inventory across reopen', async () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    const b = openLocalDatabase(dir);
    expect((await b.installedPacks.counts()).packs).toBe(1);
    b.close();
  });

  it('leaves updated_at untouched when re-recording an unchanged inventory (no churn)', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    // Stamp a sentinel updated_at; an unchanged re-record must NOT overwrite it
    // (the record runs on every gateway open, so a no-op here is what prevents
    // write amplification on the hook path).
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec('UPDATE installed_packs SET updated_at = 0');
    raw.close();

    const b = openLocalDatabase(dir);
    b.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]); // identical
    b.close();

    const check = new DatabaseSync(join(dir, DB_FILENAME));
    const row = check.prepare('SELECT updated_at AS t FROM installed_packs').get() as { t: number };
    check.close();
    expect(row.t).toBe(0); // guard held — no rewrite
  });

  it('surfaces a rules-only change (same version) as available without touching the install', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    // Same version, but the rule set grew (coverage added without a version
    // bump). The signature hashes rule content, so the mirror refreshes — but
    // the installed snapshot must stay at one rule until a manual update.
    const b = openLocalDatabase(dir);
    b.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh'])]);

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const installedRules = raw
      .prepare(`SELECT json_array_length(rules_json) AS n FROM installed_packs`)
      .get() as { n: number };
    const availableRules = raw
      .prepare(`SELECT json_array_length(rules_json) AS n FROM available_packs`)
      .get() as { n: number };
    raw.close();
    expect(installedRules.n).toBe(1);
    expect(availableRules.n).toBe(2);

    expect(b.installedPacks.applyUpdate('aka', 'secrets')).toBe(true);
    const after = new DatabaseSync(join(dir, DB_FILENAME));
    const n = (
      after.prepare(`SELECT json_array_length(rules_json) AS n FROM installed_packs`).get() as {
        n: number;
      }
    ).n;
    after.close();
    expect(n).toBe(2);
    b.close();
  });

  it('preserves a user-disabled detection across re-records and updates', async () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.installedPacks.setEnabled('aka', 'secrets', false);
    a.close();

    // A later session re-records the (now newer) inventory.
    const b = openLocalDatabase(dir);
    b.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    const counts = await b.installedPacks.counts();
    expect(counts.enabled).toBe(0); // stays disabled
    expect(counts.rules).toBe(1); // and the snapshot stays until a manual update
    b.close();
  });
});

describe('installedRuleset (scan-time snapshot)', () => {
  it('returns only rules from ENABLED packs, with the ladder counts', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh']),
      pack('core-pii', '2.0.0', ['core-pii/email']),
    ]);
    db.installedPacks.setEnabled('aka', 'core-pii', false);

    const snapshot = db.installedPacks.installedRuleset();
    expect(snapshot.installedPacks).toBe(2);
    expect(snapshot.enabledPacks).toBe(1);
    expect(snapshot.rules.map((r) => r.id).sort()).toEqual(['secrets/aws', 'secrets/gh']);
    expect(snapshot.invalidRules).toBe(0);
    db.close();
  });

  it('counts JSON-level corruption (malformed / non-array rules_json) as invalid', () => {
    // The display-tolerant parseRules silently returns [] for these — at scan
    // time that would masquerade as "no rules" and let the ladder authorize an
    // empty ruleset. installedRuleset must surface them as invalid instead.
    const db = openLocalDatabase(dir);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const insert = raw.prepare(
      `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
       VALUES (?, 'aka', ?, '1.0.0', ?, ?, 1, 0, 0)`,
    );
    insert.run('t1', 'truncated', 'Truncated', '[{"id":'); // malformed JSON
    insert.run('t2', 'object', 'Object', '{}'); // not an array
    raw.close();

    const snapshot = db.installedPacks.installedRuleset();
    expect(snapshot.enabledPacks).toBe(2);
    expect(snapshot.rules).toEqual([]);
    expect(snapshot.invalidRules).toBe(2); // one per unusable pack — ladder falls back
    db.close();
  });

  // Read the current available_packs mirror row for `secrets`.
  function mirrorSecrets(): { version: string; n: number } {
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const row = raw
      .prepare(
        `SELECT version, json_array_length(rules_json) AS n FROM available_packs WHERE pack_id = 'secrets'`,
      )
      .get() as { version: string; n: number };
    raw.close();
    return row;
  }

  it('never rewrites the mirror to an OLDER pack version (downgrade guard)', () => {
    const db = openLocalDatabase(dir);
    // A newer binary records v2.5.0 with two rules…
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    // …then an OLDER binary (version skew: plugin vs CLI) records v2.0.0.
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);

    // The mirror keeps the newer snapshot — otherwise the manual update flow
    // would present a protection downgrade as an "update".
    expect(mirrorSecrets()).toEqual({ version: '2.5.0', n: 2 });
    db.close();
  });

  it('at an EQUAL version, refuses a content regression but accepts a superset', () => {
    const db = openLocalDatabase(dir);
    // Mirror is 2.0.0 = [aws, gh, slack] (a newer binary shipped more rules at
    // the same manifest version — coverage growth).
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh', 'secrets/slack']),
    ]);
    // An older binary records the SAME version with FEWER rules. Same version
    // passes the version compare; the rule-content signature differs so it isn't
    // skipped — the superset check must still refuse the downgrade.
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    expect(mirrorSecrets()).toEqual({ version: '2.0.0', n: 3 });

    // A binary that ADDS coverage at the same version is a valid advance.
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh', 'secrets/slack', 'secrets/stripe']),
    ]);
    expect(mirrorSecrets()).toEqual({ version: '2.0.0', n: 4 });
    db.close();
  });

  it('fails CLOSED on an unparsable INCOMING version (refuses the rewrite)', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    // A malformed version ('v2.6.0') must not be trusted to overwrite the mirror
    // in either direction — the guard distrusts exactly the input it exists to catch.
    db.installedPacks.recordInventory([pack('secrets', 'v2.6.0', ['secrets/aws'])]);
    expect(mirrorSecrets()).toEqual({ version: '2.5.0', n: 2 });
    db.close();
  });

  it('lets a VALID incoming version heal an unparsable stored mirror row', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    // Corrupt the stored version directly.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec(`UPDATE available_packs SET version = 'garbage' WHERE pack_id = 'secrets'`);
    raw.close();
    // A well-formed incoming record replaces the bad row (stored-unparsable path).
    db.installedPacks.recordInventory([pack('secrets', '2.1.0', ['secrets/aws', 'secrets/gh'])]);
    expect(mirrorSecrets()).toEqual({ version: '2.1.0', n: 2 });
    db.close();
  });

  it('counts invalid rules instead of throwing on a corrupt row', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('y', 'aka', 'broken', '1.0.0', 'Broken', '[{"name":"not a rule"}]', 1, 0, 0)`,
      )
      .run();
    raw.close();

    const snapshot = db.installedPacks.installedRuleset();
    expect(snapshot.installedPacks).toBe(2);
    expect(snapshot.enabledPacks).toBe(2);
    expect(snapshot.rules.map((r) => r.id)).toEqual(['secrets/aws']);
    expect(snapshot.invalidRules).toBe(1);
    db.close();
  });
});

// ─── Write gate (migration 0005) ─────────────────────────────────────────────
// The manual-updates invariant is defended IN THE DATABASE: a column-scoped
// BEFORE UPDATE trigger on installed_packs silently ignores (RAISE(IGNORE))
// any UPDATE of version/name/rules_json unless the one-row _pack_write_gate is
// open — and only applyUpdate ever opens it, inside its own transaction. This
// is what stops ALREADY-SHIPPED legacy binaries (≤0.0.2-alpha.5 hooks run a
// compiled-in auto-sync upsert) from clobbering an applied update: app-level
// guards don't bind code that is already on disk. The gate MECHANICS live
// here; the frozen legacy-SQL replays live in legacy-writers.test.ts (the
// prevention-P1 class suite — extend it for any write-semantics change).

function installedRow(storeDir: string, packId: string): { version: string; rules: number } {
  const raw = new DatabaseSync(join(storeDir, DB_FILENAME));
  const row = raw
    .prepare(
      `SELECT version, json_array_length(rules_json) AS rules FROM installed_packs WHERE pack_id = ?`,
    )
    .get(packId) as { version: string; rules: number };
  raw.close();
  return row;
}

function gateState(storeDir: string): number {
  const raw = new DatabaseSync(join(storeDir, DB_FILENAME));
  const row = raw.prepare(`SELECT open FROM _pack_write_gate WHERE id = 1`).get() as {
    open: number;
  };
  raw.close();
  return row.open;
}

describe('installed_packs write gate (migration 0005)', () => {
  it('applyUpdate works end-to-end post-migration and leaves the gate closed', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    expect(db.installedPacks.applyUpdate('aka', 'secrets')).toBe(true);
    db.close();
    expect(installedRow(dir, 'secrets')).toEqual({ version: '2.5.0', rules: 2 });
    expect(gateState(dir)).toBe(0);
  });

  it('resets the gate when applyUpdate fails mid-transaction (rollback reverts the open)', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);

    // Sabotage: a second trigger that aborts the UPDATE only while the gate is
    // open — i.e. exactly when applyUpdate's inner write runs.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec(
      `CREATE TRIGGER test_sabotage BEFORE UPDATE OF version ON installed_packs
       WHEN (SELECT open FROM _pack_write_gate WHERE id = 1) = 1
       BEGIN SELECT RAISE(ABORT, 'sabotage'); END;`,
    );
    raw.close();
    try {
      expect(() => db.installedPacks.applyUpdate('aka', 'secrets')).toThrow(/sabotage/);
    } finally {
      const cleanup = new DatabaseSync(join(dir, DB_FILENAME));
      cleanup.exec('DROP TRIGGER test_sabotage');
      cleanup.close();
      db.close();
    }
    // ROLLBACK reverted both the row write AND the gate open — no dangling gate.
    expect(gateState(dir)).toBe(0);
    expect(installedRow(dir, 'secrets')).toEqual({ version: '2.0.0', rules: 1 });
  });

  it('setEnabled / setPolicy are untouched by the column-scoped trigger', async () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);

    expect(db.installedPacks.setEnabled('aka', 'secrets', false)).toBe(true);
    expect((await db.installedPacks.counts()).enabled).toBe(0);
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'redact')).toBe(true);
    db.close();

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    const row = raw
      .prepare(`SELECT enabled, policy_id AS policyId FROM installed_packs WHERE pack_id = ?`)
      .get('secrets') as { enabled: number; policyId: string };
    raw.close();
    expect(row).toEqual({ enabled: 0, policyId: 'redact' });
  });
});

describe('recordInventory recorded_by stamp', () => {
  function recordedBy(storeDir: string, packId: string): string | null {
    const raw = new DatabaseSync(join(storeDir, DB_FILENAME));
    const row = raw
      .prepare(`SELECT recorded_by AS recordedBy FROM available_packs WHERE pack_id = ?`)
      .get(packId) as { recordedBy: string | null };
    raw.close();
    return row.recordedBy;
  }

  it('stamps the recording binary on mirror rows it changes', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])], {
      recordedBy: 'plugin@0.0.2-alpha.7',
    });
    db.close();
    expect(recordedBy(dir, 'secrets')).toBe('plugin@0.0.2-alpha.7');
  });

  it('leaves recorded_by null for versionless writers, and unchanged on identical re-records', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();
    expect(recordedBy(dir, 'secrets')).toBeNull();

    // Identical content from a versioned binary: the signature gate (and the
    // change-detection WHERE, which excludes recorded_by) keep it a no-op —
    // recorded_by names who last CHANGED the mirror, not who last looked.
    const b = openLocalDatabase(dir);
    b.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])], {
      recordedBy: 'aka-cli@0.0.2-alpha.7',
    });
    b.close();
    expect(recordedBy(dir, 'secrets')).toBeNull();

    // Changed content DOES take the new stamp.
    const c = openLocalDatabase(dir);
    c.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])], {
      recordedBy: 'aka-cli@0.0.2-alpha.7',
    });
    c.close();
    expect(recordedBy(dir, 'secrets')).toBe('aka-cli@0.0.2-alpha.7');
  });
});

describe('newestRecordedBinary', () => {
  function stampRecordedBy(packId: string, recordedBy: string | null): void {
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw
      .prepare(`UPDATE available_packs SET recorded_by = ? WHERE pack_id = ?`)
      .run(recordedBy, packId);
    raw.close();
  }

  it('returns the newest recorded binary across mirror rows, skipping nulls and garbage', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws']),
      pack('core-pii', '2.0.0', ['core-pii/email']),
      pack('code-flaws', '1.0.0', ['code-flaws/x']),
    ]);
    stampRecordedBy('secrets', 'plugin@0.0.2-alpha.5');
    stampRecordedBy('core-pii', 'aka-cli@0.0.2-alpha.7');
    stampRecordedBy('code-flaws', 'not a stamp'); // malformed → skipped

    expect(db.installedPacks.newestRecordedBinary()).toEqual({
      binary: 'aka-cli',
      version: '0.0.2-alpha.7',
    });
    db.close();
  });

  it('returns null on a pre-hardening store (no recorded_by anywhere)', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    expect(db.installedPacks.newestRecordedBinary()).toBeNull();
    db.close();
  });

  it('skips a stamp whose version is unparseable, keeping the newer parseable one', () => {
    // Well-formed `<binary>@<version>` structure, but an unparseable version.
    // It compares *equal* to everything, so if it were kept as the running max a
    // genuinely-newer parseable stamp (which is not `> 0` against it) could never
    // displace it. It must be skipped outright, whatever the row order.
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([
      pack('secrets', '2.0.0', ['secrets/aws']),
      pack('core-pii', '2.0.0', ['core-pii/email']),
    ]);
    stampRecordedBy('secrets', 'aka-cli@garbage'); // parseable structure, unparseable version
    stampRecordedBy('core-pii', 'plugin@0.0.2-alpha.7');

    expect(db.installedPacks.newestRecordedBinary()).toEqual({
      binary: 'plugin',
      version: '0.0.2-alpha.7',
    });
    db.close();
  });

  it('returns null when every stamp has an unparseable version (never surfaces garbage)', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    stampRecordedBy('secrets', 'aka-cli@garbage');
    expect(db.installedPacks.newestRecordedBinary()).toBeNull();
    db.close();
  });
});
