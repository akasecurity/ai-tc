import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { InstalledPackInput, Rule } from '@aka/schema';
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
  it('records the inventory and rolls up detections / rules / active counts', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.upsertPacks([
      pack('secrets', '2.0.0', ['secrets/aws', 'secrets/gh']),
      pack('core-pii', '2.0.0', ['core-pii/email']),
    ]);
    expect(db.installedPacks.counts()).toEqual({ packs: 2, rules: 3, enabled: 2 });
    db.close();
  });

  it('is idempotent on (namespace, packId) and refreshes version + rule snapshot', () => {
    const db = openLocalDatabase(dir);
    db.installedPacks.upsertPacks([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.upsertPacks([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);

    const counts = db.installedPacks.counts();
    expect(counts.packs).toBe(1); // upserted, not duplicated
    expect(counts.rules).toBe(2); // snapshot refreshed
    db.close();
  });

  it('persists the inventory across reopen', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.upsertPacks([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    const b = openLocalDatabase(dir);
    expect(b.installedPacks.counts().packs).toBe(1);
    b.close();
  });

  it('leaves updated_at untouched when re-recording an unchanged pack (no churn)', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.upsertPacks([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    // Stamp a sentinel updated_at; an unchanged re-record must NOT overwrite it
    // (the upsert runs on every gateway open, so a no-op here is what prevents
    // write amplification on the hook path).
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec('UPDATE installed_packs SET updated_at = 0');
    raw.close();

    const b = openLocalDatabase(dir);
    b.installedPacks.upsertPacks([pack('secrets', '2.0.0', ['secrets/aws'])]); // identical
    b.close();

    const check = new DatabaseSync(join(dir, DB_FILENAME));
    const row = check.prepare('SELECT updated_at AS t FROM installed_packs').get() as { t: number };
    check.close();
    expect(row.t).toBe(0); // guard held — no rewrite
  });

  it('preserves a user-disabled detection when the inventory is re-recorded', () => {
    const a = openLocalDatabase(dir);
    a.installedPacks.upsertPacks([pack('secrets', '2.0.0', ['secrets/aws'])]);
    a.close();

    // No toggle API yet — simulate the user disabling the detection directly.
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
    raw.exec('UPDATE installed_packs SET enabled = 0');
    raw.close();

    // A later session re-records the (now newer) inventory.
    const b = openLocalDatabase(dir);
    b.installedPacks.upsertPacks([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    const counts = b.installedPacks.counts();
    expect(counts.enabled).toBe(0); // stays disabled
    expect(counts.rules).toBe(2); // but version/rules still refresh
    b.close();
  });
});
