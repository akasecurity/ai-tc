import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import type { ScanLedgerEntry } from '../../src/repositories/scan-ledger.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-ledger-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function entry(path: string, overrides: Partial<ScanLedgerEntry> = {}): ScanLedgerEntry {
  return {
    path,
    mtime: '2026-07-02T10:00:00.000Z',
    contentHash: `hash-of-${path}`,
    rulesetHash: 'ruleset-v1',
    ...overrides,
  };
}

describe('SqliteScanLedgerRepository (via LocalDatabase.scanLedger)', () => {
  it('round-trips entries keyed by path', () => {
    const db = openLocalDatabase(dir);
    db.scanLedger.upsertEntries([entry('/repo/a.ts'), entry('/repo/b.ts')]);

    const state = db.scanLedger.entriesForRuleset('ruleset-v1');
    expect(state.size).toBe(2);
    expect(state.get('/repo/a.ts')).toEqual({
      mtime: '2026-07-02T10:00:00.000Z',
      contentHash: 'hash-of-/repo/a.ts',
    });
    db.close();
  });

  it('excludes entries recorded under a different ruleset', () => {
    const db = openLocalDatabase(dir);
    db.scanLedger.upsertEntries([entry('/repo/a.ts', { rulesetHash: 'ruleset-v1' })]);

    expect(db.scanLedger.entriesForRuleset('ruleset-v2').size).toBe(0);
    expect(db.scanLedger.entriesForRuleset('ruleset-v1').size).toBe(1);
    db.close();
  });

  it('upserts on path: a re-scan overwrites mtime, hash, and ruleset', () => {
    const db = openLocalDatabase(dir);
    db.scanLedger.upsertEntries([entry('/repo/a.ts')]);
    db.scanLedger.upsertEntries([
      entry('/repo/a.ts', {
        mtime: '2026-07-02T11:00:00.000Z',
        contentHash: 'new-hash',
        rulesetHash: 'ruleset-v2',
      }),
    ]);

    expect(db.scanLedger.entriesForRuleset('ruleset-v1').size).toBe(0);
    expect(db.scanLedger.entriesForRuleset('ruleset-v2').get('/repo/a.ts')).toEqual({
      mtime: '2026-07-02T11:00:00.000Z',
      contentHash: 'new-hash',
    });
    db.close();
  });

  it('persists across reopen', () => {
    const db1 = openLocalDatabase(dir);
    db1.scanLedger.upsertEntries([entry('/repo/a.ts')]);
    db1.close();

    const db2 = openLocalDatabase(dir);
    expect(db2.scanLedger.entriesForRuleset('ruleset-v1').has('/repo/a.ts')).toBe(true);
    db2.close();
  });

  it('treats an empty upsert as a no-op', () => {
    const db = openLocalDatabase(dir);
    db.scanLedger.upsertEntries([]);
    expect(db.scanLedger.entriesForRuleset('ruleset-v1').size).toBe(0);
    db.close();
  });
});
