import { describe, expect, it } from 'vitest';

import type { ScanLedgerEntry } from '../../src/repositories/scan-ledger.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-ledger-', { migrated: true });

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
    const db = store.open();
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
    const db = store.open();
    db.scanLedger.upsertEntries([entry('/repo/a.ts', { rulesetHash: 'ruleset-v1' })]);

    expect(db.scanLedger.entriesForRuleset('ruleset-v2').size).toBe(0);
    expect(db.scanLedger.entriesForRuleset('ruleset-v1').size).toBe(1);
    db.close();
  });

  it('lists every ledgered path whatever ruleset it was scanned under', () => {
    const db = store.open();
    db.scanLedger.upsertEntries([
      entry('/repo/a.ts', { rulesetHash: 'ruleset-v1' }),
      entry('/repo/b.ts', { rulesetHash: 'ruleset-v2' }),
    ]);

    expect(db.scanLedger.allPaths().sort()).toEqual(['/repo/a.ts', '/repo/b.ts']);
    expect([...db.scanLedger.entriesForRuleset('ruleset-v2').keys()]).toEqual(['/repo/b.ts']);
    db.close();
  });

  it('upserts on path: a re-scan overwrites mtime, hash, and ruleset', () => {
    const db = store.open();
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
    const db1 = store.open();
    db1.scanLedger.upsertEntries([entry('/repo/a.ts')]);
    db1.close();

    const db2 = store.open();
    expect(db2.scanLedger.entriesForRuleset('ruleset-v1').has('/repo/a.ts')).toBe(true);
    db2.close();
  });

  describe('the repository a file was in when it was read', () => {
    const WORK = 'github.com/acme/work';

    it('round-trips the key beside every ledgered path, and leaves allPaths as it was', () => {
      const db = store.open();
      db.scanLedger.upsertEntries([
        entry('/repo/a.ts', { scopeKey: WORK }),
        entry('/repo/b.ts', { rulesetHash: 'ruleset-v2' }),
      ]);

      // Whatever ruleset the row was written under: the sweep that reads this
      // looks at every ledgered path.
      expect(db.scanLedger.pathKeys()).toEqual(
        new Map<string, string | undefined>([
          ['/repo/a.ts', WORK],
          ['/repo/b.ts', undefined],
        ]),
      );
      expect(db.scanLedger.allPaths().sort()).toEqual(['/repo/a.ts', '/repo/b.ts']);
      db.close();
    });

    it('writes NULL for an entry with no key, and a re-read replaces the key it had', () => {
      const db = store.open();
      db.scanLedger.upsertEntries([entry('/repo/a.ts', { scopeKey: WORK })]);
      db.scanLedger.upsertEntries([entry('/repo/a.ts', { mtime: '2026-07-02T11:00:00.000Z' })]);

      // The row now describes the file as it was last read: in no repository
      // with a remote. Keeping the older key would vouch for what is no longer so.
      expect(db.scanLedger.pathKeys().get('/repo/a.ts')).toBeUndefined();
      const raw = store.openRaw();
      expect(raw.prepare('SELECT scope_key FROM scan_ledger').all()).toEqual([{ scope_key: null }]);
      db.close();
    });

    it('carries a key across reopen', () => {
      const db1 = store.open();
      db1.scanLedger.upsertEntries([entry('/repo/a.ts', { scopeKey: WORK })]);
      db1.close();

      const db2 = store.open();
      expect(db2.scanLedger.pathKeys().get('/repo/a.ts')).toBe(WORK);
      db2.close();
    });

    it("returns the recorded key with a ruleset's state, and none for a row without one", () => {
      const db = store.open();
      db.scanLedger.upsertEntries([
        entry('/repo/a.ts', { scopeKey: WORK }),
        entry('/repo/b.ts'),
        entry('/repo/c.ts', { rulesetHash: 'ruleset-v2', scopeKey: WORK }),
      ]);

      const state = db.scanLedger.entriesForRuleset('ruleset-v1');
      // The change-detection read the scan already makes carries the key, so a
      // scan can compare it with the key an unchanged file has now.
      expect(state.get('/repo/a.ts')).toEqual({
        mtime: '2026-07-02T10:00:00.000Z',
        contentHash: 'hash-of-/repo/a.ts',
        scopeKey: WORK,
      });
      expect(state.get('/repo/b.ts')?.scopeKey).toBeUndefined();
      expect(state.has('/repo/c.ts')).toBe(false);
      db.close();
    });

    it('lists nothing for an empty ledger', () => {
      const db = store.open();
      expect(db.scanLedger.pathKeys().size).toBe(0);
      db.close();
    });
  });

  describe('the directory of the repository a file was read in', () => {
    const WORK = 'github.com/acme/work';
    const WORK_ROOT = '/repo';
    const CLONE_ROOT = '/repo/clone';

    it("returns the recorded root with a ruleset's state, beside the key", () => {
      const db = store.open();
      db.scanLedger.upsertEntries([
        entry('/repo/a.ts', { scopeKey: WORK, scopeRoot: WORK_ROOT }),
        // A repository with no forge remote has a root and no key.
        entry('/repo/clone/b.ts', { scopeRoot: CLONE_ROOT }),
        entry('/repo/c.ts', { rulesetHash: 'ruleset-v2', scopeKey: WORK, scopeRoot: WORK_ROOT }),
      ]);

      const state = db.scanLedger.entriesForRuleset('ruleset-v1');
      expect(state.get('/repo/a.ts')).toEqual({
        mtime: '2026-07-02T10:00:00.000Z',
        contentHash: 'hash-of-/repo/a.ts',
        scopeKey: WORK,
        scopeRoot: WORK_ROOT,
      });
      expect(state.get('/repo/clone/b.ts')).toEqual({
        mtime: '2026-07-02T10:00:00.000Z',
        contentHash: 'hash-of-/repo/clone/b.ts',
        scopeRoot: CLONE_ROOT,
      });
      expect(state.has('/repo/c.ts')).toBe(false);
      db.close();
    });

    it('writes NULL for an entry with no root, and a re-read replaces the root it had', () => {
      const db = store.open();
      db.scanLedger.upsertEntries([entry('/repo/a.ts', { scopeKey: WORK, scopeRoot: WORK_ROOT })]);
      db.scanLedger.upsertEntries([entry('/repo/a.ts', { mtime: '2026-07-02T11:00:00.000Z' })]);

      // Written exactly as the key is: what the entry says is what the row holds.
      expect(db.scanLedger.entriesForRuleset('ruleset-v1').get('/repo/a.ts')?.scopeRoot).toBe(
        undefined,
      );
      const raw = store.openRaw();
      expect(raw.prepare('SELECT scope_key, scope_root FROM scan_ledger').all()).toEqual([
        { scope_key: null, scope_root: null },
      ]);
      db.close();
    });

    it('carries a root across reopen', () => {
      const db1 = store.open();
      db1.scanLedger.upsertEntries([entry('/repo/a.ts', { scopeRoot: WORK_ROOT })]);
      db1.close();

      const db2 = store.open();
      expect(db2.scanLedger.entriesForRuleset('ruleset-v1').get('/repo/a.ts')?.scopeRoot).toBe(
        WORK_ROOT,
      );
      db2.close();
    });

    it('leaves what pathKeys lists as it was: the key alone', () => {
      const db = store.open();
      db.scanLedger.upsertEntries([
        entry('/repo/a.ts', { scopeKey: WORK, scopeRoot: WORK_ROOT }),
        entry('/repo/clone/b.ts', { scopeRoot: CLONE_ROOT }),
      ]);

      expect(db.scanLedger.pathKeys()).toEqual(
        new Map<string, string | undefined>([
          ['/repo/a.ts', WORK],
          ['/repo/clone/b.ts', undefined],
        ]),
      );
      db.close();
    });
  });

  it('treats an empty upsert as a no-op', () => {
    const db = store.open();
    db.scanLedger.upsertEntries([]);
    expect(db.scanLedger.entriesForRuleset('ruleset-v1').size).toBe(0);
    db.close();
  });
});
