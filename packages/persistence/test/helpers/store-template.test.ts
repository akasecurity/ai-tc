/**
 * The repo-root `test/helpers/store-template.ts`, driven from the package whose
 * store it templates.
 *
 * Two things have to hold, and they fail differently. The template must be
 * built ONCE — a rebuild per seed would satisfy every equivalence assertion
 * below while saving nothing, which is the whole point of the helper. And a
 * seeded store must be indistinguishable from one `openLocalDatabase` migrated
 * itself, because the suites that copy it read it as if it were: a template
 * missing a table, an index or a ledger row would not fail here, it would fail
 * somewhere else, as an assertion about the repository under test.
 *
 * Every tree below comes from the store harness rather than a `mkdtempSync` of
 * its own — `harness-adoption.test.ts` allows no exception for a suite that
 * opens a store, and this one does. `createTempStore` is the shape that fits:
 * the seeding cases need a data dir with NO store in it yet, which is exactly
 * what an unseeded temp store is.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { createStoreTemplate } from '../../../../test/helpers/store-template.ts';
import { openLocalDatabase } from '../../src/database.ts';
import { errorFrom } from './errors.ts';
import { migratedStore } from './migrated-store.ts';
import { createTempStore, useTempStore } from './temp-store.ts';

/** Run `fn` against an unseeded temp store, then tear it down. */
function withPlainStore<T>(fn: (store: ReturnType<typeof createTempStore>) => T): T {
  const store = createTempStore('aka-tpl-');
  try {
    return fn(store);
  } finally {
    store.destroy();
  }
}

/** Every user object the store carries, as a stable, comparable list. */
function schemaOf(file: string): string[] {
  const db = new DatabaseSync(file);
  try {
    return (
      db
        .prepare(
          "SELECT type, name, COALESCE(sql, '') AS sql FROM sqlite_master " +
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .all() as { type: string; name: string; sql: string }[]
    ).map((row) => `${row.type} ${row.name} :: ${row.sql.replace(/\s+/g, ' ').trim()}`);
  } finally {
    db.close();
  }
}

function ledgerTagsOf(file: string): string[] {
  const db = new DatabaseSync(file);
  try {
    return (
      db.prepare('SELECT tag FROM migration_ledger ORDER BY tag').all() as { tag: string }[]
    ).map((row) => row.tag);
  } finally {
    db.close();
  }
}

function ledgerStampsOf(file: string): number[] {
  const db = new DatabaseSync(file);
  try {
    return (
      db.prepare('SELECT applied_at FROM migration_ledger').all() as { applied_at: number }[]
    ).map((row) => row.applied_at);
  } finally {
    db.close();
  }
}

function userVersionOf(file: string): number {
  const db = new DatabaseSync(file);
  try {
    return (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  } finally {
    db.close();
  }
}

describe('createStoreTemplate builds once', () => {
  it('runs the build step on the first seed and never again', () => {
    let calls = 0;
    const template = createStoreTemplate((dataDir) => {
      calls += 1;
      openLocalDatabase(dataDir).close();
    });

    expect(template.isBuilt()).toBe(false);
    expect(calls).toBe(0);

    for (let i = 0; i < 3; i++) {
      withPlainStore((store) => {
        template.seed(store.dataDir);
        expect(existsSync(store.dbFile)).toBe(true);
      });
    }

    // The claim is build-once, so it is read off the build step itself. Three
    // seeds that each produced a usable store would look identical here if the
    // template rebuilt every time — which is precisely the regression that
    // would make the helper pointless while every suite stayed green.
    expect(calls).toBe(1);
    expect(template.buildCount()).toBe(1);
    expect(template.isBuilt()).toBe(true);
  });

  it('does not build at all until something seeds', () => {
    let calls = 0;
    const template = createStoreTemplate((dataDir) => {
      calls += 1;
      openLocalDatabase(dataDir).close();
    });
    expect(calls).toBe(0);
    expect(template.buildCount()).toBe(0);
  });
});

describe('createStoreTemplate refuses a build it cannot trust', () => {
  it('refuses a build step that leaves no store', () => {
    const template = createStoreTemplate(() => {
      // Opens nothing.
    });
    withPlainStore((store) => {
      const err = errorFrom(() => {
        template.seed(store.dataDir);
      });
      expect(err?.message).toContain('left no aka.db');
    });
  });

  it('refuses a build step that never closed its handle', () => {
    // A live WAL is the observable form of an unclosed handle, and the reason
    // it matters is that the copy would silently lack whatever is still only in
    // the log. Provoked directly rather than by leaking a real handle, so the
    // case does not depend on leaving one open across the assertion.
    const template = createStoreTemplate((dataDir) => {
      openLocalDatabase(dataDir).close();
      writeFileSync(join(dataDir, 'aka.db-wal'), Buffer.alloc(64, 1));
    });
    withPlainStore((store) => {
      const err = errorFrom(() => {
        template.seed(store.dataDir);
      });
      expect(err?.message).toContain('non-empty -wal');
    });
  });

  it('refuses to seed beside a foreign log left with no store', () => {
    // An absent `aka.db` is not an empty data dir. A `-wal` from an earlier
    // store would be paired by SQLite with the template copied over it, and a
    // log belonging to a different database reads as corruption — attributed to
    // the template rather than to the leftover, which is why it is named here.
    withPlainStore((store) => {
      writeFileSync(`${store.dbFile}-wal`, Buffer.alloc(64, 1));
      const err = errorFrom(() => {
        migratedStore.seed(store.dataDir);
      });
      expect(err?.message).toContain('-wal is present with no aka.db');
      // And the refusal left nothing half-written behind.
      expect(existsSync(store.dbFile)).toBe(false);
      expect(existsSync(`${store.dbFile}.template-partial`)).toBe(false);
    });
  });

  it('reports the same failure on every seed without rebuilding', () => {
    let calls = 0;
    const template = createStoreTemplate(() => {
      calls += 1;
    });
    withPlainStore((store) => {
      const first = errorFrom(() => {
        template.seed(store.dataDir);
      });
      const second = errorFrom(() => {
        template.seed(store.dataDir);
      });
      expect(first?.message).toContain('left no aka.db');
      // The SAME error object, not a fresh one from a second failing build: a
      // suite calls seed per test, and re-paying a failing build each time
      // turns one clear setup fault into a slow cascade of identical ones.
      expect(second).toBe(first);
      expect(calls).toBe(1);
    });
  });

  it('refuses to seed over a store that is already there', () => {
    withPlainStore((store) => {
      migratedStore.seed(store.dataDir);
      const err = errorFrom(() => {
        migratedStore.seed(store.dataDir);
      });
      expect(err?.message).toContain('already exists');
    });
  });
});

describe('a seeded store is what a migration would have produced', () => {
  it('carries the identical schema, ledger and user_version', () => {
    withPlainStore((fresh) => {
      // A real migration, for comparison — the handle is closed at once so the
      // file it leaves is complete.
      fresh.open().close();

      withPlainStore((seeded) => {
        migratedStore.seed(seeded.dataDir);

        // Read BEFORE the seeded store is opened: the equivalence that matters
        // is of the file the copy hands over, not of one openLocalDatabase has
        // since had a chance to repair.
        expect(schemaOf(seeded.dbFile)).toEqual(schemaOf(fresh.dbFile));
        expect(ledgerTagsOf(seeded.dbFile)).toEqual(ledgerTagsOf(fresh.dbFile));
        expect(userVersionOf(seeded.dbFile)).toEqual(userVersionOf(fresh.dbFile));
        // Positive controls: an empty comparison satisfies all three above.
        expect(ledgerTagsOf(seeded.dbFile).length).toBeGreaterThan(0);
        expect(schemaOf(seeded.dbFile).length).toBeGreaterThan(0);
      });
    });
  });

  it('runs no migration when it is opened', () => {
    // The saving is the claim, so it is asserted on the ledger's own clock:
    // every tag was written when the TEMPLATE was built, so a store that
    // migrated on open would carry rows stamped after the seed.
    withPlainStore((store) => {
      migratedStore.seed(store.dataDir);
      const seededAt = Date.now();
      const before = ledgerTagsOf(store.dbFile);

      store.open().close();

      expect(ledgerTagsOf(store.dbFile)).toEqual(before);
      const stamps = ledgerStampsOf(store.dbFile);
      expect(stamps.length).toBeGreaterThan(0);
      expect(stamps.every((at) => at <= seededAt)).toBe(true);
    });
  });
});

describe('useTempStore({ migrated: true })', () => {
  const store = useTempStore('aka-tpl-hook-', { migrated: true });

  it('hands each test its own file, already migrated', async () => {
    expect(existsSync(store.dbFile)).toBe(true);
    const db = store.open();
    // Usable as any other store: the repositories prepare against this schema
    // eagerly, so a template short of a column would throw on open, and
    // seedDefaults has to find the tables it writes.
    expect((await db.policies.readPolicies()).length).toBeGreaterThan(0);
    await db.exceptions.create({
      ruleId: 'aws-access-key-id',
      category: 'secret',
      valueFingerprint: '1'.repeat(64),
      keyVersion: 1,
      maskedValue: 'AKIA******Q',
      scope: 'temporary',
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      maxUses: null,
      justification: 'proves the seeded store is writable, and is not carried over',
      conditions: null,
      createdBy: 'alice',
      createdVia: 'cli-approve',
    });
    expect((await db.exceptions.list()).length).toBe(1);
  });

  it('carries nothing the previous test wrote', async () => {
    // The row the test above recorded must not be here: a template seeded once
    // and then shared would carry it, and so would a store the hook failed to
    // replace.
    const db = store.open();
    expect((await db.exceptions.list()).length).toBe(0);
    expect(readFileSync(store.dbFile).length).toBeGreaterThan(0);
  });
});

describe('useTempStore() without the option', () => {
  const store = useTempStore('aka-tpl-off-');

  it('leaves the store absent until something opens it', () => {
    // The opt-in is what keeps the open-path suites honest, so the default must
    // stay "nothing seeded" — a template arriving by default would make every
    // migration and fault assertion in this package vacuous at once.
    expect(existsSync(store.dbFile)).toBe(false);
  });
});
