import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  type VaultDerefInsert,
  type VaultRowInsert,
} from '@akasecurity/persistence';
import type { VaultDerefReason } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  loadMoreVaultInventory,
  loadMoreVaultReuse,
  loadVaultDerefs,
  purgeVault,
  revealEntry,
} from '../../app/(app)/vault/actions.ts';
import { removeTree } from '../helpers/remove-tree.ts';

/**
 * The vault page's three paged READ actions.
 *
 * What they own is the boundary and the keyset: an action is a POST endpoint the
 * browser can reach with anything, so a hand-rolled body must be refused rather
 * than reaching the store as a query; and a page walk must cover every row
 * exactly once even where the sort key ties, since the plugin hooks and the CLI
 * write to this table while the reader pages.
 *
 * Setup follows the four steps every web-ui Server Action test needs: redirect
 * the home dir by mocking `node:os` (the actions resolve ~/.aka from it, and
 * n/no-process-env rules out an env override), stub `next/cache` (the module
 * imports revalidatePath whichever export is called, and it needs a Next render
 * context that does not exist under vitest), and close and drop the memoised DB
 * handle on globalThis around every test.
 *
 * The stub is a spy rather than a no-op because "these reads do not revalidate"
 * is itself one of the properties under test.
 */
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
const revalidate = vi.hoisted(() => vi.fn());
vi.mock('next/cache', () => ({ revalidatePath: revalidate }));

// app/lib/db.ts memoises its handle on globalThis across requests and HMR
// reloads, so it must be closed and dropped between tests or the next action
// reads the PREVIOUS test's store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

let home: string;
let dir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-vault-paging-'));
  osHome.dir = home;
  // dataDir()'s argument is the ~/.aka ROOT, not the home — with the mock in
  // place the no-argument form resolves to exactly what the action will open.
  dir = dataDir();
  revalidate.mockClear();
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
  removeTree(home);
});

// Every case here drives a READ, so the fixture is written straight through the
// repository rather than through SecretVault.tokenize: the store IS the input,
// and going through the vault would drag in the consent grant and the key
// custody that none of these reads touch.
function seed(write: (db: LocalDatabase) => void): void {
  const db = openLocalDatabase(dir);
  try {
    write(db);
  } finally {
    db.close();
  }
  // The seeding handle is a SECOND one; drop the memoised handle again so the
  // action reopens and sees these rows.
  dropMemoisedDb();
}

const BASE = Date.UTC(2026, 5, 29, 12, 0, 0);

function vaultRow(pointerId: string): VaultRowInsert {
  return {
    pointerId,
    // The store's identity key, unique per VALUE. Derived from the pointer id so
    // the mapping is 1:1 and a failing row is identifiable from either side.
    valueFingerprint: createHash('sha256').update(pointerId).digest('hex'),
    fingerprintKeyVersion: 1,
    keyVersion: 1,
    category: 'secret',
    ruleId: 'secrets/test-rule',
    maskedMatch: 'val…ue',
    provider: 'aws',
    ciphertext: 'Y2lwaGVy',
    nonce: 'bm9uY2U=',
    authTag: 'dGFn',
  };
}

function derefRow(pointerId: string, at: number, reason: VaultDerefReason): VaultDerefInsert {
  return { id: randomUUID(), pointerId, at, target: 'human', reason, outcome: 'revealed' };
}

/**
 * Vault one value `times` times at a fixed clock. Every call passes the SAME
 * `now`, because a repeat sighting bumps `last_seen` — so this raises
 * `occurrence_count` (what the reuse list ranks on) while leaving `last_seen`
 * (what the inventory sorts on) exactly where the caller put it.
 */
function vaultValue(db: LocalDatabase, pointerId: string, at: number, times = 1): void {
  for (let i = 0; i < times; i += 1) db.secretVault.upsert(vaultRow(pointerId), at);
}

interface Paged {
  items: unknown[];
  nextCursor: string | null;
}

/**
 * Walk a paged read to exhaustion and return every page.
 *
 * The iteration cap is not decoration: a keyset comparison that stops advancing
 * hands back the same cursor forever, which would HANG the run rather than fail
 * it — and a hung run reports nothing about which property broke.
 */
async function pageThrough<T extends Paged>(
  action: (raw: unknown) => Promise<T>,
  limit: number,
): Promise<T[]> {
  const pages: T[] = [];
  let cursor: string | null = null;
  do {
    const page = await action(cursor === null ? { limit } : { limit, cursor });
    pages.push(page);
    cursor = page.nextCursor;
    if (pages.length > 20) throw new Error('paging did not terminate');
  } while (cursor !== null);
  return pages;
}

describe('loadMoreVaultInventory', () => {
  // Six values over four distinct `last_seen` stamps, two of them shared. The
  // ties are the point: the keyset compares (last_seen DESC, pointer_id DESC),
  // and with every stamp distinct the tie-breaking half of that comparison is
  // never exercised — a read that dropped it would page identically.
  //
  // Pointer ids are anti-correlated with time on purpose, so an ordering taken
  // from the ids alone disagrees with the one taken from the clock.
  const SEEDED: readonly (readonly [string, number])[] = [
    ['p-b', BASE + 3_000],
    ['p-a', BASE + 3_000],
    ['p-c', BASE + 2_000],
    ['p-e', BASE + 1_000],
    ['p-d', BASE + 1_000],
    ['p-f', BASE],
  ];
  // (last_seen DESC, pointer_id DESC). At limit 2 the pages are [p-b, p-a],
  // [p-c, p-e], [p-d, p-f] — so the BASE+1_000 tie straddles the boundary
  // between page two and page three, which is the only place the tie-break can
  // be observed from outside.
  const NEWEST_FIRST = ['p-b', 'p-a', 'p-c', 'p-e', 'p-d', 'p-f'];

  function seedInventory(): void {
    seed((db) => {
      for (const [pointerId, at] of SEEDED) vaultValue(db, pointerId, at);
    });
  }

  it('covers every value exactly once across pages, including a straddled tie', async () => {
    seedInventory();

    const pages = await pageThrough(loadMoreVaultInventory, 2);

    expect(pages.map((p) => p.items.length)).toEqual([2, 2, 2]);
    const walked = pages.flatMap((p) => p.items.map((e) => e.pointerId));
    // Exact order, not just membership: a cursor that resumed from the probe row
    // instead of the last row of the page would still return six distinct
    // pointers, just not these six.
    expect(walked).toEqual(NEWEST_FIRST);
    expect(new Set(walked).size).toBe(SEEDED.length);
    // The last page is the last page — nothing further to fetch.
    expect(pages[pages.length - 1]?.nextCursor).toBeNull();
  });

  it('reports the whole-store total on every page, not the page length', async () => {
    seedInventory();

    const pages = await pageThrough(loadMoreVaultInventory, 2);

    expect(pages.map((p) => p.totals.values)).toEqual([6, 6, 6]);
    // The control: the pages really were shorter than the total, so a totals
    // field taken from `items.length` would have been caught above.
    expect(pages.every((p) => p.items.length < 6)).toBe(true);
  });
});

describe('loadMoreVaultReuse', () => {
  it('returns only values detected twice or written in two places', async () => {
    seed((db) => {
      // Reused by DETECTION count.
      vaultValue(db, 'reuse-by-count', BASE + 2_000, 2);
      // Reused by SIGHTING count — detected once, but its pointer was written
      // to two files. The predicate is an OR, so both halves need a witness.
      vaultValue(db, 'reuse-by-sighting', BASE + 1_000);
      db.secretVault.recordSighting(
        { pointerId: 'reuse-by-sighting', location: 'a.ts', kind: 'file' },
        BASE,
      );
      db.secretVault.recordSighting(
        { pointerId: 'reuse-by-sighting', location: 'b.ts', kind: 'file' },
        BASE,
      );
      // Neither: one detection, one place.
      vaultValue(db, 'solo', BASE + 3_000);
      db.secretVault.recordSighting({ pointerId: 'solo', location: 'c.ts', kind: 'file' }, BASE);
    });

    const page = await loadMoreVaultReuse({});

    expect(page.items.map((e) => e.pointerId)).toEqual(['reuse-by-count', 'reuse-by-sighting']);
    expect(page.totals.reused).toBe(2);

    // The positive control for the absence above: `solo` was really seeded, and
    // it is the NEWEST row, so its absence from the reuse list is the predicate
    // at work rather than the fixture never landing.
    const inventory = await loadMoreVaultInventory({});
    expect(inventory.items.map((e) => e.pointerId)).toContain('solo');
    expect(inventory.items[0]?.pointerId).toBe('solo');
  });

  it('pages most-reused first without repeating a value', async () => {
    // Occurrence counts descend as `last_seen` ascends, so this list's order is
    // the exact reverse of the inventory's — a page walk that borrowed the
    // inventory's cursor codec could not produce it.
    seed((db) => {
      vaultValue(db, 'r-most', BASE, 4);
      vaultValue(db, 'r-mid', BASE + 1_000, 3);
      vaultValue(db, 'r-least', BASE + 2_000, 2);
    });

    const pages = await pageThrough(loadMoreVaultReuse, 2);

    expect(pages.map((p) => p.items.length)).toEqual([2, 1]);
    expect(pages.flatMap((p) => p.items.map((e) => e.pointerId))).toEqual([
      'r-most',
      'r-mid',
      'r-least',
    ]);
    expect(pages.map((p) => p.totals.reused)).toEqual([3, 3]);
  });
});

describe('loadVaultDerefs', () => {
  // Two model-crossing rows worth surfacing, buried under four batched render
  // rows. `hiddenBatched` is what the view's "N hidden" line speaks for, so it
  // must count the whole trail — and the page below holds ONE row, so a count
  // taken from the page could only ever be 0.
  const BATCHED: readonly (readonly [VaultDerefReason, number])[] = [
    ['display', BASE + 6_000],
    ['display', BASE + 5_000],
    ['display', BASE + 4_000],
    ['view-render', BASE + 3_000],
  ];
  const SURFACED: readonly (readonly [VaultDerefReason, number])[] = [
    ['explicit-reveal', BASE + 2_000],
    ['model-input', BASE + 1_000],
  ];

  function seedTrail(): void {
    seed((db) => {
      for (const [reason, at] of [...BATCHED, ...SURFACED]) {
        db.secretVault.recordDeref(derefRow('p-1', at, reason));
      }
    });
  }

  it('hides the batched render reasons and counts them over the whole trail', async () => {
    seedTrail();

    const first = await loadVaultDerefs({ limit: 1 });
    expect(first.items.map((r) => r.reason)).toEqual(['explicit-reveal']);
    expect(first.hiddenBatched).toBe(BATCHED.length);
    expect(first.nextCursor).not.toBeNull();

    const cursor = first.nextCursor;
    if (cursor === null) throw new Error('unreachable');
    const second = await loadVaultDerefs({ limit: 1, cursor });
    expect(second.items.map((r) => r.reason)).toEqual(['model-input']);
    // Unchanged as the reader pages: it is a property of the trail, not of the
    // window the reader happens to be looking at.
    expect(second.hiddenBatched).toBe(BATCHED.length);
    expect(second.nextCursor).toBeNull();
  });

  it('includes them when asked, and then reports nothing hidden', async () => {
    seedTrail();

    const page = await loadVaultDerefs({ includeBatched: true, limit: 100 });

    expect(page.items.map((r) => r.reason)).toEqual([
      'display',
      'display',
      'display',
      'view-render',
      'explicit-reveal',
      'model-input',
    ]);
    expect(page.hiddenBatched).toBe(0);
  });
});

// The whole reason these actions parse: each is a POST endpoint reachable with
// any body at all, and a query that reached the store unparsed would page with
// whatever limit the caller asked for.
const PAGED_READS: readonly (readonly [string, (raw: unknown) => Promise<Paged>])[] = [
  ['loadMoreVaultInventory', loadMoreVaultInventory],
  ['loadMoreVaultReuse', loadMoreVaultReuse],
  ['loadVaultDerefs', loadVaultDerefs],
];

for (const [name, action] of PAGED_READS) {
  describe(`${name} parses its argument at the boundary`, () => {
    // Three of everything: enough for a limit of 2 to be observably a limit,
    // and each row vaulted twice so it qualifies for the reuse list too.
    function seedThreeOfEach(): void {
      seed((db) => {
        for (let i = 0; i < 3; i += 1) {
          const pointerId = `boundary-${String(i)}`;
          vaultValue(db, pointerId, BASE + i * 1_000, 2);
          db.secretVault.recordDeref(derefRow(pointerId, BASE + i * 1_000, 'explicit-reveal'));
        }
      });
    }

    it('rejects a hand-rolled body', async () => {
      seedThreeOfEach();

      await expect(action({ limit: 5000 })).rejects.toThrow(); // past the ceiling
      await expect(action({ limit: 0 })).rejects.toThrow(); // below the floor
      await expect(action({ limit: 'abc' })).rejects.toThrow(); // coerces to NaN
      await expect(action(null)).rejects.toThrow(); // not an object at all
    });

    it('accepts a limit that crossed the wire as a string', async () => {
      seedThreeOfEach();

      // The coercion is deliberate: a Server Action is a POST boundary, and a
      // number can arrive from a form or a hand-rolled body as its decimal
      // string. Three rows are seeded, so a limit that failed to apply would
      // return three items rather than two.
      const page = await action({ limit: '2' });
      expect(page.items).toHaveLength(2);
      expect(page.nextCursor).not.toBeNull();
    });
  });
}

describe('loadVaultDerefs takes a real boolean for includeBatched', () => {
  it('rejects the string form', async () => {
    seed((db) => {
      db.secretVault.recordDeref(derefRow('p-1', BASE, 'display'));
    });

    // Not `z.stringbool()`: this arrives over a Server Action, which preserves
    // the type. Accepting 'false' would silently unhide the batched rows, since
    // every non-empty string is truthy.
    await expect(loadVaultDerefs({ includeBatched: 'true' })).rejects.toThrow();
    await expect(loadVaultDerefs({ includeBatched: 'false' })).rejects.toThrow();

    // The control: the boolean form is accepted, so the refusals above are the
    // type check rather than the whole call failing.
    const page = await loadVaultDerefs({ includeBatched: true });
    expect(page.items).toHaveLength(1);
  });
});

describe('the paged reads never revalidate the route', () => {
  it('is a live spy — a mutating action does revalidate', async () => {
    // The positive control for the absence assertion below. Without it,
    // "revalidatePath was not called" would hold just as well for a spy wired
    // to a module the actions never import.
    //
    // `purgeVault` rather than `revealEntry`: a reveal deliberately does NOT
    // revalidate any more (it would drop the reader's appended pages along with
    // the value they just revealed), so it can no longer serve as the control.
    const result = await purgeVault({ confirmation: 'purge' });

    expect(result).toEqual({ ok: true, destroyed: 0 });
    expect(revalidate).toHaveBeenCalledWith('/vault');
  });

  it('a reveal does not revalidate — it would discard the reader page state', async () => {
    seed((db) => {
      vaultValue(db, 'p-1', BASE, 1);
    });

    // Unresolvable is fine here: the point is which side effects the action has,
    // and the vault deliberately does not distinguish a miss from a forgery.
    const result = await revealEntry({ pointerId: 'no-such-pointer' });

    expect(result).toEqual({ ok: true, value: null });
    expect(revalidate).not.toHaveBeenCalled();
  });

  it('leaves the reader accumulated pages and revealed values alone', async () => {
    seed((db) => {
      vaultValue(db, 'p-1', BASE, 2);
      db.secretVault.recordDeref(derefRow('p-1', BASE, 'explicit-reveal'));
    });

    // A revalidate here re-runs the route, which hands the client a fresh first
    // page — dropping every page the reader has appended AND every value they
    // revealed on screen.
    const inventory = await loadMoreVaultInventory({});
    const reuse = await loadMoreVaultReuse({});
    const derefs = await loadVaultDerefs({});

    // Each read really ran, so the absence below is about the reads rather than
    // about three calls that failed before reaching revalidatePath.
    expect(inventory.items).toHaveLength(1);
    expect(reuse.items).toHaveLength(1);
    expect(derefs.items).toHaveLength(1);
    expect(revalidate).not.toHaveBeenCalled();
  });
});
