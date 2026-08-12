import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  type VaultRowInsert,
} from '@akasecurity/persistence';
import type { VaultDerefReason } from '@akasecurity/schema';
import { DEFAULT_VAULT_DEREFS_LIMIT, DEFAULT_VAULT_INVENTORY_LIMIT } from '@akasecurity/schema';
import type { ComponentProps, ReactElement, ReactNode } from 'react';
import { Children, isValidElement } from 'react';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import VaultPage from '../../app/(app)/vault/page.tsx';
import { VaultDashboardClient } from '../../app/(app)/vault/VaultDashboardClient.tsx';

// The vault route issues THREE DISTINCT store reads and hands each to its own
// prop:
//
//   inventory — every vaulted value, newest first
//   reuse     — the values seen more than once, MOST-REUSED first
//   derefs    — the de-reference trail with the batched render reasons hidden
//
// Two things about that are invisible to every other suite. The first is that
// each is a FIRST PAGE: the inventory grows one row per distinct value ever
// detected here, and loading it whole is what this route was paginated to stop
// doing — but a whole table and a first page are the same shape, so nothing
// downstream can tell them apart. The second is the WIRING. Reuse and inventory
// are the same row type over the same table, so feeding the reuse view the
// inventory's read typechecks, lints, renders, and quietly answers "which values
// are reused here" with "the fifty most recent ones".
//
// The page is a synchronous Server Component — a plain function returning an
// element — so calling it and reading the props it hands down needs no renderer
// and no DOM. The store is real (house style); only `homedir()` is redirected,
// since the page resolves ~/.aka from it and `n/no-process-env` rules out an env
// override. `next/cache` is stubbed because the client component pulls in the
// actions module, which imports revalidatePath at load.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

let home: string;
let dir: string;

// app/lib/db.ts memoises its handle on globalThis across requests and HMR
// reloads, so a suite that does not drop it reads the PREVIOUS test's store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

// The fixture is seeded ONCE for the whole file, not per test.
//
// Every assertion here READS — the route is a Server Component that only
// queries — so a per-test store buys no isolation, and it is not free. The
// fixture is 175 writes (113 upserts + 62 derefs), which unwrapped is 175
// durable commits, and on the Windows CI leg a commit costs a fsync. Seeding
// that per test ran the file at ~13s a test against the 20s per-test budget in
// web-ui/vitest.config.ts, and timed one out.
// packages/persistence/test/repositories/findings.test.ts seeds its bulk store
// once for the same reason.
//
// Both halves of that are fixed, and the second is what makes it hold. Seeding
// once takes six seeds to one; wrapping the seed in a single transaction
// (`seedFixture`) takes that one seed from 175 commits to 1. The first alone
// was not enough — it left the whole cost in one hook, which then blew a 60s
// hook budget on a runner roughly five times slower than the one it was sized
// against.
//
// The hook keeps an explicit budget anyway, now covering the store open and its
// migrations rather than a pile of fsyncs: on that same degraded runner a plain
// one-store `beforeEach` elsewhere in this package exceeded 20s. The per-test
// budget stays at the config default, where a genuinely slow assertion still
// has to answer for itself.
//
// This holds only while the block stays read-only. A test that WRITES belongs
// on its own store — `afterAll` re-reads the totals and fails if the fixture
// moved, so that lands as a named failure here rather than as a confusing one
// in whichever neighbour happened to run next.
const SEED_TIMEOUT_MS = 60_000;

beforeAll(async () => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-vault-page-'));
  osHome.dir = home;
  dir = dataDir();
  dropMemoisedDb();
  await seedFixture();
}, SEED_TIMEOUT_MS);

afterAll(() => {
  // Cleanup sits in the `finally` because vitest runs afterAll even when
  // beforeAll THREW (measured, not assumed). On that path the invariant below
  // reads a store that was never seeded and throws in turn — so outside a
  // `finally` it would both leak the temp tree and bury the real failure under
  // its own. Dropping the handle before rmSync matters on Windows too, where an
  // open SQLite handle refuses the delete.
  try {
    // The shared-fixture invariant, checked where a writing test cannot dodge
    // it by running after the totals case. Reads through the memoised handle,
    // so it opens nothing.
    const props = renderPage();
    expect(props.inventory.totals.values).toBe(SEEDED_VALUES);
    expect(props.derefs.hiddenBatched).toBe(BATCHED_DEREFS);
  } finally {
    dropMemoisedDb();
    removeTree(home);
  }
});

type ClientProps = ComponentProps<typeof VaultDashboardClient>;

/**
 * Find the VaultDashboardClient node in the tree the route returns.
 *
 * This walk exists because the vault page — unlike the exceptions route — does
 * NOT return its client component. It returns a layout wrapper holding the page
 * head, the lookup panel and the dashboard, so `element.type` on the root is a
 * `div` and `element.props` carries `className` and `children`, not `inventory`.
 * Reading the props straight off the root would make every assertion below read
 * `undefined` and report the wrong reason for going red.
 */
function findClient(node: ReactNode): ReactElement<ClientProps> | null {
  if (!isValidElement(node)) return null;
  if (node.type === VaultDashboardClient) return node as ReactElement<ClientProps>;
  const { children } = node.props as { children?: ReactNode };
  for (const child of Children.toArray(children)) {
    const found = findClient(child);
    if (found !== null) return found;
  }
  return null;
}

/** Call the route and return the props it hands the dashboard client. */
function renderPage(): ClientProps {
  const client = findClient(VaultPage());
  // Asserted, never assumed: a miss here means the tree moved, and every prop
  // assertion downstream would go red naming a value instead of the structure.
  expect(client).not.toBeNull();
  if (client === null) throw new Error('unreachable');
  return client.props;
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

// A discriminating fixture. Every value is reused, so both lists are longer than
// a page — but their orders are REVERSES of each other:
//
//   `at` rises with the index, so the inventory (last_seen DESC) runs
//   VALUES[n-1] … VALUES[0];
//   the pointer ids fall with the index and the oldest row is the most reused,
//   so the reuse list (occurrence_count DESC, pointer_id DESC) runs
//   VALUES[0] … VALUES[n-1].
//
// With rows that satisfied both orderings the assertions below would pass
// whichever read fed which prop, and the suite would prove nothing.
const SEEDED_VALUES = DEFAULT_VAULT_INVENTORY_LIMIT + 5;
const OLDEST_POINTER = `vault-${String(SEEDED_VALUES - 1).padStart(2, '0')}`;
const NEWEST_POINTER = 'vault-00';
// The oldest value is detected this many times; every other value twice. That
// makes it first in the reuse list and last in the inventory — far enough down
// to fall off the inventory's first page entirely.
const OLDEST_OCCURRENCES = 5;

// Far more batched render rows than a reader wants to scroll past, and enough
// model/reveal crossings to overflow a page on their own.
const BATCHED_DEREFS = 7;
const SURFACED_DEREFS = DEFAULT_VAULT_DEREFS_LIMIT + 5;

async function seedFixture(): Promise<void> {
  const db = openLocalDatabase(dir);
  try {
    // ONE transaction around all 175 writes, so the seed costs one commit
    // rather than 175. `upsert` opens its own IMMEDIATE envelope per call and
    // `recordDeref` writes its own row, so unwrapped this is 175 durable
    // commits — and a commit is an fsync, which is why the seed was the
    // tallest pole on the Windows leg. Nesting is supported rather than
    // tolerated: `withTransaction` runs inside a SAVEPOINT when the handle is
    // already in a transaction, and only this outer COMMIT makes any of it
    // durable.
    await db.transaction(() => {
      for (let i = 0; i < SEEDED_VALUES; i += 1) {
        const pointerId = `vault-${String(SEEDED_VALUES - 1 - i).padStart(2, '0')}`;
        const at = BASE + i * 1_000;
        // Every upsert passes the same clock: a repeat sighting bumps
        // `last_seen`, so this raises the occurrence count the reuse list ranks
        // on while leaving the stamp the inventory sorts on where it was put.
        const times = i === 0 ? OLDEST_OCCURRENCES : 2;
        for (let n = 0; n < times; n += 1) db.secretVault.upsert(vaultRow(pointerId), at);
      }
      const deref = (at: number, reason: VaultDerefReason): void => {
        db.secretVault.recordDeref({
          id: randomUUID(),
          pointerId: NEWEST_POINTER,
          at,
          target: 'human',
          reason,
          outcome: 'revealed',
        });
      };
      for (let i = 0; i < SURFACED_DEREFS; i += 1) deref(BASE + i * 1_000, 'explicit-reveal');
      for (let i = 0; i < BATCHED_DEREFS; i += 1) deref(BASE + i * 1_000, 'display');
    });
  } finally {
    db.close();
  }
  // The seeding handle is a SECOND one; drop the memoised handle so the route
  // reopens and sees these rows.
  dropMemoisedDb();
}

describe('the vault route hands down first pages, not whole tables', () => {
  it('is a fixture that outgrows every page', () => {
    // The control for everything below. If a default page size ever grows past
    // what this seeds, the assertions keep passing while testing nothing —
    // every list would fit in one page and "first page" would be identical to
    // "whole table". Pin the disagreement itself so that failure is loud.
    expect(SEEDED_VALUES).toBeGreaterThan(DEFAULT_VAULT_INVENTORY_LIMIT);
    expect(SURFACED_DEREFS).toBeGreaterThan(DEFAULT_VAULT_DEREFS_LIMIT);
  });

  it('caps each list at one page and says there is more', () => {
    const props = renderPage();

    expect(props.inventory.items).toHaveLength(DEFAULT_VAULT_INVENTORY_LIMIT);
    expect(props.inventory.nextCursor).not.toBeNull();
    expect(props.reuse.items).toHaveLength(DEFAULT_VAULT_INVENTORY_LIMIT);
    expect(props.reuse.nextCursor).not.toBeNull();
    expect(props.derefs.items).toHaveLength(DEFAULT_VAULT_DEREFS_LIMIT);
    expect(props.derefs.nextCursor).not.toBeNull();
  });

  it('reports the whole-store totals alongside the capped pages', () => {
    const props = renderPage();

    // The counts the section headings speak for cover the store, so they must
    // not shrink to the page the reader is looking at.
    expect(props.inventory.totals.values).toBe(SEEDED_VALUES);
    expect(props.reuse.totals.reused).toBe(SEEDED_VALUES);
  });
});

describe('the vault route wires each read to the prop that needs it', () => {
  it('is a fixture the two orderings disagree on', () => {
    const props = renderPage();

    // The control for the wiring cases below: the inventory's page and the
    // reuse list's page must not be the same rows in the same order, or both
    // assertions would hold whichever read fed which prop.
    expect(props.inventory.items.map((e) => e.pointerId)).not.toEqual(
      props.reuse.items.map((e) => e.pointerId),
    );
  });

  it('leads the inventory with the newest value', () => {
    const props = renderPage();

    expect(props.inventory.items[0]?.pointerId).toBe(NEWEST_POINTER);
    // The most-reused value is also the OLDEST, so it is the last of 55 rows and
    // falls off a 50-row page entirely. Feed this prop the reuse read and it
    // arrives first instead.
    expect(props.inventory.items.map((e) => e.pointerId)).not.toContain(OLDEST_POINTER);
  });

  it('leads the reuse list with the most-reused value, wherever it sits in time', () => {
    const props = renderPage();

    expect(props.reuse.items[0]?.pointerId).toBe(OLDEST_POINTER);
    expect(props.reuse.items[0]?.occurrences).toBe(OLDEST_OCCURRENCES);
    // And the rest of the list runs oldest-first behind it — the exact reverse
    // of the inventory, so a second inventory read could not produce this.
    expect(props.reuse.items[1]?.pointerId).toBe(
      `vault-${String(SEEDED_VALUES - 2).padStart(2, '0')}`,
    );
    expect(props.reuse.items.map((e) => e.pointerId)).not.toContain(NEWEST_POINTER);
  });

  it('hides the batched render reasons from the trail and counts them whole', () => {
    const props = renderPage();

    expect(props.derefs.items.map((r) => r.reason)).not.toContain('display');
    expect(props.derefs.items.map((r) => r.reason)).not.toContain('view-render');
    // Counted over the whole trail, not the page — and the page holds none of
    // them, so a count taken from it could only ever have been 0.
    expect(props.derefs.hiddenBatched).toBe(BATCHED_DEREFS);
  });
});
