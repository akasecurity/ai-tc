// The dashboard is the one surface where a store-open failure cannot speak for
// itself. A hook writes to a terminal and the CLI prints `err.message`, but a
// throw inside a Server Component reaches `app/(app)/error.tsx` — which renders
// a digest and never the message, because these pages read a store holding
// scanned content. So a dashboard running an older build than its store showed
// "Something went wrong" and an opaque digest, for a store that was perfectly
// intact.
//
// The layout is an async-free Server Component — a plain function returning an
// element — so calling it and reading what it hands down needs no renderer and
// no DOM. Only `homedir()` is redirected; the store and its migration ledger are
// real.
import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { DatabaseSync } from 'node:sqlite';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

const AppLayout = (await import('../../app/(app)/layout.tsx')).default;
const { StoreSkewNotice } = await import('../../app/components/StoreSkewNotice.tsx');
const { storeVersionSkew } = await import('../../app/lib/db.ts');

const newHome = tempHomes('aka-web-skew-');
let home: string;

// Lexically past every real tag, so it sorts last and cannot collide with one a
// future migration adds.
const FUTURE_TAG = '9999_from_a_newer_build';

// app/lib/db memoises its handle on globalThis, so a suite that does not drop it
// reads the PREVIOUS test's temp store.
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

/**
 * A store written by a newer build: a ledger tag this build does not define,
 * plus a table its repositories prepare against turned into a view — the shape
 * `0014_drop_legacy_events_findings` gave `events`/`findings`. Every byte is
 * intact and an up-to-date build reads it correctly.
 */
function seedStoreAheadOfBuild(): void {
  openLocalDatabase(dataDir()).close();
  const raw = new DatabaseSync(`${dataDir()}/aka.db`);
  try {
    raw.exec('ALTER TABLE classified_data RENAME TO classified_data_backing');
    raw.exec('CREATE VIEW classified_data AS SELECT * FROM classified_data_backing');
    raw
      .prepare('INSERT OR IGNORE INTO migration_ledger (tag, applied_at) VALUES (?, ?)')
      .run(FUTURE_TAG, Date.now());
    raw.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length + 1)}`);
  } finally {
    raw.close();
  }
}

beforeEach(() => {
  resetSingleton();
  home = newHome();
  osHome.dir = home;
});

afterEach(() => {
  resetSingleton();
});

describe('storeVersionSkew', () => {
  it('reports nothing for a store this build just created', () => {
    openLocalDatabase(dataDir()).close();
    resetSingleton();

    expect(storeVersionSkew()).toBeNull();
  });

  it('names the unknown tags and both counts for a newer store', () => {
    seedStoreAheadOfBuild();
    resetSingleton();

    const skew = storeVersionSkew();

    expect(skew).not.toBeNull();
    expect(skew?.unknownTags).toEqual([FUTURE_TAG]);
    expect(skew?.storeVersion).toBe(SQLITE_MIGRATIONS.length + 1);
    expect(skew?.buildVersion).toBe(SQLITE_MIGRATIONS.length);
  });

  // The narrowing that keeps this from becoming a catch-all: a store that is
  // genuinely unreadable must still reach the error boundary rather than being
  // reported as a version problem.
  it('reports nothing for a failure that is not skew', () => {
    mkdirSync(dataDir(), { recursive: true });
    writeFileSync(`${dataDir()}/aka.db`, 'not a database, definitely not sqlite');
    resetSingleton();

    expect(storeVersionSkew()).toBeNull();
  });
});

describe('the (app) layout', () => {
  function childOf(element: ReactElement): unknown {
    // NavigationTransitionProvider → AppShell → the decided child.
    const provider = element.props as { children: ReactElement };
    const shell = provider.children.props as { children: unknown };
    return shell.children;
  }

  it('renders the pages when the store is healthy', () => {
    openLocalDatabase(dataDir()).close();
    resetSingleton();
    const children = 'the-pages';

    const rendered = AppLayout({ children }) as ReactElement;

    expect(childOf(rendered)).toBe(children);
  });

  it('renders the skew notice INSTEAD of the pages when the store is newer', () => {
    seedStoreAheadOfBuild();
    resetSingleton();
    const children = 'the-pages';

    const rendered = AppLayout({ children }) as ReactElement;
    const decided = childOf(rendered) as ReactElement;

    expect(decided).not.toBe(children);
    expect(decided.type).toBe(StoreSkewNotice);
    expect((decided.props as { skew: { unknownTags: string[] } }).skew.unknownTags).toEqual([
      FUTURE_TAG,
    ]);
  });

  // A page that throws for any OTHER reason must still reach the error boundary,
  // so the layout has to hand its children through rather than swallowing it.
  it('still hands the pages through when the store is unreadable', () => {
    mkdirSync(dataDir(), { recursive: true });
    writeFileSync(`${dataDir()}/aka.db`, 'not a database, definitely not sqlite');
    resetSingleton();
    const children = 'the-pages';

    const rendered = AppLayout({ children }) as ReactElement;

    expect(childOf(rendered)).toBe(children);
  });
});
