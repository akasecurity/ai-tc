/**
 * The store under a path long enough to reach Windows' `MAX_PATH`.
 *
 * 260 characters is the ceiling the Win32 ANSI/Unicode path APIs impose unless
 * both the OS and the process opt in to long paths. Node opts in for its own
 * `fs` calls by prefixing `\\?\`, so a deep tree is created and removed without
 * complaint — but `node:sqlite` hands the path to SQLite's own Windows VFS,
 * which does not necessarily do the same. So the directory work and the store
 * open can disagree, and only on Windows.
 *
 * A monorepo checkout, a Jenkins workspace, a OneDrive-redirected profile with
 * a long account name — deep homes are ordinary rather than exotic.
 *
 * **The failure that matters is not "it does not work".** Every capture path in
 * the product is fail-open: a hook whose `openLocalDatabase` throws writes
 * nothing and exits 0, so a store that cannot be opened costs the user their
 * whole record with no error anywhere they will see it. What must never happen
 * is the quieter one — a handle that opens, accepts writes, and keeps none of
 * them. So the shape asserted here is: on POSIX it works outright, and on any
 * platform it either round-trips writes or refuses loudly. There is no third
 * outcome, and a silent one is the defect.
 *
 * The sidecar boundary is the sharp case. `aka.db-journal` is eight characters
 * longer than `aka.db`, so a database path just under the ceiling puts its own
 * journal over it: the main file opens and the journal it needs to commit
 * cannot be created.
 */
import { mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { openLocalDatabase, UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { dataDir, dbPath } from '../../src/local-layout.ts';
import { dbSidecars, ensureDataDirSync } from '../../src/paths.ts';
import { captureCount, captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { errorFrom } from '../helpers/errors.ts';
import { useTempStore } from '../helpers/temp-store.ts';

/** Windows' classic path ceiling. */
const MAX_PATH = 260;

// A segment long enough to reach the ceiling in a handful of levels rather than
// a hundred. Depth costs real time — every level is a directory create and a
// directory remove — and it is length, not depth, that MAX_PATH bounds.
const SEGMENT = 'nested-workspace-directory';

// The temp tree comes from the harness, which is also what removes it — a deep
// tree is the case where a hand-rolled `rmSync` in a `finally` is least worth
// re-deriving. The store's own `open()` is not usable here, though: it opens
// `<store.home>/data`, and the whole point of this suite is a data dir several
// hundred characters further down. So `openDeep` below opens by hand and closes
// in a `finally`; only the tree's lifetime is the harness's.
const store = useTempStore('aka-long-path-');

// Bumped per `deepHome` call so each gets a disjoint root. Never reset between
// tests: it only has to be unique, and a per-test store makes reuse harmless
// anyway — resetting it would be one more thing to keep in step with the hooks.
let roots = 0;

/**
 * A home whose `<home>/data/aka.db` is at least `target` characters. Built by
 * appending whole segments to the store's own root and then one trimmed segment,
 * so the length lands where the caller asked rather than wherever the loop
 * happened to stop.
 */
function deepHome(target: number): { home: string; dbFile: string } {
  // Each call gets its own root under the store, so two calls in one body build
  // disjoint trees. Sharing `store.home` directly would make the shorter home a
  // prefix DIRECTORY of the longer one — both descend through identical SEGMENT
  // names — and the two stores would then sit inside each other.
  let home = join(store.home, `deep-${String(roots++)}`);
  while (dbPath(join(home, SEGMENT)).length < target) home = join(home, SEGMENT);

  const shortfall = target - dbPath(home).length;
  if (shortfall > 0) home = join(home, SEGMENT.slice(0, Math.max(shortfall - 1, 1)));

  mkdirSync(home, { recursive: true });
  return { home, dbFile: dbPath(home) };
}

/** Open the store under `home`, or report why it could not be opened. */
type DeepOpen = { db: LocalDatabase; error?: undefined } | { db?: undefined; error: Error };

function openDeep(home: string): DeepOpen {
  // The directory work and the store open are separated because they use
  // different path layers: Node prefixes `\\?\` for its own fs calls, SQLite
  // does whatever its Windows VFS does. Either can be the one that refuses, and
  // the caller's property holds the same way for both.
  const dirError = errorFrom(() => {
    ensureDataDirSync(dataDir(home));
  });
  if (dirError) return { error: dirError };

  let db: LocalDatabase | undefined;
  const openError = errorFrom(() => {
    db = openLocalDatabase(dataDir(home));
  });
  if (openError) return { error: openError };
  if (db === undefined) throw new Error('openLocalDatabase neither threw nor returned a handle');
  return { db };
}

/**
 * The whole property in one place: a store either round-trips a capture or
 * refuses to open. Returns which, so a caller can additionally require the
 * first on a platform where the ceiling does not exist.
 */
function roundTripsOrRefuses(home: string): 'stored' | 'refused' {
  const { db, error } = openDeep(home);
  if (db === undefined) {
    // Loud is the requirement — an Error the caller can act on, not a
    // half-built handle and not `undefined`.
    expect(error).toBeInstanceOf(Error);
    expect(error.message).not.toBe('');
    return 'refused';
  }
  try {
    const event = captureEvent();
    db.recordCapture(event, [captureFinding(event.id)]);
    // recordCapture is fail-open and returns void, so the only account of a
    // write is the row. This is the assertion the silent case would fail.
    expect(captureCount(db[UNSAFE_TEST_ONLY_RAW_HANDLE])).toBeGreaterThan(0);
    return 'stored';
  } finally {
    db.close();
  }
}

describe('a store in a deep tree', () => {
  it('works outright when the path is comfortably short', () => {
    // The control. Without it every case below is satisfied by a store that
    // refuses everything, and the suite would report the ceiling as reached at
    // any length at all.
    const { home, dbFile } = deepHome(80);
    expect(dbFile.length).toBeLessThan(MAX_PATH);
    expect(roundTripsOrRefuses(home)).toBe('stored');
  });

  it('either stores or refuses loudly past MAX_PATH — never silently', () => {
    const { home, dbFile } = deepHome(MAX_PATH + 40);
    expect(dbFile.length).toBeGreaterThan(MAX_PATH);
    roundTripsOrRefuses(home);
  });

  it('either stores or refuses loudly where only the SIDECAR crosses MAX_PATH', () => {
    // The boundary the database path alone cannot show: `aka.db-journal` is
    // eight characters longer than the file it belongs to, so this store's main
    // file is inside the ceiling and its journal is outside it. A platform that
    // opens the one and cannot create the other commits nothing.
    const { home, dbFile } = deepHome(MAX_PATH - 4);
    expect(dbFile.length).toBeLessThan(MAX_PATH);
    const longest = Math.max(...dbSidecars(dbFile).map((path) => path.length));
    expect(longest).toBeGreaterThan(MAX_PATH);
    roundTripsOrRefuses(home);
  });

  it.skipIf(process.platform === 'win32')(
    'stores past MAX_PATH on this platform, which has no such ceiling',
    () => {
      // POSIX bounds a single component (NAME_MAX, 255) and the whole path
      // (PATH_MAX, 1024 on darwin and 4096 on Linux), and 300 characters of
      // short components is inside both. So here the outcome is not a choice:
      // anything but 'stored' is a real defect, and this is what stops the
      // permissive shape above from being the only thing asserted anywhere.
      const { home, dbFile } = deepHome(MAX_PATH + 40);
      expect(dbFile.length).toBeGreaterThan(MAX_PATH);
      expect(roundTripsOrRefuses(home)).toBe('stored');

      // And the at-rest control still applies at this length — a chmod that
      // silently missed a long path would leave the store world-readable.
      expect(statSync(dbFile).mode & 0o777).toBe(0o600);
    },
  );

  it.skipIf(process.platform !== 'win32')('reports which outcome Windows gives', async (ctx) => {
    // Recorded rather than asserted, deliberately: whether SQLite's Windows VFS
    // reaches past MAX_PATH depends on the OS long-path opt-in, which is a
    // property of the runner and not of this repository. The property that IS
    // asserted is in roundTripsOrRefuses, and it holds either way; this case
    // exists so the answer is visible in the log rather than inferred from a
    // green run, since the two outcomes have very different consequences for a
    // user with a deep profile.
    const { home, dbFile } = deepHome(MAX_PATH + 40);
    expect(dbFile.length).toBeGreaterThan(MAX_PATH);
    // roundTripsOrRefuses carries this case's real assertions: it requires a
    // round-trip on the store it opened, or a thrown Error with a message on
    // the one it could not. Asserting its return value against the union it is
    // typed as would add nothing — that comparison is true by construction and
    // could never go red. What is left here is the report.
    const outcome = roundTripsOrRefuses(home);
    await ctx.annotate(`store at ${String(dbFile.length)} chars on win32: ${outcome}`);
  });
});
