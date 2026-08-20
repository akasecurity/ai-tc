// Build a migrated SQLite store ONCE, then hand out copies of the file.
//
// `openLocalDatabase` runs every migration in the ledger on a store that has
// none, and a suite with per-test isolation pays that on every single test. The
// work is identical each time and its result is a file, so it can be done once
// per worker process and copied — which keeps per-test isolation exactly as it
// was (each test still gets its own file, in its own directory, with no shared
// handle) while removing the repeated schema build.
//
// Measured by `packages/persistence/bench/store-template.bench.ts` on arm64
// macOS 26.5.2 / Node 24.18.0, 22 migrations, end to end per iteration
// (mkdtemp → seed → open → close → rm), tinybench mean over two runs:
//
//   migrate per test         11.10 ms / 14.81 ms
//   copyFileSync + open       1.39 ms /  1.62 ms
//   write cached bytes+open   1.21 ms /  1.42 ms
//
// Roughly 9-10x either way. Two runs rather than one because the migrating row
// alone went from ±0.50% rme to ±13.37% between them — the RATIO is the stable
// part, which is why the bench reports a trend and asserts nothing.
//
// The bytes are cached in memory rather than re-read from a template file
// because the read is the larger half of the copy: the store is ~470 KB and
// every test would otherwise pull it back off disk. That matters most on the
// platform this exists for — Windows charges most for file creation, fsync and
// a scanner reading each new file, and CI has measured this work at roughly 30x
// its local cost there.
//
// It sits at the repo root for the reason `remove-tree.ts` does: six packages'
// suites need the SAME pre-migrated store (persistence, web-ui, plugin-runtime,
// claude-code, cli and local-ops), `@akasecurity/persistence`'s own
// harness is behind a package wall and is importable from none of them, and
// private copies drift apart. It imports nothing but `node:fs`/`node:path` —
// the caller supplies the build step, so this file needs no workspace package
// and stays resolvable from every one of them.
//
// Its suite is `packages/persistence/test/helpers/store-template.test.ts`, not
// a sibling: the repo root is not a workspace package, so `turbo run test`
// reaches no test task here, and persistence is where the store's own semantics
// (schema, migration ledger) can be asserted against a real freshly-migrated
// store.
//
// `test/helpers/**` is in turbo's `globalDependencies`, so a change here
// rehashes every package's `test` task — without which a suite would replay a
// cached green produced against different template bytes.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { removeTree } from './remove-tree.ts';

/** The store filename every caller here builds and seeds. */
const DB_FILE = 'aka.db';

// A store that was closed cleanly has no sidecar: SQLite checkpoints the WAL
// into the main file and removes `-wal`/`-shm` on the last connection's close.
// One left behind means the build step handed back a handle it never closed, so
// the bytes read here are missing whatever is still only in the log. That is a
// silent shortfall — the copy opens fine and simply lacks rows — so it is
// refused rather than tolerated.
const SIDECARS = ['-wal', '-shm', '-journal'] as const;

export interface StoreTemplate {
  /**
   * Write the pre-migrated store into `dataDir` as `aka.db`, creating the
   * directory if it is absent. Builds the template on the first call.
   *
   * Refuses rather than overwrites when a store is already there: seeding over
   * a live store would discard whatever a test had written, and the only way to
   * reach that is a caller seeding twice or seeding after an open.
   */
  readonly seed: (dataDir: string) => void;
  /**
   * Whether the template has been built yet. For this helper's own suite — a
   * build-once claim is otherwise unobservable, and a template rebuilt per
   * `seed` would pass every other assertion here while saving nothing.
   */
  readonly isBuilt: () => boolean;
  /** How many times the build step has run. Its suite asserts this is 1. */
  readonly buildCount: () => number;
}

/**
 * A template built by `build`, which must open a store under the directory it
 * is given, do whatever seeding the caller wants baked in, and CLOSE it.
 *
 * Call this once at module scope so every test in the worker shares one build.
 * The build is lazy, so a module that is loaded but whose tests are all
 * filtered out pays nothing.
 *
 * What the copy does NOT carry is the `aka.db.pre-drop.<ts>.<rand>.bak` a fresh
 * migration leaves beside the store — only `aka.db` is copied. Nothing is lost
 * by that: the backup is snapshotted during the open, so it always predates
 * every write a test makes, and an at-rest scan over it can contain no test
 * value. A suite whose subject IS that backup must not use a template.
 */
export function createStoreTemplate(build: (dataDir: string) => void): StoreTemplate {
  let bytes: Buffer | undefined;
  let failure: Error | undefined;
  let builds = 0;

  const ensureBuilt = (): Buffer => {
    if (bytes !== undefined) return bytes;
    // A build that failed once fails the same way every time, and a suite calls
    // this per test — so the first error is kept and re-thrown rather than
    // paying an mkdtemp, a failed open and a removeTree again for each of them.
    // Every test still reports, and reports the real cause.
    if (failure !== undefined) throw failure;
    const base = mkdtempSync(join(tmpdir(), 'aka-store-template-'));
    try {
      const dataDir = join(base, 'data');
      mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      builds += 1;
      build(dataDir);
      const file = join(dataDir, DB_FILE);
      if (!existsSync(file)) {
        throw new Error(
          `createStoreTemplate: the build step left no ${DB_FILE} in ${dataDir} — it must open a store under the directory it is given.`,
        );
      }
      const live = liveSidecar(file);
      if (live !== undefined) {
        throw new Error(
          `createStoreTemplate: the build step left a non-empty ${live} beside ${DB_FILE} — it must close the handle it opened, or the template would be missing whatever is still only in the log.`,
        );
      }
      bytes = readFileSync(file);
      return bytes;
    } catch (err) {
      failure = err instanceof Error ? err : new Error(String(err));
      throw failure;
    } finally {
      // The build tree has served its purpose either way: on the throw path it
      // must not be stranded, and on the success path the bytes are already in
      // memory. A failure to remove it is not worth speaking over the build's
      // own error, and on win32 `removeTree` already tolerates a held handle.
      removeTree(base);
    }
  };

  return {
    seed: (dataDir: string): void => {
      const template = ensureBuilt();
      mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      const file = join(dataDir, DB_FILE);
      if (existsSync(file)) {
        throw new Error(
          `createStoreTemplate: ${file} already exists — seed a store before it is opened, and only once.`,
        );
      }
      // An absent `aka.db` is not on its own an empty data dir. A `-wal` or
      // `-journal` left by an earlier store — a partial teardown, or a win32
      // `removeTree` that tolerated a held handle — would be paired by SQLite
      // with the template copied over it, and a log whose header belongs to a
      // different database reads as `database disk image is malformed`. That
      // gets attributed to the template rather than to the leftover, so it is
      // refused here where the leftover can still be named.
      const stale = liveSidecar(file);
      if (stale !== undefined) {
        throw new Error(
          `createStoreTemplate: ${file}${stale} is present with no ${DB_FILE} beside it — an earlier store left a log here, and seeding over it would pair the template with a foreign one. Remove the data dir first.`,
        );
      }
      // A temp file plus a rename, not a direct write: the store is only ever
      // read through SQLite, and a reader meeting a partially-written database
      // header reports corruption rather than a short file. The rename is
      // atomic on both platforms, so `aka.db` either is not there or is the
      // whole template.
      writeThenRename(template, file);
    },
    isBuilt: (): boolean => bytes !== undefined,
    buildCount: (): number => builds,
  };
}

function writeThenRename(bytes: Buffer, file: string): void {
  const staging = `${file}.template-partial`;
  try {
    // `writeFileSync`'s mode applies only where it CREATES the file, and is
    // umask-masked besides — the store's real 0600 is set by the product's own
    // `tightenPerms` on the open that follows. This only has to avoid being
    // wider than that in the window between.
    writeFileSync(staging, bytes, { mode: 0o600 });
    renameSync(staging, file);
  } catch (err) {
    // A rename that lost to a scanner holding the file (win32 EPERM) leaves the
    // staging copy in the data dir, where an at-rest scan over that directory
    // would read template bytes as store contents. `force` swallows the ENOENT
    // of the path that never got written.
    try {
      rmSync(staging, { force: true });
    } catch {
      // Nothing to add — the write failure below is the one worth reading.
    }
    throw err;
  }
}

/**
 * The first sidecar beside `file` that carries bytes, or `undefined` when the
 * store stands alone.
 *
 * A store closed cleanly has none: SQLite checkpoints the WAL into the main
 * file and removes `-wal`/`-shm` on the last connection's close. One with bytes
 * in it therefore means a live or abandoned log, which matters at both ends —
 * reading a template out from under one loses whatever is still only in the
 * log, and writing a template in beside one pairs it with a foreign database.
 */
function liveSidecar(file: string): (typeof SIDECARS)[number] | undefined {
  return SIDECARS.find((suffix) => {
    const sidecar = `${file}${suffix}`;
    return existsSync(sidecar) && statSync(sidecar).size > 0;
  });
}
