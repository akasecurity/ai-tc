import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import vitestConfig from '../../vitest.config.ts';
import { scanTeardowns, type TeardownScan } from './teardown-removals.ts';

const TEST_ROOT = fileURLToPath(new URL('..', import.meta.url));

interface OwnTeardown {
  /** Why no store handle can be inside the tree this suite removes. */
  reason: string;
  /** Exactly the removals the reason covers, as the scan reports their paths. */
  removals: readonly string[];
}

/**
 * The suites allowed to remove a directory tree from a teardown WITHOUT
 * `tempHomes()`, each with the reason no store handle can be inside that tree.
 *
 * Pinned per REMOVAL, not per file. An exception is granted for one stated
 * reason about one removal; exempting the whole file would let a second removal
 * added there later — one that does sit over an open store — pass under a reason
 * that does not cover it. Both a new removal and a missing one fail below, so
 * any change to what an exempt suite removes is a review-visible diff.
 */
const OWN_TEARDOWN: Readonly<Record<string, OwnTeardown>> = {
  'e2e/scan-worker-bundle.e2e.test.ts': {
    reason:
      'copies the built scan worker into temp trees and runs it on a worker thread; nothing in this process opens the store',
    removals: ['afterAll → rmSync'],
  },
  'helpers/store-bytes.test.ts': {
    reason:
      'writes store-shaped bytes into a bare directory and deliberately never opens a store, so no handle can be inside it',
    removals: ['afterEach → rmSync'],
  },
  'install-origin.test.ts': {
    reason: 'builds fake install layouts to classify, and imports nothing that opens the store',
    removals: ['afterAll → rmSync'],
  },
  'lib/close-store.test.ts': {
    reason:
      'the subject is closeStore() itself — the release every other suite relies on — so it has to release and remove by hand, in that order, to test it',
    removals: ['afterEach → removeTrees'],
  },
};

type SuiteScan = TeardownScan & { file: string };

/**
 * What the scans report that no pinned exception covers (`offenders`), and what
 * is pinned but no longer found (`stale`). Each pinned removal covers exactly
 * one reported removal of that path in that file — never the file as a whole.
 */
function checkExceptions(
  scans: readonly SuiteScan[],
  pinned: Readonly<Record<string, OwnTeardown>>,
): { offenders: string[]; stale: string[] } {
  const remaining = new Map(Object.entries(pinned).map(([file, own]) => [file, [...own.removals]]));
  const offenders = scans.flatMap((scan) => {
    const left = remaining.get(scan.file) ?? [];
    return scan.removals.flatMap((removal) => {
      const index = left.indexOf(removal.path);
      if (index !== -1) {
        left.splice(index, 1);
        return [];
      }
      return [`${scan.file}:${String(removal.line)}  ${removal.path}`];
    });
  });
  const stale = [...remaining].flatMap(([file, left]) => left.map((path) => `${file}  ${path}`));
  return { offenders, stale };
}

/** Every `*.test.ts`/`*.test.tsx` under `dir`, recursively. */
function testFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...testFiles(full));
    else if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx')) out.push(full);
  }
  return out;
}

let cached: SuiteScan[] | undefined;
/** Every suite in the package, scanned once for the whole file. */
function suites(): SuiteScan[] {
  cached ??= testFiles(TEST_ROOT).map((file) => ({
    file: relative(TEST_ROOT, file).replaceAll('\\', '/'),
    ...scanTeardowns(file, readFileSync(file, 'utf-8')),
  }));
  return cached;
}

describe('a suite that removes a directory tree from a teardown', () => {
  // The bug this pins, in full: anything a suite renders opens the local store
  // under whichever home was current, and app/lib/db.ts holds that handle for
  // the process. Removing that directory from a teardown is silently fine on
  // POSIX — the files are unlinked and the open handle keeps serving them — and
  // refused outright on Windows, where the removal raises EPERM and the suite
  // fails in its own teardown naming a cleanup line and no test.
  //
  // Only the FIRST suite in a worker to open a store can fail that way, so the
  // failure moves between files as import order changes. That is exactly why
  // this is a guard and not a fix in one suite.
  //
  // THE RULE IS ONE PATH, not "remove it, but release first". Every suite this
  // guard once flagged did release first, through a helper of its own —
  // `resetSingleton`, `dropMemoisedDb` — and a guard that tried to recognise a
  // release would have to learn each new name, or be fooled by one that forgets
  // to close. `tempHomes()` releases and removes in one hook, in that order, and
  // a suite on it has nothing here to get wrong.
  //
  // It applies to EVERY suite, not only ones seen redirecting `homedir()`: the
  // redirect was once a precondition, and recognising a redirect is as
  // open-ended as recognising a removal, so each spelling it missed took a
  // whole suite out of the guard. What the scan can and cannot see is written
  // down in teardown-removals.ts.
  it('does so only through tempHomes(), or exactly where the exception is pinned', () => {
    // The exit, named in the failure rather than left for the reader to find.
    expect(
      checkExceptions(suites(), OWN_TEARDOWN).offenders,
      'Remove the tree when the FILE finishes instead, via tempHomes() in ' +
        'test/helpers/temp-home.ts — it releases the store first, in the same hook. ' +
        'See akasecurity/ai-tc#486.',
    ).toEqual([]);
  });

  it('still finds every pinned removal', () => {
    // A pinned removal that is gone is either a suite that moved onto
    // tempHomes() — take it off the list — or a scan that stopped seeing
    // removals on real files, which is the failure this exists to catch.
    expect(
      checkExceptions(suites(), OWN_TEARDOWN).stale,
      'A pinned removal is no longer there — see the comment above.',
    ).toEqual([]);
  });

  // The positive control for the path most suites depend on. Every pinned
  // exception is a removal written in the suite itself, so they prove nothing
  // about reading a HELPER from disk: a scan whose on-disk import resolution had
  // gone blind would still find all four of them, and every helper-mediated
  // removal would slip past. This fixture reaches its removal only through a
  // real import of a real file, and it is never run or collected.
  it('reads a teardown a helper module registers, through a real import on disk', () => {
    const fixture = fileURLToPath(new URL('./guard-control/suite.ts', import.meta.url));
    const scan = scanTeardowns(fixture, readFileSync(fixture, 'utf-8'));
    expect(scan.removals.map((removal) => removal.path)).toEqual([
      'guard-control/helper.ts → afterEach → removeTree',
    ]);
  });

  // A setup file runs its hooks in every suite and is imported by none, so the
  // walk above never reaches it. A removal there would be the widest possible
  // instance of the bug, and this repo already registers hooks in setup files.
  it('also holds in every setup file the package runs', () => {
    const setupFiles = [vitestConfig.test?.setupFiles ?? []].flat();
    expect(setupFiles.length).toBeGreaterThan(0);
    const offenders = setupFiles.flatMap((file) =>
      scanTeardowns(file, readFileSync(file, 'utf-8')).removals.map(
        (removal) => `${file}:${String(removal.line)}  ${removal.path}`,
      ),
    );
    expect(offenders).toEqual([]);
  });

  it('walks the whole package and finds teardowns in it, so an empty result is not a blind one', () => {
    expect(suites().length).toBeGreaterThan(40);
    const hooks = suites().reduce((total, scan) => total + scan.hooks, 0);
    expect(hooks).toBeGreaterThan(20);
  });
});

// The matcher, on scans the real tree does not happen to contain. The tree is
// clean, so the tests above cannot tell an exception pinned per removal from one
// that exempts its whole file — the difference only shows once an exempt file
// grows a second removal, which is exactly when it matters.
describe('checkExceptions', () => {
  const scan = (file: string, ...paths: string[]): SuiteScan => ({
    file,
    hooks: paths.length,
    removals: paths.map((path, index) => ({ hook: 'afterEach', line: index + 1, path })),
  });
  const pinned = { 'a.test.ts': { reason: 'r', removals: ['afterEach → rmSync'] } };

  it('accepts exactly the pinned removal', () => {
    expect(checkExceptions([scan('a.test.ts', 'afterEach → rmSync')], pinned)).toEqual({
      offenders: [],
      stale: [],
    });
  });

  it('reports a second removal in an exempt file, which the exception does not cover', () => {
    expect(
      checkExceptions([scan('a.test.ts', 'afterEach → rmSync', 'afterAll → removeTree')], pinned)
        .offenders,
    ).toEqual(['a.test.ts:2  afterAll → removeTree']);
  });

  it('reports the same removal twice when it is pinned once', () => {
    expect(
      checkExceptions([scan('a.test.ts', 'afterEach → rmSync', 'afterEach → rmSync')], pinned)
        .offenders,
    ).toEqual(['a.test.ts:2  afterEach → rmSync']);
  });

  it('reports a pinned removal that is no longer found', () => {
    expect(checkExceptions([scan('a.test.ts')], pinned).stale).toEqual([
      'a.test.ts  afterEach → rmSync',
    ]);
  });

  it('reports a removal in a file that has no exception at all', () => {
    expect(checkExceptions([scan('b.test.ts', 'afterEach → removeTree')], pinned)).toEqual({
      offenders: ['b.test.ts:1  afterEach → removeTree'],
      stale: ['a.test.ts  afterEach → rmSync'],
    });
  });
});
