import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { scanTeardowns, type TeardownScan } from './teardown-removals.ts';

const TEST_ROOT = fileURLToPath(new URL('..', import.meta.url));

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

type SuiteScan = TeardownScan & { file: string };

let cached: SuiteScan[] | undefined;
/** Every suite that redirects the home, scanned once for the whole file. */
function redirectingSuites(): SuiteScan[] {
  cached ??= testFiles(TEST_ROOT)
    .map((file) => ({
      file: relative(TEST_ROOT, file),
      ...scanTeardowns(file, readFileSync(file, 'utf-8')),
    }))
    .filter((scan) => scan.redirectsHome);
  return cached;
}

describe('a suite that redirects the home', () => {
  // The bug this pins, in full: anything these suites render opens the local
  // store under whichever home was current, and app/lib/db.ts holds that handle
  // for the process. Removing that directory from a teardown hook is silently
  // fine on POSIX — the files are unlinked and the open handle keeps serving
  // them — and refused outright on Windows, where the removal raises EPERM and
  // the suite fails in its own teardown naming a cleanup line and no test.
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
  // What the scan can and cannot see is written down in teardown-removals.ts.
  it('never removes a directory tree from a teardown hook', () => {
    const offenders = redirectingSuites().flatMap((scan) =>
      scan.removals.map((removal) => `${scan.file}:${String(removal.line)}  ${removal.path}`),
    );

    // The exit, named in the failure rather than left for the reader to find.
    expect(
      offenders,
      'Remove the tree when the FILE finishes instead, via tempHomes() in ' +
        'test/helpers/temp-home.ts — it releases the store first, in the same hook. ' +
        'See akasecurity/ai-tc#486.',
    ).toEqual([]);
  });

  it('has suites that actually redirect it, so the scan above is not vacuous', () => {
    // Without this the guard passes just as well on a tree where nothing matches
    // its precondition — which is how a guard stops guarding without going red.
    expect(redirectingSuites().length).toBeGreaterThan(10);
  });

  it('finds teardown hooks in them, so an empty result is not a parse that saw nothing', () => {
    // The second way to be vacuous: suites found, hooks not. A scan that stopped
    // recognising `afterEach` would report no removals from every one of them.
    const hooks = redirectingSuites().reduce((total, scan) => total + scan.hooks, 0);
    expect(hooks).toBeGreaterThan(10);
  });
});
