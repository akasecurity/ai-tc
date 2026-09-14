import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { scanTeardowns, type TeardownScan } from './teardown-removals.ts';

const TEST_ROOT = fileURLToPath(new URL('..', import.meta.url));

/**
 * The suites allowed to remove a directory tree from a teardown WITHOUT
 * `tempHomes()`, each with the reason no store handle can be inside that tree.
 *
 * Pinned as an EXACT set rather than an allowlist the scan merely consults, for
 * two reasons. A new entry is a review-visible diff that has to state its
 * reason. And the set doubles as a positive control on real files: if the scan
 * went blind, these four would drop out of what it finds and the guard would go
 * red, which a "no offenders" check alone can never do.
 */
const OWN_TEARDOWN: Readonly<Record<string, string>> = {
  'e2e/scan-worker-bundle.e2e.test.ts':
    'copies the built scan worker into temp trees and runs it on a worker thread; nothing in this process opens the store',
  'helpers/store-bytes.test.ts':
    'writes store-shaped bytes into a bare directory and deliberately never opens a store, so no handle can be inside it',
  'install-origin.test.ts':
    'builds fake install layouts to classify, and imports nothing that opens the store',
  'lib/close-store.test.ts':
    'the subject is closeStore() itself — the release every other suite relies on — so it has to release and remove by hand, in that order, to test it',
};

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
  it('does so only through tempHomes(), or where the exception is pinned', () => {
    const offenders = suites()
      .filter((scan) => !(scan.file in OWN_TEARDOWN))
      .flatMap((scan) =>
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

  it('still finds a removal in every pinned exception', () => {
    // The positive control. An exception that no longer removes anything is
    // either a suite that moved onto tempHomes() — take it off the list — or a
    // scan that stopped seeing removals on real files, which is the failure
    // this exists to catch.
    const removing = new Set(
      suites()
        .filter((scan) => scan.removals.length > 0)
        .map((scan) => scan.file),
    );
    const stale = Object.keys(OWN_TEARDOWN).filter((file) => !removing.has(file));
    expect(stale, 'A pinned exception no longer removes a tree — see the comment above.').toEqual(
      [],
    );
  });

  it('walks the whole package and finds teardowns in it, so an empty result is not a blind one', () => {
    expect(suites().length).toBeGreaterThan(40);
    const hooks = suites().reduce((total, scan) => total + scan.hooks, 0);
    expect(hooks).toBeGreaterThan(20);
  });
});
