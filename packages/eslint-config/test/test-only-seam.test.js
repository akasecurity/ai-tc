import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

import { describe, expect, it } from 'vitest';

import { lintableTrackedFiles, REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

// `@akasecurity/persistence` ships one deliberately test-only seam:
// UNSAFE_TEST_ONLY_RAW_HANDLE, a symbol-keyed property on `LocalDatabase`
// holding the `DatabaseSync` the facade writes through. The fault suite needs it
// because `PRAGMA max_page_count` — the only way to raise a real SQLITE_FULL in
// CI — binds to a CONNECTION, and the store's blanket fail-open closures write
// through one nothing else could reach.
//
// A raw handle on a shipped, bundled package is worth exactly one guarantee: no
// product code reads it. Nothing else here can check that. The network and
// process.env audits in this package are about MODULES and DIRECTIVES; neither
// looks at an identifier, and the persistence package's own suite cannot see
// past its package wall to `cli/src` or `web-ui/app`. So the check lives here,
// beside the tree-wide walk and the turbo inputs that already hash the whole
// workspace — a guard scoped to one package would go on passing while a caller
// appeared in another.
//
// The rule is derived, not listed. A file naming the seam is either its one
// definition site or a test, so a new fault test needs no edit here while a
// `cli/src/*.ts` reaching for it fails — which is the property, stated directly.

// Budget for the cases below that walk the WHOLE tracked tree — a `git ls-files`
// plus a read of every lintable file. That costs ~3s on an idle developer
// machine, against vitest's 5s per-test default, so these carry under 2x
// headroom before any other suite is running. This package runs its files in
// parallel and several of them resolve flat configs (which pull the whole
// typescript-eslint stack), so the headroom is gone whenever the suite is busy,
// and the failure then surfaces as a timeout on whichever file lost the race
// rather than on whatever was added. Same reasoning as the resolution hooks'
// budgets: bound the hang where the slow work actually is, and leave the package
// default alone so the sub-millisecond assertions keep a tight one.
const TREE_WALK_TIMEOUT_MS = 30_000;

/** The seam this suite exists for. */
const SEAM = 'UNSAFE_TEST_ONLY_RAW_HANDLE';

/** The only shipped-source file allowed to name it: where it is defined. */
const DEFINITION = 'packages/persistence/src/database.ts';

/** The package whose entry point must not re-export it. */
const ENTRY = 'packages/persistence/src/index.ts';
const MANIFEST = 'packages/persistence/package.json';

/**
 * True for a path the workspace treats as test code.
 *
 * A `test`/`tests` path segment or a `.test.`/`.spec.` basename — the two
 * layouts the tree actually uses. Anything else counts as shipped source, which
 * is the safe direction to be wrong in: a test file this misses is reported as a
 * product caller and someone looks, where a product file it wrongly excused
 * would ship unguarded.
 * @param {string} file repo-relative posix path
 */
function isTestFile(file) {
  const segments = file.split('/');
  return (
    segments.slice(0, -1).some((s) => s === 'test' || s === 'tests') ||
    /\.(test|spec)\./.test(posix.basename(file))
  );
}

/**
 * Every tracked lintable file whose text names the given seam.
 * @param {string} seam defaults to the raw handle, this file's original subject
 */
function filesNamingSeam(seam = SEAM) {
  return lintableTrackedFiles().filter((file) => {
    // A tracked path can still be unreadable — a submodule gitlink, a symlink
    // to nowhere. Skipping one silently would drop a file out of the audit
    // without anyone noticing, so this throws instead.
    let text;
    try {
      text = readFileSync(join(REPO_ROOT, file), 'utf8');
    } catch (cause) {
      throw new Error(`Could not read tracked file ${file} while auditing ${seam}.`, { cause });
    }
    return text.includes(seam);
  });
}

describe(`the ${SEAM} test-only seam`, () => {
  it(
    'is named by exactly one shipped source file — the one that defines it',
    () => {
      const shipped = filesNamingSeam()
        .filter((file) => !isTestFile(file))
        .sort();

      // An exact set of one, not a floor. "The definition is still there" would
      // stay green with a second, product caller beside it, and the second caller
      // is the entire failure mode.
      expect(shipped).toEqual([DEFINITION]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'is used by the fault tests, so this suite is not guarding an absence',
    () => {
      const tests = filesNamingSeam().filter(isTestFile);

      // The positive control. Delete the seam and its consumers and every
      // assertion above holds perfectly — on a workspace where the thing being
      // guarded does not exist. This is the case that goes red for that.
      expect(tests.length).toBeGreaterThan(0);
      expect(tests).toContain('packages/persistence/test/faults/disk-full.test.ts');
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it('is not re-exported from the package entry point', () => {
    const entry = readFileSync(join(REPO_ROOT, ENTRY), 'utf8');

    // What makes "test-only" structural rather than a request. The manifest
    // below exposes `.` alone, so `src/database.ts` is unreachable from another
    // package — re-export the symbol here and every consumer of
    // `@akasecurity/persistence` can name it, at which point the rule above is
    // the only thing left and it is a rule about this repo, not about a
    // published surface.
    expect(entry).not.toContain(SEAM);
  });

  it('is unreachable from outside the package: no exports subpath resolves to its module', () => {
    const { exports: map } = JSON.parse(readFileSync(join(REPO_ROOT, MANIFEST), 'utf8'));
    const entries = Object.entries(map);

    expect(entries.length).toBeGreaterThan(0);
    for (const [subpath, target] of entries) {
      // A wildcard subpath (`"./*": "./src/*"`) would expose every module in
      // the package, this one included, without ever naming it.
      expect(subpath).not.toContain('*');
      expect(JSON.stringify(target)).not.toContain('*');
      expect(JSON.stringify(target)).not.toContain('database.ts');
    }
  });

  it(
    'reads a tree it really walked',
    () => {
      // `trackedFiles()` returning nothing would make every assertion above pass
      // by describing an empty workspace — the failure mode a git-backed walk has
      // and a hardcoded list does not.
      expect(trackedFiles()).toContain(DEFINITION);
      expect(lintableTrackedFiles()).toContain(DEFINITION);
    },
    TREE_WALK_TIMEOUT_MS,
  );
});

// The workspace's SECOND test-only seam, and it is held to the SAME two
// properties as the raw handle above: one shipped definition site, and no
// re-export from the package entry point.
//
// UNSAFE_TEST_ONLY_setManagedSettingsPaths points the DEFAULT managed read at
// other locations, or at none, so that a suite's view of which administrator
// owns this machine stops depending on whose machine is running it. Its one
// caller outside this package is the shared vitest setup file, which reaches it
// by RELATIVE path — `test/setup/no-managed-settings.ts` sits at the repo root
// and is not a package, so it needs no `exports` entry to import a module. That
// is what lets the seam keep the stronger property while still being installed
// process-wide in every package that can load the overlay.
const MANAGED_SEAM = 'UNSAFE_TEST_ONLY_setManagedSettingsPaths';

/** The only shipped-source file allowed to name it: where it is defined. */
const MANAGED_DEFINITION = 'packages/persistence/src/managed-settings.ts';

/** The shared vitest setup file that installs it for every owing package. */
const MANAGED_GUARD = 'test/setup/no-managed-settings.ts';

describe(`the ${MANAGED_SEAM} test-only seam`, () => {
  it(
    'is named by exactly one shipped source file — the one that defines it',
    () => {
      const shipped = filesNamingSeam(MANAGED_SEAM)
        .filter((file) => !isTestFile(file))
        .sort();

      // An exact set of one, not a floor. A floor keeps the definition honest
      // and lets the next product caller in beside it — and a product caller is
      // the entire failure mode, since a seam something in `src/` calls is not a
      // test seam at all, it is a way for shipped code to decide which
      // administrator this machine has.
      expect(shipped).toEqual([MANAGED_DEFINITION]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it('is not re-exported from the package entry point', () => {
    // The same structural property the raw handle has, and available here for
    // the same reason: the manifest exposes `.` alone, so `src/*.ts` is
    // unreachable from another PACKAGE. Re-export it here and every consumer of
    // @akasecurity/persistence could name it, leaving the walk above as the
    // whole guarantee rather than a second line of defence.
    expect(readFileSync(join(REPO_ROOT, ENTRY), 'utf8')).not.toContain(MANAGED_SEAM);
  });

  it(
    'is installed by the shared guard, so this suite is not guarding an absence',
    () => {
      // The positive control. Delete the seam, its guard and its callers and
      // every assertion above holds perfectly, describing a workspace where the
      // thing being guarded does not exist. `isTestFile` classifies the guard
      // as test code on its `test/` segment, which is what keeps it out of the
      // shipped set above rather than an exemption written by hand.
      const tests = filesNamingSeam(MANAGED_SEAM).filter(isTestFile);
      expect(tests).toContain(MANAGED_GUARD);
      expect(tests).toContain('packages/persistence/test/managed-settings.test.ts');
    },
    TREE_WALK_TIMEOUT_MS,
  );
});

describe('isTestFile', () => {
  // The classifier decides which side of the rule a file lands on, so its own
  // edges are pinned rather than assumed. Wrong in the excusing direction and a
  // product caller is reported as a test.
  it.each([
    ['packages/persistence/test/faults/disk-full.test.ts', true],
    ['packages/persistence/test/helpers/temp-store.ts', true],
    ['cli/test/commands/exception.test.ts', true],
    ['packages/plugin-sdk/src/scan.test.ts', true],
    ['packages/persistence/src/database.ts', false],
    ['cli/src/commands/exception.ts', false],
    // A directory whose name merely starts with `test` is not a test directory.
    ['packages/testkit/src/index.ts', false],
    // The last segment is the file, never a directory — a source file called
    // `test.ts` is source.
    ['packages/persistence/src/test.ts', false],
  ])('%s -> %s', (file, expected) => {
    expect(isTestFile(file)).toBe(expected);
  });
});
