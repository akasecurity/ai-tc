import { readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

import { describe, expect, it } from 'vitest';

import { lintableTrackedFiles, REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

// `@akasecurity/persistence` carries a directory of sample datasets —
// `src/test-fixtures/` — that exists only for this repository's own tests and
// benchmarks. It sits under `src/` and the package is inlined into four
// published artifacts by `noExternal: [/^@akasecurity\//]`, so ONE product
// import of it puts the whole sample dataset plus the corpus generator into the
// CLI and all three plugins.
//
// What keeps that from happening today is that `src/index.ts` does not
// re-export the directory and the manifest exposes `.` alone — a property any
// one line can undo. Until this suite existed the rule was stated in a comment
// at the top of `src/test-fixtures/index.ts` and checked by nobody, and it had
// already drifted: the comment named `*.test.ts` and `*.bench.ts` while the
// first non-spec importer, `test/helpers/corpus.ts`, was neither.
//
// So the rule is derived from the tracked tree rather than listed. It lives in
// this package for the reason the seam audit next door gives: only this task's
// turbo `inputs` hash the whole workspace, so the same check inside
// `persistence` would replay a cached green while an importer appeared in
// `cli/src`.

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

/** The directory that must not reach a shipped bundle. */
const FIXTURES = 'packages/persistence/src/test-fixtures';

/** The package entry point that must not re-export it. */
const ENTRY = 'packages/persistence/src/index.ts';
const MANIFEST = 'packages/persistence/package.json';

/** The importer that made the old comment false — the positive control. */
const HELPER = 'packages/persistence/test/helpers/corpus.ts';

/**
 * Module specifiers a file imports, in source order.
 *
 * Covers the five forms the tree uses: `import … from`, `export … from`, a bare
 * side-effect `import`, dynamic `import()`, and `require()`.
 * @param {string} text file contents
 */
function importSpecifiers(text) {
  return [...text.matchAll(/\b(?:from|import|require)\b\s*\(?\s*['"]([^'"]+)['"]/g)].map(
    (m) => m[1],
  );
}

/**
 * True for a path allowed to import the fixtures.
 *
 * A `test`/`tests`/`bench` path segment, a `.test.`/`.spec.`/`.bench.` basename,
 * or a file inside the fixture directory itself (its own modules import each
 * other). Anything else counts as shipped source, which is the safe direction to
 * be wrong in.
 *
 * Deliberately NOT `isTestFile` from the seam audit, which this otherwise
 * mirrors. That predicate rejects `.bench.ts`, correctly — a benchmark may not
 * read the raw-handle seam — while a benchmark may import fixtures, which is
 * the entire reason the directory has a generator in it. Two different
 * questions, so two different predicates rather than one widened until it
 * answers both.
 * @param {string} file repo-relative posix path
 */
function mayImportFixtures(file) {
  if (file === FIXTURES || file.startsWith(`${FIXTURES}/`)) return true;
  const segments = file.split('/');
  return (
    segments.slice(0, -1).some((s) => s === 'test' || s === 'tests' || s === 'bench') ||
    /\.(test|spec|bench)\./.test(posix.basename(file))
  );
}

/** Every tracked lintable file that imports something inside the fixture dir. */
function filesImportingFixtures() {
  return lintableTrackedFiles().filter((file) => {
    // A tracked path can still be unreadable — a submodule gitlink, a symlink
    // to nowhere. Skipping one silently would drop a file out of the audit
    // without anyone noticing, so this throws instead.
    let text;
    try {
      text = readFileSync(join(REPO_ROOT, file), 'utf8');
    } catch (cause) {
      throw new Error(`Could not read tracked file ${file} while auditing ${FIXTURES}.`, { cause });
    }

    const dir = posix.dirname(file);
    return importSpecifiers(text).some((spec) => {
      // Relative specifiers are resolved against the importer rather than
      // substring-matched, so a path reaching the directory by another route is
      // still caught and an unrelated directory of the same name is not. A bare
      // specifier cannot reach it at all while the manifest below stays closed.
      //
      // It also means a file merely NAMING the directory in prose is not an
      // importer: `test/migrations.test.ts` mentions `test-fixtures/sample-ids.ts`
      // in a comment and imports nothing from here. A grep for the directory name
      // counts it, which is how the count in this suite's own history came out
      // one too high.
      if (!spec.startsWith('.')) return false;
      const resolved = posix.normalize(posix.join(dir, spec));
      return resolved === FIXTURES || resolved.startsWith(`${FIXTURES}/`);
    });
  });
}

describe('the test-and-benchmark-only fixture directory', () => {
  it(
    'is imported only from test and bench code',
    () => {
      const shipped = filesImportingFixtures()
        .filter((file) => !mayImportFixtures(file))
        .sort();

      // An exact empty set, not a floor. A product importer anywhere in the
      // workspace is the entire failure mode, and it ships the dataset in four
      // artifacts the moment it lands.
      expect(shipped).toEqual([]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'is imported by tests and by the benchmark helper, so this is not guarding an absence',
    () => {
      const importers = filesImportingFixtures();

      // The positive control. Delete the directory and its consumers and the
      // assertion above holds perfectly — on a workspace where the thing being
      // guarded does not exist. `HELPER` is named specifically because it is the
      // importer the old comment failed to describe: a rule that stopped covering
      // helpers would go green here rather than quietly reverting.
      expect(importers.length).toBeGreaterThan(0);
      expect(importers).toContain(HELPER);
      expect(importers).toContain('packages/persistence/test/repositories/activity.test.ts');
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it('is not re-exported from the package entry point', () => {
    const entry = readFileSync(join(REPO_ROOT, ENTRY), 'utf8');

    // What makes the rule structural rather than a request. The manifest below
    // exposes `.` alone, so the directory is unreachable from another package —
    // re-export it here and every consumer of `@akasecurity/persistence` can
    // import the dataset, at which point no rule about THIS repo helps.
    const reachesFixtures = importSpecifiers(entry).some((spec) =>
      posix.normalize(posix.join(posix.dirname(ENTRY), spec)).startsWith(`${FIXTURES}/`),
    );
    expect(reachesFixtures).toBe(false);
  });

  it('is unreachable from outside the package: no exports subpath resolves into it', () => {
    const { exports: map } = JSON.parse(readFileSync(join(REPO_ROOT, MANIFEST), 'utf8'));
    const entries = Object.entries(map);

    expect(entries.length).toBeGreaterThan(0);
    for (const [subpath, target] of entries) {
      // A wildcard subpath (`"./*": "./src/*"`) would expose every module in the
      // package, this directory included, without ever naming it.
      expect(subpath).not.toContain('*');
      expect(JSON.stringify(target)).not.toContain('*');
      expect(JSON.stringify(target)).not.toContain('test-fixtures');
    }
  });

  it(
    'reads a tree it really walked',
    () => {
      // `trackedFiles()` returning nothing would make every assertion above pass
      // by describing an empty workspace — the failure mode a git-backed walk has
      // and a hardcoded list does not.
      expect(trackedFiles()).toContain(`${FIXTURES}/index.ts`);
      expect(lintableTrackedFiles()).toContain(HELPER);
    },
    TREE_WALK_TIMEOUT_MS,
  );
});

describe('mayImportFixtures', () => {
  // The classifier decides which side of the rule a file lands on, so its own
  // edges are pinned rather than assumed. Wrong in the excusing direction and a
  // product importer is reported as a test.
  it.each([
    ['packages/persistence/test/helpers/corpus.ts', true],
    ['packages/persistence/test/migrations.test.ts', true],
    // A benchmark may import fixtures. This is the case the seam audit's
    // `isTestFile` answers the other way, and the reason this predicate exists.
    ['packages/persistence/bench/corpus.bench.ts', true],
    ['packages/detections/bench/rules.bench.ts', true],
    // The directory's own modules import each other.
    ['packages/persistence/src/test-fixtures/generate.ts', true],
    ['packages/persistence/src/database.ts', false],
    ['packages/persistence/src/index.ts', false],
    ['cli/src/commands/dashboard.ts', false],
    ['web-ui/app/lib/db.ts', false],
    // A directory whose name merely starts with `bench` is not a bench
    // directory, and one merely starting with `test` is not a test directory.
    ['packages/benchmarks/src/index.ts', false],
    ['packages/testkit/src/index.ts', false],
    // The last segment is the file, never a directory — a source file called
    // `bench.ts` is source.
    ['packages/persistence/src/bench.ts', false],
  ])('%s -> %s', (file, expected) => {
    expect(mayImportFixtures(file)).toBe(expected);
  });
});
