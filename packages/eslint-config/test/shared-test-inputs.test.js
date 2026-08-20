import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { LINTABLE_EXT, REPO_ROOT, toPosix, trackedFiles } from './helpers/lint-invocations.js';

// The repo-root `test/` tree is shared, and turbo cannot see that on its own.
//
// A package's default turbo `inputs` cover that package's own directory and
// nothing else, so a file a package reaches for at `../../test/<something>`
// belongs to NO task's hash unless `globalDependencies` puts it there. The
// consequence is not a stale build — it is a suite that reports green WITHOUT
// EXECUTING at the one moment it is being changed, because turbo restores a
// result computed under the old shared file. Every directory under `test/` is
// the same defect, and the entries went in one at a time as each was noticed:
// `test/setup/**`, then `test/helpers/**`, then `test/vitest/**`, then
// `test/fixtures/**` — which spent its whole life outside the hash while the
// adversarial corpus it holds was the input three walkers' guards drive.
//
// So this derives the requirement instead of listing it: whatever a package
// reaches for under the repo-root `test/` tree must be hashed into every test
// task. A fifth directory added tomorrow is covered the day it is first
// referenced, with no edit here.
//
// It lives in THIS package for the reason the other workspace-wide guards do:
// only `@akasecurity/eslint-config#test` declares `inputs` spanning the whole
// workspace (turbo.json included, asserted in coverage-config.test.js), so only
// a suite here re-runs when a DIFFERENT package grows the reference.

const ROOT_TEST_DIR = join(REPO_ROOT, 'test');

// Every relative path literal in a file, whatever syntax carries it. Matching
// the STRING rather than the import statement is deliberate: `test/vitest/` and
// `test/helpers/` arrive through `import`, while `test/setup/no-network.ts`
// arrives as the argument to `new URL(…, import.meta.url)` in every package's
// vitest config — the same dependency, and an import-only reader would miss the
// entry that has been in this list the longest.
//
// Backticks are in the quote class for the same reason, and it is the omission
// that would fail SILENTLY: a reference this cannot see is a directory this
// never requires, so the guard would report green while that directory sat
// outside every test hash — which is the exact false green it exists to stop.
//
// Matching text rather than import syntax is what reaches `new URL(…)`, and it
// is also why the segment has to be checked against the DISK below: this reader
// cannot tell a real reference from a path inside a comment, and it captures a
// template literal raw, `${…}` included. An interpolation in the FIRST segment
// therefore yields a segment like `${kind}` — a requirement no turbo entry can
// satisfy, naming a directory that cannot exist. (Past the first segment the
// literal prefix does name the directory, which is why
// `../../test/fixtures/${name}/x.ts` is read correctly as `test/fixtures`.)
const RELATIVE_LITERAL = /(['"`])(\.\.?\/[^'"`\n]*)\1/g;

/**
 * The first path segment under the repo-root `test/` tree that `file` reaches
 * for, e.g. `fixtures`. Empty for a file that reaches for nothing there.
 *
 * The literal is RESOLVED rather than pattern-matched, because the two are not
 * the same question: `packages/persistence/bench/capture.bench.ts` imports
 * `../test/helpers/corpus.ts`, which is that package's OWN test tree and no
 * business of this guard. A substring reader counts it and reports a
 * requirement that does not exist.
 */
function rootTestSegments(file) {
  const dir = dirname(join(REPO_ROOT, file));
  const segments = new Set();
  for (const [, , specifier] of readFileSync(join(REPO_ROOT, file), 'utf8').matchAll(
    RELATIVE_LITERAL,
  )) {
    // `relative` rather than a prefix test on the string: the two disagree on
    // win32, where `resolve` hands back backslashes and a `startsWith('…/test/')`
    // matches nothing at all — which would report an empty requirement set and
    // pass.
    const rest = toPosix(relative(ROOT_TEST_DIR, resolve(dir, specifier)));
    const first = rest.split('/')[0];
    // `''` is the directory itself and `'..'` is anything above it — including
    // the bare `..` a literal resolving to the repo root produces, which is not
    // the same string as a `../`-PREFIXED one and slips a `test/../**`
    // requirement past a prefix test.
    if (!first || first === '..') continue;
    // It must be a directory that EXISTS. A reader matching text rather than
    // imports otherwise manufactures requirements nothing can meet — `${kind}`
    // from an interpolated literal, or a path quoted inside a comment — and
    // each one fails this suite demanding a globalDependencies entry that the
    // "names a directory that exists" case below would then reject. A reference
    // to a directory that is not there cannot be a real dependency anyway.
    //
    // The residue, stated rather than hidden: the real directory an
    // interpolation ranges over goes unguarded. Nothing short of evaluating the
    // expression can recover it.
    if (!existsSync(join(ROOT_TEST_DIR, first))) continue;
    segments.add(first);
  }
  return segments;
}

/** Every repo-root `test/` subdirectory some file outside `test/` reaches for. */
function referencedSegments() {
  const found = new Map();
  for (const file of trackedFiles()) {
    if (!LINTABLE_EXT.test(file)) continue;
    // Files INSIDE the shared tree reach for their own siblings constantly, and
    // those references say nothing about which package needs which directory.
    if (file === 'test' || file.startsWith('test/')) continue;
    for (const segment of rootTestSegments(file)) {
      const seen = found.get(segment);
      if (seen) seen.push(file);
      else found.set(segment, [file]);
    }
  }
  return found;
}

const TURBO = JSON.parse(
  // turbo.json carries comments (jsonc). Strip line comments before parsing —
  // block comments are not used in it, and a regex that tried to handle them
  // would eat the `**/*` globs.
  readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8').replace(/^\s*\/\/.*$/gm, ''),
);

describe('the shared repo-root test tree is hashed into every test task', () => {
  const referenced = referencedSegments();

  it('reads a relative path out of every quoting form', () => {
    // The reader's own unit case, and it exists because the alternative is a
    // guarantee nothing can falsify: no file in the tree happens to reach for
    // the shared tree with a backtick today, so narrowing this regex back to
    // `['"]` would leave every other assertion in this suite green while the
    // directory it stopped seeing sat outside every test hash.
    const forms = [
      String.raw`import x from '../../test/setup/no-network.ts';`,
      String.raw`new URL("../../test/vitest/coverage.ts", import.meta.url)`,
      'new URL(`../../test/helpers/remove-tree.ts`, import.meta.url)',
    ];
    for (const src of forms) {
      const found = [...src.matchAll(RELATIVE_LITERAL)].map((m) => m[2]);
      expect(found, `no relative literal read out of: ${src}`).toHaveLength(1);
      expect(found[0]).toMatch(/^\.\.\/\.\.\/test\//);
    }
    // The negative control: a bare word in quotes is not a relative path, so a
    // regex loose enough to match everything would fail here rather than
    // silently demanding a globalDependencies entry for every string in the
    // repo.
    expect([...String.raw`import x from 'vitest';`.matchAll(RELATIVE_LITERAL)]).toEqual([]);
  });

  it('manufactures no requirement a turbo entry could not satisfy', () => {
    // Both phantom classes, driven through the real reader. Without the
    // on-disk check each of these demands an entry naming a directory that does
    // not exist — which no edit to turbo.json can satisfy, because the "names a
    // directory that exists" case below would then reject it.
    const phantom = [
      'new URL(`../../../test/${kind}/index.ts`, import.meta.url)',
      "// see '../../../test/phantom/thing.ts' for details",
    ];
    for (const src of phantom) {
      const found = [...src.matchAll(RELATIVE_LITERAL)].map((m) => m[2]);
      expect(found, `nothing was read out of: ${src}`).toHaveLength(1);
      const rest = toPosix(
        relative(ROOT_TEST_DIR, resolve(REPO_ROOT, 'packages/x/test', found[0])),
      );
      const first = rest.split('/')[0];
      expect(existsSync(join(ROOT_TEST_DIR, first)), `${first} would be demanded`).toBe(false);
    }
    // The positive control: a REAL shared directory still resolves and still
    // exists, so the check above rejects phantoms without rejecting everything.
    expect(existsSync(join(ROOT_TEST_DIR, 'fixtures'))).toBe(true);
  });

  it('finds the references it is derived from', () => {
    // The vacuity control. The assertion below is "each directory found is
    // covered", which a reader that finds NOTHING satisfies perfectly — and it
    // would, on one mangled regex or a resolve that stopped agreeing with the
    // tree. These four are what the repo has today; it is a floor rather than a
    // pin, because a fifth appearing is the case this suite exists to handle
    // and not a reason to fail.
    for (const segment of ['setup', 'helpers', 'vitest', 'fixtures']) {
      expect(
        referenced.get(segment),
        `nothing outside test/ was found reaching for test/${segment}/ — the reader is broken, ` +
          `so the coverage assertion holds vacuously`,
      ).toBeDefined();
    }
  });

  it('every referenced directory is in globalDependencies', () => {
    // Collected rather than asserted one at a time, so a run names every
    // uncovered directory instead of the first.
    const uncovered = [...referenced]
      .filter(([segment]) => !TURBO.globalDependencies.includes(`test/${segment}/**`))
      .map(
        ([segment, files]) =>
          `test/${segment}/** — reached for by ${String(files.length)} file(s), e.g. ${String(files[0])}`,
      );
    expect(
      uncovered,
      'an edit to these moves no test task hash, so every suite driving them replays a cached ' +
        'green taken under the OLD file',
    ).toEqual([]);
  });

  it('every globalDependencies entry under test/ names a directory that exists', () => {
    // A typo is the failure mode this catches, and it is invisible from the
    // other direction: `test/fixture/**` reads exactly like coverage and hashes
    // nothing at all, so the suite it was meant to protect goes on replaying
    // cached greens with the entry sitting right there in the file.
    for (const entry of TURBO.globalDependencies) {
      if (!entry.startsWith('test/')) continue;
      const dir = join(REPO_ROOT, entry.replace(/\/\*\*$/, ''));
      expect(existsSync(dir), `${entry} names no directory`).toBe(true);
    }
  });
});
