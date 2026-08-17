import { writeFileSync } from 'node:fs';
import { join, sep } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  createHostileRepo,
  deepChain,
  dotDotNames,
  flatFiles,
  gitignorePerDirectory,
  type HostileRepo,
  ignoredSubtree,
  ignoreEverything,
  nestedGitignoreChain,
  symlinkLoops,
} from '../../../../test/fixtures/adversarial/hostile-repo/index.ts';
import { walkTree } from '../../src/walk.ts';

// The worktree scanner's file discovery against the adversarial corpus.
//
// Every file-discovery walk in this package goes through `walkTree` —
// `walkSourceFiles` and the manifest walk alike — so a tree that traps it traps
// `/aka:scan`. The corpus is shared with the inventory walk and the dashboard's
// folder scan for exactly that reason, and until now only the inventory walk
// drove it: the symlink-loop, deep-chain and ignore-everything shapes had never
// been run against this walker at all.
//
// WHAT THIS TIER ASSERTS. Termination and shape, not a duration — the durations
// live in `bench/walk.bench.ts`, which is advisory.
//
// The budget rows at the bottom are the exception, and it is worth being exact
// about what they can and cannot catch, because the obvious reading is wrong.
// They are sized the way the rest of the repo sizes a timing assertion — the
// estimator is the FASTEST of several passes, since noise only ever adds time —
// and what they detect is a walk that stopped TERMINATING or got an order of
// magnitude slower. They do NOT gate the offset representation those rows were
// added alongside: that change measured 1,312 ms -> 432 ms on the nested row
// here (arm64 Mac, fastest of three), a ~3x CONSTANT factor, and both figures
// sit inside any budget loose enough to survive a contended runner. The
// complexity is unchanged by it and stays O(entries x layers), which is why the
// depth-200 row costs ~3.4x the depth-100 one before and after alike. Nothing
// in this tier can hold a 3x constant factor honestly; the bench is where it is
// tracked.
//
// `trackGitignore: true` throughout, because that is the mode `walkSourceFiles`
// asks for and the only one that accumulates a `.gitignore` layer per
// directory. In the default mode no `.gitignore` is read at all, so every
// assertion about layered evaluation would hold vacuously.

let repo: HostileRepo | undefined;

afterEach(() => {
  repo?.cleanup();
  repo = undefined;
});

const fresh = (prefix?: string): HostileRepo => {
  repo = createHostileRepo(prefix);
  return repo;
};

/** Ceiling for a case whose fixture is thousands of files — see project-files-walk.test.ts. */
const FIXTURE_TIMEOUT_MS = 120_000;

/** The fastest of `runs` passes: noise only ever adds time, so the minimum is the closest a loaded machine gets to the code's own cost. */
function fastestOf(runs: number, body: () => void): number {
  body();
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const started = performance.now();
    body();
    best = Math.min(best, performance.now() - started);
  }
  return best;
}

const walk = (root: string) => [...walkTree(root, { trackGitignore: true })];

/** Walked paths as posix, relative to the walk root — what the assertions read. */
const relPaths = (root: string): string[] =>
  walk(root).map((f) =>
    f.path
      .slice(root.length + 1)
      .split(sep)
      .join('/'),
  );

describe('the worktree walk terminates on a hostile tree', () => {
  it('a symlink loop does not trap the walk', (ctx) => {
    const r = fresh();
    const shape = symlinkLoops(r);
    if (!shape.created) ctx.skip(shape.reason);

    const paths = relPaths(r.root);

    // Reaching this line at all is most of the assertion: a walk that followed
    // `a/to-root` would revisit the root forever and never return.
    //
    // The positive control comes first. Without it a walk that returned nothing
    // would satisfy every absence check below.
    expect(paths).toContain('a/real.ts');
    expect(paths).toContain('b/real.ts');
    // Dirent types are lstat-based, so a link is neither file nor directory and
    // falls through. Nothing may be recorded THROUGH one.
    expect(paths.filter((p) => p.includes('to-root'))).toEqual([]);
    expect(paths.filter((p) => p.includes('to-self'))).toEqual([]);
    expect(paths.filter((p) => p.includes('to-a') || p.includes('to-b'))).toEqual([]);
    expect(paths).not.toContain('dangling');
  });

  it('nesting deeper than a path can address does not overflow the stack', (ctx) => {
    const r = fresh();

    const chain = deepChain(r);
    // GATED, not asserted: `created: false` is how the corpus reports a shape
    // this platform refused to build, and turning that into a failed assertion
    // would blame the walker for something the filesystem decided.
    if (!chain.created) ctx.skip(chain.reason);
    // A depth that fell short ON THE BUDGET says the runner was busy, not that
    // the platform stopped it — a wall clock must not decide a correctness
    // assertion, so that case skips while the floor below still fires for every
    // non-timing reason.
    if (chain.budgetSpent && chain.addressable <= 50) {
      ctx.skip(`${chain.reason} — a contended runner, not a walker defect`);
    }
    expect(
      chain.addressable,
      'no addressable depth at all — every assertion below would hold vacuously',
    ).toBeGreaterThan(50);

    // A marker the walk can only reach by recursing to it. Sixteen levels short
    // of the ceiling, because the ceiling is the deepest addressable DIRECTORY
    // and this appends a filename to one.
    let marker = r.root;
    for (let i = 0; i < chain.addressable - 16; i++) marker = join(marker, 'd');
    writeFileSync(join(marker, 'm.ts'), 'x');

    const paths = relPaths(r.root);

    // Returning at all is the headline: that many frames of recursion, and no
    // RangeError.
    expect(paths.some((p) => p.endsWith('/m.ts'))).toBe(true);
  });

  it('a gitignore that ignores everything marks every file instead of dropping it', () => {
    const r = fresh();
    ignoreEverything(r);

    const files = walk(r.root);

    // The difference from the inventory walk, pinned rather than assumed: a `*`
    // .gitignore leaves that walk with nothing and this one with everything,
    // because a gitignored file is where a secret is MOST likely to be. What the
    // layer decides here is provenance, and the scan still runs.
    expect(files.map((f) => f.name)).toContain('index.ts');
    for (const file of files) {
      expect(file.gitignored, `${file.path} lost its gitignored provenance`).toBe(true);
    }
  });

  it('a directory the gitignore names is still walked, and everything under it marked', () => {
    const r = fresh();
    ignoredSubtree(r, 12);

    const byRel = new Map(
      walk(r.root).map((f) => [
        f.path
          .slice(r.root.length + 1)
          .split(sep)
          .join('/'),
        f,
      ]),
    );

    // `vendor-cache/` is named by the root .gitignore. The inventory walk never
    // opens it; this one descends and marks — so the entries below are the
    // positive control for a walk that really did go in, and the flag is what
    // separates "walked it" from "walked it and forgot why".
    expect(byRel.get('index.ts')?.gitignored).toBe(false);
    const inside = [...byRel.keys()].filter((p) => p.startsWith('vendor-cache/'));
    expect(inside.length).toBe(12);
    for (const rel of inside) expect(byRel.get(rel)?.gitignored).toBe(true);
  });

  it('names containing .. never produce a path that climbs out of the root', () => {
    const r = fresh();
    dotDotNames(r);

    const paths = relPaths(r.root);

    // Unlike the folder scan, this walker has no dot-directory floor — only
    // SKIP_DIRS — so `..nested` IS descended into. Pinned because the two
    // walkers disagreeing on one fixture reads like a bug in whichever one you
    // looked at second.
    expect(paths).toContain('weird/..hidden.ts');
    expect(paths).toContain('weird/..nested/inner.ts');
    for (const path of paths) {
      expect(path.split('/'), `${path} carries a .. segment`).not.toContain('..');
    }
  });
});

describe('the worktree walk stays inside its budget', () => {
  // `files` is the CONTROL, per row: every assertion here is an upper bound on
  // elapsed time, and a walk that stopped early satisfies one more easily than
  // a walk that finished — faster, even, for having quit.
  const ROWS = [
    {
      label: '5k files',
      budgetMs: 2_000,
      files: 5_000,
      build: (r: HostileRepo) => {
        flatFiles(r, 5_000);
      },
    }, // 4.5 ms
    {
      // 1,000 directories x (2 source files + the .gitignore itself). Two layers
      // apply to any entry however many directories there are — the cheap
      // arrangement, and the control for the expensive one below.
      label: '1k sibling directories each with a .gitignore',
      budgetMs: 3_000,
      files: 3_000,
      build: (r: HostileRepo) => {
        gitignorePerDirectory(r, 1_000);
      },
    }, // 41.6 ms
  ] as const;

  it.each(ROWS.map((row) => [row.label, row] as const))(
    '%s',
    (_label, row) => {
      const r = fresh();
      row.build(r);

      let files = 0;
      const ms = fastestOf(3, () => {
        files = walk(r.root).length;
      });

      expect(files, "the walk did not return this row's whole tree").toBe(row.files);
      expect(ms).toBeLessThan(row.budgetMs);
    },
    FIXTURE_TIMEOUT_MS,
  );

  it(
    '100 nested directories, one .gitignore each, 2k files',
    (ctx) => {
      const r = fresh();
      // THE shape this walker's layered evaluation was quadratic in: layers
      // ACCUMULATE down the tree, so each bottom file is tested against `depth`
      // of them where a sibling arrangement tests it against two. The patterns
      // are unique per level so none of them matches — the case where no layer
      // can answer and every one is consulted, which is what a deepest-first
      // lookup cannot short-circuit and only the offset representation makes
      // cheap.
      //
      // Depth 100 rather than 400: Windows' default MAX_PATH stops this chain
      // around there, and a row that silently builds a shallower tree measures
      // a different shape while reading like this one.
      const chain = nestedGitignoreChain(r, 100, 2_000);
      if (chain.depth < 50) ctx.skip(`${chain.reason} — too shallow to be this shape`);

      let files = 0;
      const ms = fastestOf(3, () => {
        files = walk(r.root).length;
      });

      // 2,000 leaf files plus one .gitignore per level. The count is the control
      // and the reason the budget below means anything.
      expect(files).toBe(2_000 + chain.depth);
      // Measured 432 ms at depth 100 on an arm64 Mac, fastest of three. The
      // budget carries ~11x headroom, which is a hang detector and not a
      // regression detector — see the header: the pre-port form measured
      // 1,312 ms here and would pass this too.
      expect(ms).toBeLessThan(5_000);
    },
    FIXTURE_TIMEOUT_MS,
  );
});
