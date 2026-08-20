/**
 * What the SessionStart project walk costs, by tree shape.
 *
 * `resolveProjectFiles()` is a full recursive SYNCHRONOUS walk that runs inside
 * the hosts' 10 s hook timeout, and the consequence of blowing it differs per
 * host: Claude Code and Codex read a killed hook as "no opinion" and lose the
 * inventory, while Antigravity reads it as a DENY — and it runs this pass from
 * `PreInvocation`, so a walk that outruns the host blocks the user's tool call.
 * A synchronous body never yields, so no watchdog can preempt it. That is why
 * this file measures shapes an attacker chooses rather than only the ones a
 * colleague commits.
 *
 * `MAX_FILES = 20_000` bounds KEPT files, not traversal — which is the whole
 * reason the ignored-tree rows below exist at two very different costs, and why
 * traversal carries its own bound (`PROJECT_WALK_BOUNDS`: a depth cap and a
 * deadline). Every row here runs UNDER that bound, so a row is a measurement of
 * the bounded walk and not of the shape it refuses.
 *
 * NO ASSERTIONS. A hosted runner varies by a large factor on neighbour load
 * alone, so the numbers are tracked here and the PROPERTIES are asserted in
 * `test/performance/project-files-walk.test.ts`, which gates PRs on termination
 * and shape instead of on a duration.
 *
 * TWO THINGS VITEST DOES IN BENCH MODE THAT IT DOES NOT DO IN TEST MODE, both of
 * which this file is built around because both fail SILENTLY:
 *
 *   - `beforeAll` / `afterAll` / `beforeEach` / `afterEach` DO NOT RUN. Fixtures
 *     are therefore built from each bench's own `setup`, which does run — once
 *     per mode, `warmup` then `run`. They are built ONCE and cached across both,
 *     because several of these trees cost more to create than to walk (the 500k
 *     rows take ~26 s each), and removed from the `run` teardown only.
 *   - A bench body that THROWS is swallowed: exit 0, no FAIL, and the row is
 *     rendered as "NaNx faster" than its neighbours. The control below is
 *     therefore at module scope, where a throw does produce a FAIL.
 */
import { bench, describe } from 'vitest';

import {
  createHostileRepo,
  deepChain,
  flatFiles,
  gitignorePerDirectory,
  type HostileRepo,
  ignoredByPattern,
  ignoredSubtree,
  nestedGitignoreChain,
  symlinkLoops,
} from '../../../test/fixtures/adversarial/hostile-repo/index.ts';
import { resolveProjectFiles } from '../src/project-files.ts';

// The control, at module scope. Every row below is "how long did a walk take",
// and a walk that returns nothing is instant — so prove the walker works at all
// before believing any number it produces.
{
  const repo = createHostileRepo('aka-bench-control-');
  try {
    flatFiles(repo, 32);
    const scan = resolveProjectFiles(repo.root);
    if (scan?.files.length !== 32) {
      throw new Error(
        `expected the walk to find 32 files in a trivial repo, got ` +
          `${scan === undefined ? 'undefined' : String(scan.files.length)} — every row below ` +
          `would otherwise be measuring a walk that does nothing and reporting it as a win.`,
      );
    }
  } finally {
    repo.cleanup();
  }
}

// Every tree this file builds, so an exit that skips the per-bench teardown does
// not leave one behind. `afterAll` does not run in bench mode (see the header)
// and the teardown below only fires on the TIMED pass, so an interrupted run, a
// `-t` filter, or a row whose body threw would otherwise strand the tree — and
// two of these are 500k files each.
const live = new Set<HostileRepo>();
process.on('exit', () => {
  for (const repo of live) {
    try {
      repo.cleanup();
    } catch {
      // Exiting anyway; a temp dir left behind beats a throw from an exit hook.
    }
  }
  live.clear();
});

/**
 * One lazily-built tree, shared by a bench's warmup and timed passes and removed
 * after the timed one. Several of these cost more to build than to walk, so
 * rebuilding per mode would double the suite's runtime for no signal.
 */
function fixture(build: (repo: HostileRepo) => void) {
  let repo: HostileRepo | undefined;
  return {
    setup: () => {
      if (repo) return;
      repo = createHostileRepo('aka-bench-');
      live.add(repo);
      build(repo);
    },
    teardown: (_task: unknown, mode: 'run' | 'warmup') => {
      if (mode !== 'run') return;
      if (repo) {
        live.delete(repo);
        repo.cleanup();
      }
      repo = undefined;
    },
    walk: () => {
      if (repo) resolveProjectFiles(repo.root);
    },
  };
}

/**
 * A row. `iterations`/`time` are set low on the expensive shapes on purpose:
 * vitest otherwise repeats a body for its default window, and a 1.6 s walk
 * repeated for 500 ms of "warmup" plus 500 ms of measurement is several minutes
 * of wall clock for a number the first pass already gave.
 */
function row(
  label: string,
  build: (repo: HostileRepo) => void,
  opts: { iterations?: number; time?: number } = {},
): void {
  const f = fixture(build);
  bench(label, f.walk, {
    setup: f.setup,
    teardown: f.teardown,
    time: opts.time ?? 1_000,
    iterations: opts.iterations ?? 5,
    warmupIterations: 1,
    warmupTime: 0,
  });
}

describe('by repository size', () => {
  // Budget ≤ 200 ms. Measured 0.11 ms.
  row('100 files', (r) => {
    flatFiles(r, 100);
  });
  // Budget ≤ 1,000 ms. Measured 3.5 ms.
  row('5k files', (r) => {
    flatFiles(r, 5_000);
  });
  // Budget ≤ 3,000 ms. Measured 14.0 ms. This is MAX_FILES, so the walk stops
  // here however many more files exist.
  row('20k files (the kept-file cap)', (r) => {
    flatFiles(r, 20_000);
  });
});

describe('a monorepo whose bulk is gitignored', () => {
  // The two halves of "500k gitignored files", and they differ by three orders
  // of magnitude. Budget ≤ 5,000 ms covers both.
  //
  // Ignored by DIRECTORY, the layer answers at the directory itself and the
  // subtree is never opened: measured 0.034 ms for 500k files behind one rule.
  row(
    '500k files under an ignored directory',
    (r) => {
      ignoredSubtree(r, 500_000);
    },
    { iterations: 3 },
  );
  // Ignored by PATTERN, every one of them comes back from a `readdir` and is
  // tested before being dropped. This is the honest cost of "traversal is
  // unbounded", and the row worth watching: measured 522 ms for 500k files.
  row(
    '500k files ignored by pattern (each one traversed)',
    (r) => {
      ignoredByPattern(r, 500_000);
    },
    { iterations: 3 },
  );
});

describe('many .gitignore files', () => {
  // The two arrangements of "1,000 directories each with a .gitignore" against
  // one budget of ≤ 3,000 ms. They are not close.
  //
  // SIBLINGS: two layers apply to any entry, however many directories there
  // are. Measured 39 ms — comfortably inside budget.
  row('1k sibling directories, one .gitignore each', (r) => {
    gitignorePerDirectory(r, 1_000);
  });

  // NESTED: layers accumulate, so an entry at depth D is tested against D of
  // them. This is the shape that used to miss the budget, and it missed it by a
  // lot — 469 / 1,556 / 5,819 ms at depth 100 / 200 / 400 over 2,000 files, with
  // a direct run at depth 400 over 5,000 files measuring 13.0 s and 645 MB, past
  // the hosts' 10 s hook timeout on a tree of 5,400 files.
  //
  // It is now bounded (PROJECT_WALK_BOUNDS), and what these rows track is that
  // the bound still holds rather than what the shape costs: all three measure
  // ~7 ms, because the walk stops at maxDepth and the depth below it no longer
  // reaches the cost. A row here climbing back toward a second is the signal —
  // the bound was raised, or something started descending past it.
  //
  // The rows are kept at three depths for that reason, even though the bound
  // makes them nearly identical: a single row cannot show that the cost stopped
  // growing WITH depth, which is the property, and three rows that diverge say
  // where it started growing again.
  //
  // A 1,000-deep chain is not a row here because it cannot be walked on macOS at
  // all: `PATH_MAX` stops an absolute path at depth 476, measured (see
  // addressableDepth); the same arithmetic over Linux's 4096 puts it near 2,000.
  // The depths below are what this platform permits.
  for (const depth of [100, 200, 400]) {
    row(
      `${String(depth)} nested directories, one .gitignore each, 2k files`,
      (r) => {
        nestedGitignoreChain(r, depth, 2_000);
      },
      { iterations: 3 },
    );
  }
});

describe('hostile shapes', () => {
  // Terminating at all is the property; the number just says what it costs.
  row('symlink loops (root, self, mutual, dangling)', (r) => {
    symlinkLoops(r);
  });

  // Deep nesting, to the deepest directory an absolute path can address and a
  // few long-named levels past it — 476 + 2 on an arm64 Mac. A literal
  // 10,000-level chain is deliberately NOT built: it is unreachable by a walk
  // that opens directories absolutely, and a chdir descent that deep costs
  // ~348 s to build and ~347 s to remove.
  // The label is a claim about what got built, so it is printed only when the
  // shape says it built it. A pool without `process.chdir` leaves the
  // past-the-ceiling half unmade, and a bench carries no assertions to notice.
  row('nesting past the deepest addressable directory', (r) => {
    const chain = deepChain(r);
    if (!chain.created || !chain.unaddressable) {
      // stderr rather than a thrown error: the header notes vitest swallows a
      // throw from a bench body, so raising one here would be silent.
      process.stderr.write(
        `[bench] "nesting past the deepest addressable directory" measured ` +
          `${String(chain.addressable)} addressable levels only — nothing past the ` +
          `ceiling was built: ${chain.reason}\n`,
      );
    }
  });
});
