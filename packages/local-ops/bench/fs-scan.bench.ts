/**
 * What the dashboard's folder scan costs to WALK, by tree shape.
 *
 * `collectFiles()` is the discovery half of `scanPathIntoStore` — a full
 * recursive synchronous walk of a folder the user picked on the Scan page. It
 * runs inside a Next Server Action, so the failure mode is a request that never
 * answers rather than a hook the host kills; the tree that produces it is the
 * same one, which is why this drives the shared adversarial corpus rather than a
 * private fixture.
 *
 * TWO stacks descend here, not one — `.gitignore` (mark) and `.akaignore`
 * (skip) — so every entry pays the layered evaluation twice. That is the cost
 * these rows exist to track.
 *
 * NO ASSERTIONS, and no PR gate. A hosted runner varies by a large factor on
 * neighbour load alone; the PROPERTIES are asserted in
 * `test/performance/fs-scan-walk.test.ts`.
 *
 * TWO THINGS VITEST DOES IN BENCH MODE THAT IT DOES NOT DO IN TEST MODE, both of
 * which this file is built around because both fail SILENTLY:
 *
 *   - `beforeAll` / `afterAll` / `beforeEach` / `afterEach` DO NOT RUN. Fixtures
 *     are built from each bench's own `setup`, which does run — once per mode,
 *     `warmup` then `run` — and cached across both, because several of these
 *     trees cost more to create than to walk.
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
import { collectFiles } from '../src/fs-scan.ts';

// Counted through the iterator rather than a `for…of`, which would bind a
// variable nothing reads — the walk is what is being measured, not the entries.
const drain = (root: string): number => {
  const walked = collectFiles(root);
  let n = 0;
  while (walked.next().done !== true) n++;
  return n;
};

// The control, at module scope. Every row below is "how long did a walk take",
// and a walk that returns nothing is instant — so prove the walker works at all
// before believing any number it produces.
{
  const repo = createHostileRepo('aka-bench-control-');
  try {
    flatFiles(repo, 32);
    const found = drain(repo.root);
    if (found !== 32) {
      throw new Error(
        `expected the walk to find 32 files in a trivial repo, got ${String(found)} — every row ` +
          `below would otherwise be measuring a walk that does nothing and reporting it as a win.`,
      );
    }
  } finally {
    repo.cleanup();
  }
}

// Every tree this file builds, so an exit that skips the per-bench teardown does
// not leave one behind: `afterAll` does not run in bench mode, and the teardown
// below only fires on the TIMED pass.
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
      if (repo) drain(repo.root);
    },
  };
}

/**
 * A row. `iterations`/`time` are set low on the expensive shapes on purpose:
 * vitest otherwise repeats a body for its default window, which turns a
 * second-long walk into minutes of wall clock for a number the first pass
 * already gave.
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

describe('by folder size', () => {
  row('100 files', (r) => {
    flatFiles(r, 100);
  });
  row('5k files', (r) => {
    flatFiles(r, 5_000);
  });
  row('20k files', (r) => {
    flatFiles(r, 20_000);
  });
});

describe('a folder whose bulk is gitignored', () => {
  // The inventory walk gets these two nearly free — it SKIPS a gitignored
  // directory outright, so the by-directory row never opens the subtree. This
  // walker MARKS instead: a gitignored file is where a secret is most likely to
  // be, so both arrangements are fully traversed and both are stat'd. The
  // by-directory row is therefore the one that differs by orders of magnitude
  // between the two walkers, and it belongs here for exactly that reason.
  //
  // 100k rather than the inventory bench's 500k: the two rows there cost ~26 s
  // each to BUILD, this walker adds a `statSync` per surviving file, and the
  // shape is what these rows are for.
  row(
    '100k files under an ignored directory (marked, not skipped)',
    (r) => {
      ignoredSubtree(r, 100_000);
    },
    { iterations: 3 },
  );
  row(
    '100k files ignored by pattern (each one traversed)',
    (r) => {
      ignoredByPattern(r, 100_000);
    },
    { iterations: 3 },
  );
});

describe('many .gitignore files', () => {
  // The two arrangements of "1,000 directories each with a .gitignore". They
  // are not close, and the difference is the whole reason the layer
  // representation matters.
  //
  // SIBLINGS: two layers apply to any entry, however many directories there are.
  row('1k sibling directories, one .gitignore each', (r) => {
    gitignorePerDirectory(r, 1_000);
  });

  // NESTED: layers ACCUMULATE, so an entry at depth D is tested against D of
  // them, and the patterns are unique per level so none of them matches — the
  // case where no layer can answer and every one is consulted. This is the shape
  // the offset representation was ported for; the trend across the three depths
  // is what says whether the cost is still growing with depth x entries.
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
  // few long-named levels past it. The label is a claim about what got built, so
  // it is printed only when the shape says it built it — a pool without
  // `process.chdir` leaves the past-the-ceiling half unmade, and a bench carries
  // no assertions to notice.
  row('nesting past the deepest addressable directory', (r) => {
    const chain = deepChain(r);
    if (!chain.created || !chain.unaddressable) {
      // stderr rather than a thrown error: vitest swallows a throw from a bench
      // body, so raising one here would be silent.
      process.stderr.write(
        `[bench] "nesting past the deepest addressable directory" measured ` +
          `${String(chain.addressable)} addressable levels only — nothing past the ceiling was ` +
          `built: ${chain.reason}\n`,
      );
    }
  });
});
