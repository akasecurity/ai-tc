import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
  symlinkLoops,
} from '../../../../test/fixtures/adversarial/hostile-repo/index.ts';
import { resolveProjectFiles } from '../../src/project-files.ts';

// The SessionStart project walk against the adversarial corpus.
//
// WHAT THIS TIER ASSERTS, AND WHAT IT DELIBERATELY DOES NOT. The walk is
// synchronous and runs inside the hosts' 10 s hook timeout. On Claude Code and
// Codex a hook killed at that timeout fails OPEN — the session loses its
// inventory. On Antigravity the same hook is read as a DENY, and the pass hangs
// off `PreInvocation` rather than a session event, so a walk that outruns the
// host blocks the user's tool call; `runHookFailOpen`'s watchdog cannot preempt
// it, because a synchronous body never yields the thread. So "does this walk
// TERMINATE, on every tree an attacker can author" is the property that matters,
// and every case below asserts termination, shape, or fail-safety rather than a
// duration. The durations live in `bench/project-files.bench.ts`, which is
// advisory and run by hand: a wall-clock gate on a hosted runner produces flakes,
// and a flaky gate is one people re-run until it passes.
//
// The four budget rows at the bottom are the exception, and they are sized the
// way the rest of the repo sizes a timing assertion: the estimator is the
// FASTEST of several passes (noise only ever adds time, so the minimum is the
// closest a loaded machine gets to the code's own cost) and the budgets carry
// 76x or more headroom over the figures the bench rows measure.

let repo: HostileRepo | undefined;

afterEach(() => {
  repo?.cleanup();
  repo = undefined;
});

const fresh = (prefix?: string): HostileRepo => {
  repo = createHostileRepo(prefix);
  return repo;
};

/** The fastest of `runs` passes — see the note above on why not a mean. */
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

/**
 * Whether this process can make a directory genuinely unreadable.
 *
 * The probe is built OUTSIDE the repository under test and removed either way —
 * a leftover directory inside the tree would be walked by the very scan these
 * cases assert on.
 *
 * It reads a real entry rather than a missing one on purpose. Under a mode of
 * 0o000 a normal user is refused with EACCES before the lookup happens, while
 * root bypasses the mode and SUCCEEDS — which is the signal wanted, and the only
 * way to get it. Probing a name that does not exist cannot distinguish them:
 * root gets ENOENT, so the root case arrives as an unexplained errno and the
 * branch naming it is unreachable.
 */
function canDenyReads(): string | undefined {
  if (process.platform === 'win32') return 'chmod does not deny reads on win32';
  const probe = mkdtempSync(join(tmpdir(), 'aka-chmod-probe-'));
  const inner = join(probe, 'entry');
  try {
    writeFileSync(inner, 'x');
    chmodSync(probe, 0o000);
    try {
      statSync(inner);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return code === 'EACCES' ? undefined : `expected EACCES, got ${String(code)}`;
    }
    return 'reads are not denied (running as root?)';
  } finally {
    chmodSync(probe, 0o700);
    rmSync(probe, { recursive: true, force: true });
  }
}

describe('the project walk terminates on a hostile tree', () => {
  it('a symlink loop does not trap the walk', (ctx) => {
    const r = fresh();
    const shape = symlinkLoops(r);
    if (!shape.created) ctx.skip(shape.reason);

    const scan = resolveProjectFiles(r.root);

    // Reaching this line at all is most of the assertion: a walk that followed
    // `a/to-root` would revisit the root forever and never return.
    expect(scan).toBeDefined();
    const paths = scan?.files.map((f) => f.path) ?? [];
    // The positive control. Without it a walk that returned nothing would
    // satisfy every absence check below.
    expect(paths).toContain('a/real.ts');
    expect(paths).toContain('b/real.ts');
    // Dirent types are lstat-based, so a link is neither file nor directory and
    // is skipped. Nothing may be recorded THROUGH one.
    expect(paths.filter((p) => p.includes('to-root'))).toEqual([]);
    expect(paths.filter((p) => p.includes('to-self'))).toEqual([]);
    expect(paths.filter((p) => p.includes('to-a') || p.includes('to-b'))).toEqual([]);
    expect(paths).not.toContain('dangling');
  });

  it('nesting deeper than a path can address does not overflow the stack', (ctx) => {
    const r = fresh();

    // Nesting is often worried about at 10,000 levels, and the honest answer is
    // that no walker here can reach a tenth of it: every directory is opened
    // by ABSOLUTE path, so `PATH_MAX` — not the JS stack — is what stops the
    // recursion. The chain runs to that ceiling and a few long-named levels
    // past it. The ceiling is probed rather than assumed: measured at 476 on
    // macOS, with `PATH_MAX` arithmetic putting Linux near 2,000 and Windows
    // anywhere from ~130 to ~16,000 depending on the long-path setting.
    const chain = deepChain(r);
    // GATED, not asserted: `created: false` is how the corpus reports a shape
    // this platform refused to build, and turning that into a failed assertion
    // would blame the walker for something the filesystem decided.
    //
    // It reports only whether the ADDRESSABLE chain exists, which is all the
    // assertions below need. Failing to push past the ceiling does not retract
    // it — that half is reported through `unaddressable`, which gates the
    // truncation assertion at the end on its own. Collapsing the two is what
    // made this whole case skip on Windows, where the chain builds fine and only
    // the `chdir` past the ceiling is refused.
    if (!chain.created) ctx.skip(chain.reason);
    expect(
      chain.addressable,
      'no addressable depth at all — every assertion below would hold vacuously',
    ).toBeGreaterThan(50);

    // A marker the walk can only record by recursing to it. `truncated` alone
    // would also be set by a walk that gave up at the very first directory, so
    // without this the case would pass on a walker that does nothing.
    //
    // Sixteen levels short of the ceiling, because the ceiling is the deepest
    // addressable DIRECTORY and this appends a filename to one: at the ceiling
    // itself the file's own name is what overflows `PATH_MAX`, which is a
    // fixture bug that reads exactly like the defect under test.
    const markerDepth = chain.addressable - 16;
    let marker = r.root;
    for (let i = 0; i < markerDepth; i++) marker = join(marker, 'd');
    const markerPath = join(marker, 'm.ts');
    writeFileSync(markerPath, 'x');
    expect(statSync(markerPath).isFile(), 'the deep marker was never written').toBe(true);

    const scan = resolveProjectFiles(r.root);

    // Returning at all is the headline: `markerDepth` frames of recursion, and
    // no RangeError.
    expect(scan).toBeDefined();
    const paths = scan?.files.map((f) => f.path) ?? [];
    expect(paths.some((p) => p.endsWith('/m.ts'))).toBe(true);

    // The levels past the ceiling are lost to ENAMETOOLONG, and a partial walk
    // must say so or the stored tree gets pruned to what this pass could see.
    // Gated, because a long-path Windows may not have been pushed past its own
    // ceiling within the fixture's bound — and asserting truncation there would
    // be asserting the fixture, not the walk.
    if (!chain.unaddressable) {
      ctx.skip(`the chain stayed addressable after ${String(chain.beyond)} extra levels`);
    }
    expect(scan?.truncated).toBe(true);
  });

  it('a directory the gitignore names is never descended into', (ctx) => {
    const r = fresh();
    const why = canDenyReads();
    if (why !== undefined) ctx.skip(why);

    ignoredSubtree(r, 12);
    // An unreadable directory INSIDE the ignored tree. Descending into the
    // ignored directory means meeting this one, failing its `readdir`, and
    // marking the scan truncated — so `truncated` is the observable that
    // separates "skipped the subtree" from "walked it and dropped every entry".
    // Both produce the same file list, which is why counting files cannot tell
    // them apart.
    const trap = join(r.root, 'vendor-cache', 'unreadable');
    mkdirSync(trap, { recursive: true });
    chmodSync(trap, 0o000);

    try {
      const scan = resolveProjectFiles(r.root);
      expect(scan).toBeDefined();
      expect(scan?.files.map((f) => f.path)).toContain('index.ts');
      expect(scan?.truncated).toBe(false);
    } finally {
      chmodSync(trap, 0o700);
    }
  });

  it('a gitignore that ignores everything drops the scan instead of emptying it', () => {
    const r = fresh();
    ignoreEverything(r);

    // Nothing survived the filter. An empty scan would be RECORDED, and
    // recording it prunes whatever tree is already stored down to nothing; the
    // contract is that a walk yielding nothing returns undefined instead.
    expect(resolveProjectFiles(r.root)).toBeUndefined();
  });

  it('names containing .. never produce a path that climbs out of the repo', () => {
    const r = fresh();
    dotDotNames(r);

    const scan = resolveProjectFiles(r.root);
    const paths = scan?.files.map((f) => f.path) ?? [];

    expect(paths).toContain('weird/..hidden.ts');
    expect(paths).toContain('weird/..nested/inner.ts');
    for (const path of paths) {
      expect(path.split('/'), `${path} carries a .. segment`).not.toContain('..');
      expect(path.startsWith('/'), `${path} is absolute`).toBe(false);
    }
  });

  // Skipped on Windows for the same reason as the 20k budget row below: the
  // FIXTURE is what exceeds the per-test timeout there, not the walk. 21,000
  // individual `writeFileSync` calls measured ~56 s on that runner against a
  // 20 s limit, where the same tree costs about 2 s locally. Nothing about
  // `MAX_FILES` is platform-dependent, so the property is proven on the legs
  // that can afford to build the tree.
  it.skipIf(process.platform === 'win32')(
    'the file cap bounds what is kept and says the tree was cut short',
    () => {
      const r = fresh();
      flatFiles(r, 21_000);

      const scan = resolveProjectFiles(r.root);

      // MAX_FILES caps KEPT files. It is not a bound on traversal, which is the
      // whole reason the bench measures an ignored 500k tree separately.
      expect(scan?.files.length).toBe(20_000);
      expect(scan?.truncated).toBe(true);
    },
  );
});

describe('the project walk stays inside its budget', () => {
  // Budgets from the performance plan; the figures beside them were measured on
  // an arm64 Mac against this fixture and are what the headroom is sized from.
  // `files` is the CONTROL, and it is per-row on purpose. Every assertion below
  // is an upper bound on elapsed time, and a walk that stopped early satisfies
  // one more easily than a walk that finished — so a single shared floor (">99",
  // as this read before) leaves the 5k, 20k and sibling rows passing on a walker
  // that quit after 100 files, and passing FASTER for having quit. Each row
  // therefore names the exact count its own tree yields.
  const ROWS = [
    {
      label: '100 files',
      budgetMs: 200,
      files: 100,
      heavy: false,
      build: (r: HostileRepo) => {
        flatFiles(r, 100);
      },
    }, // 0.11 ms
    {
      label: '5k files',
      budgetMs: 1_000,
      files: 5_000,
      heavy: false,
      build: (r: HostileRepo) => {
        flatFiles(r, 5_000);
      },
    }, // 3.5 ms
    {
      label: '20k files (the cap)',
      budgetMs: 3_000,
      files: 20_000,
      // See the skip below: the 20k-file BUILD, not the walk, is what blows the
      // per-test timeout on the Windows runner.
      heavy: true,
      build: (r: HostileRepo) => {
        flatFiles(r, 20_000);
      },
    }, // 14.0 ms
    {
      // 1,000 directories x (2 source files + the `.gitignore` itself), all of
      // which the walk keeps: the patterns written into each one name `*.log`
      // and `build-N/`, and the tree holds neither.
      label: '1k sibling directories each with a .gitignore',
      budgetMs: 3_000,
      files: 3_000,
      heavy: false,
      build: (r: HostileRepo) => {
        gitignorePerDirectory(r, 1_000);
      },
    }, // 39 ms
  ] as const;

  function runRow(row: (typeof ROWS)[number]): void {
    const r = fresh();
    row.build(r);

    let files = 0;
    const ms = fastestOf(3, () => {
      files = resolveProjectFiles(r.root)?.files.length ?? 0;
    });

    expect(files, "the walk did not return this row's whole tree").toBe(row.files);
    expect(ms).toBeLessThan(row.budgetMs);
  }

  const asCases = (rows: readonly (typeof ROWS)[number][]) =>
    rows.map((row) => [row.label, row] as const);

  it.each(asCases(ROWS.filter((row) => !row.heavy)))('%s', (_label, row) => {
    runRow(row);
  });

  // Skipped on Windows, for the reason the file-cap case above states: the tree
  // costs more to BUILD there than the whole test is allowed to take, and
  // `fastestOf` walks it four times on top of that — measured at ~41 s against a
  // 20 s timeout. What this row asserts is a property of the walk, not of the
  // filesystem underneath it, so it is proven on the legs that can afford the
  // fixture rather than by widening a timeout until the slowest runner fits.
  const heavyRows = ROWS.filter((row) => row.heavy);
  it.skipIf(process.platform === 'win32').each(asCases(heavyRows))('%s', (_label, row) => {
    runRow(row);
  });
});
