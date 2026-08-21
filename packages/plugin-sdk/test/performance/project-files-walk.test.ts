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
  nestedGitignoreChain,
  symlinkLoops,
} from '../../../../test/fixtures/adversarial/hostile-repo/index.ts';
import { fastestOf, FIXTURE_TIMEOUT_MS } from '../../../../test/helpers/perf.ts';
import { PROJECT_WALK_BOUNDS, resolveProjectFiles } from '../../src/project-files.ts';

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
// advisory and gates nothing — run by the nightly `.github/workflows/bench.yml`
// and by hand: a wall-clock gate on a hosted runner produces flakes, and a flaky
// gate is one people re-run until it passes.
//
// The four budget rows at the bottom are the exception, and they are sized the
// way the rest of the repo sizes a timing assertion: the estimator is the
// FASTEST of several passes (noise only ever adds time, so the minimum is the
// closest a loaded machine gets to the code's own cost) and the budgets carry
// 76x or more headroom over the figures the bench rows measure.
//
// THE PER-TEST TIMEOUT IS NOT THE GATE, and the two must not be conflated. A
// row's wall clock is dominated by BUILDING its tree — thousands of individual
// `writeFileSync` calls, which cost an order of magnitude more on the Windows
// runner than here — while what it asserts is `fastestOf`, which times the walk
// alone. Leaving both under one 20 s budget makes the fixture the binding
// constraint, so a row goes red for being slow to SET UP and the failure reads
// as a slow walk. These carry a generous timeout that catches only a genuine
// hang; `budgetMs` is what fails a walk that got slower.

let repo: HostileRepo | undefined;

afterEach(() => {
  repo?.cleanup();
  repo = undefined;
});

const fresh = (prefix?: string): HostileRepo => {
  repo = createHostileRepo(prefix);
  return repo;
};

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
    // The clock and the ceiling both shorten the chain, and only one of them is
    // a fact about this platform. `deepChain` stops on whichever comes first, so
    // a depth that fell short ON THE BUDGET says the runner was busy — measured
    // at 26 levels on a contended Windows leg, against a ceiling that allows far
    // more — while the same depth reached at the ceiling is a real constant.
    //
    // Skipped rather than asserted, for the reason `created: false` is: a wall
    // clock must not decide a correctness assertion. The floor below still fires
    // whenever the chain stopped for any NON-timing reason, so this narrows the
    // guard to the case it can actually speak about instead of disabling it.
    if (chain.budgetSpent && chain.addressable <= 50) {
      ctx.skip(`${chain.reason} — a contended runner, not a walker defect`);
    }
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

    // Driven past the shipped depth cap on purpose. `PATH_MAX` is the ceiling
    // this case is named for and it sits an order of magnitude below the JS
    // stack; the walk's OWN cap sits below both, so at shipped bounds this
    // chain stops at 64 and the marker is unreachable. Raising the bound past
    // the marker is what keeps the case testing recursion rather than testing
    // the cap — the cap has its own cases below, and one of them re-runs this
    // fixture at the default to show the difference is the bound and not the
    // tree.
    // `budgetMs` is raised well past the shipped 4 s along with the depth, and
    // that is not incidental: this case asserts RECURSION, so a wall clock must
    // not be able to decide it. The walk measures ~51 ms here against ~474
    // levels, but the same chain reaches roughly four times deeper on Linux
    // (`PATH_MAX` 4096 against macOS' 1024) and a contended runner has measured
    // an order of magnitude slower for filesystem work — and the deadline is now
    // read once per DIRECTORY, so a chain of ~474 of them consults it ~474
    // times where it used to consult it never. If it fired the walk would stop
    // before the marker and this case would fail as though the walker had
    // overflowed, which is the one failure it must not be able to report
    // falsely. Every sibling in the bounds block below keeps the clock out the
    // same way.
    const scan = resolveProjectFiles(r.root, {
      bounds: { maxDepth: chain.addressable + 8, budgetMs: 60_000 },
    });

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

  // Skipped on Windows on COST, not on the timeout — the ceiling above would now
  // accommodate it. 21,000 individual `writeFileSync` calls measured ~56 s on
  // that runner against ~2 s here, and the Windows leg is shared: the first
  // version of this suite pushed it to 10m16s and four unrelated `persistence`
  // cases plus a `web-ui` one started timing out alongside it, which stopped as
  // soon as the load came off. `MAX_FILES` has no platform-dependent behaviour,
  // so a minute of pure file creation buys no coverage worth that.
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
    // Same ceiling the budget rows take, and for the same reason: what this
    // asserts is a COUNT, so the clock is measuring the 21,000-file build. The
    // package default is 20 s, which the macOS runner overran at 35.6 s while
    // this machine builds the same tree in 2 s — a per-platform fixture cost
    // deciding a case that has no timing property to fail.
    FIXTURE_TIMEOUT_MS,
  );
});

describe('traversal is bounded, and every omission says so', () => {
  // The bound exists because `MAX_FILES` never fires on the shape that costs the
  // most: 400 nested directories each carrying a .gitignore, over 5,000 leaf
  // files, measured 13.0 s and 645 MB — past the hosts' 10 s hook timeout on a
  // tree of 5,400 files. On Antigravity that is a DENY of the user's tool call,
  // not a lost inventory, and a synchronous walk yields nothing for a watchdog
  // to preempt.
  //
  // Every case here drives SMALL bounds against a small tree and pins the
  // SHIPPED ones separately, because the alternative is a fixture big enough to
  // exhaust three million charged units — which is the cost the bound exists to
  // refuse, paid on every run.

  /** A chain of `depth` nested directories, each holding one source file. */
  function chainWithFilePerLevel(r: HostileRepo, depth: number): void {
    let cur = r.root;
    for (let i = 0; i < depth; i++) {
      cur = join(cur, `d${String(i)}`);
      mkdirSync(cur);
      writeFileSync(join(cur, `f${String(i)}.ts`), 'x');
    }
  }

  it('the shipped bounds are the ones every other case reasons about', () => {
    // The pin. Each case below overrides the bounds to keep its fixture small,
    // so on its own it proves the MECHANISM and says nothing about what ships —
    // a `maxDepth` quietly raised to 100_000 would leave all of them green.
    expect(PROJECT_WALK_BOUNDS).toEqual({ maxDepth: 64, budgetMs: 4_000 });
  });

  it('a subtree past the depth cap is omitted, and the scan is marked truncated', () => {
    const r = fresh();
    chainWithFilePerLevel(r, 12);

    const bounded = resolveProjectFiles(r.root, { bounds: { maxDepth: 5, budgetMs: 60_000 } });

    // Everything down to the cap is inventoried and nothing below it is. The
    // count is exact rather than a floor: a walk that stopped one level early
    // satisfies "nothing below 5" perfectly.
    expect(bounded?.files.map((f) => f.path).sort()).toEqual(
      [
        'd0/f0.ts',
        'd0/d1/f1.ts',
        'd0/d1/d2/f2.ts',
        'd0/d1/d2/d3/f3.ts',
        'd0/d1/d2/d3/d4/f4.ts',
      ].sort(),
    );
    // The half that cannot be quiet. An omitted subtree that is not marked
    // truncated PRUNES the stored tree down to what this pass could see, which
    // turns a bound into data loss.
    expect(bounded?.truncated).toBe(true);

    // The control, and the reason the assertions above are about the CAP rather
    // than about this tree: the same fixture at a bound that clears it yields
    // every level and reports no truncation at all.
    const whole = resolveProjectFiles(r.root, { bounds: { maxDepth: 64, budgetMs: 60_000 } });
    expect(whole?.files.length).toBe(12);
    expect(whole?.truncated).toBe(false);
  });

  it('a directory refused for an ordinary reason does not mark the scan truncated', () => {
    const r = fresh();
    // Files at the ROOT and the only directory below it a skip-listed one, then
    // a cap of zero — so the depth check and the SKIP_DIRS check both have an
    // opinion about the same entry and their ORDER is the only thing that
    // decides the outcome. Anything else leaves the two orderings agreeing:
    // a cap the tree does not reach is never consulted, which is how this case
    // first passed while the ordering was wrong.
    for (let i = 0; i < 4; i++) writeFileSync(join(r.root, `f${String(i)}.ts`), 'x');
    const deps = join(r.root, 'node_modules', 'pkg');
    mkdirSync(deps, { recursive: true });
    writeFileSync(join(deps, 'index.js'), 'x');

    const scan = resolveProjectFiles(r.root, { bounds: { maxDepth: 0, budgetMs: 60_000 } });

    // SKIP_DIRS answers first, so `node_modules` is a directory the walk was
    // never going to enter rather than a subtree the bound took away. Reported
    // as an omission, every repository with a dependency tree would publish
    // `truncated` — which suppresses the stored tree's prune for ever.
    expect(scan?.files.length).toBe(4);
    expect(scan?.truncated).toBe(false);
  });

  it(
    'the deadline stops a walk spread across MANY directories',
    () => {
      const r = fresh();
      // Flat and shallow, so the depth cap plays no part and the only bound that
      // can fire is the deadline. That matters: this is the shape a depth cap
      // alone does NOT bound — 500k files behind one root-level pattern are each
      // tested against the whole stack, and not one of them is a kept file, so
      // MAX_FILES never fires either.
      //
      // MANY directories, few entries each, is what the PER-DIRECTORY check
      // covers. It has a sibling below for the mirror shape, and the two are not
      // interchangeable: with this fixture alone, deleting the per-entry check
      // leaves the whole suite green.
      // 10 directories x 100 files. The DIRECTORY count is the property; the file
      // count is pure fixture cost, and on the Windows runner each writeFileSync
      // costs an order of magnitude more than here — 5,000 of them measured
      // 69,234 ms there against ~400 ms locally, which is what blew this case's
      // budget while the walk itself was never the problem.
      flatFiles(r, 1_000, 100);

      // The clock is injected rather than raced. A real deadline small enough to
      // fire inside this fixture is a few milliseconds, which is the same order as
      // the walk itself on a fast machine — a wall-clock race deciding a
      // correctness assertion, and a flake on whichever runner lands on the wrong
      // side of it.
      //
      // It STEPS rather than jumping, so the walk gets somewhere before the
      // deadline bites. A clock that returned the budget on its second read would
      // trip at the root directory's own check, leave nothing collected, and the
      // walk would return undefined — which is a different contract (an empty walk
      // is dropped) and would prove nothing about a partial one.
      let reads = 0;
      const now = () => reads++ * 100;
      const bounded = resolveProjectFiles(r.root, { bounds: { maxDepth: 64, budgetMs: 500 }, now });

      expect(bounded?.truncated).toBe(true);
      expect(bounded?.files.length).toBeLessThan(1_000);
      // Not zero, or this would also pass on a walk that refused to start — and a
      // walk that yields nothing returns undefined, so the assertion above would
      // be reading `undefined?.truncated` and comparing it to nothing.
      expect(bounded?.files.length).toBeGreaterThan(0);
      // The clock was actually consulted. Without this the case still passes on a
      // walk that truncated for some entirely different reason.
      expect(reads).toBeGreaterThan(1);

      // The control, and what makes the assertions above about the DEADLINE rather
      // than about this tree: the same fixture on the real clock walks whole and
      // reports no truncation.
      const whole = resolveProjectFiles(r.root);
      expect(whole?.files.length).toBe(1_000);
      expect(whole?.truncated).toBe(false);
    },
    FIXTURE_TIMEOUT_MS,
  );

  it(
    'the deadline stops a walk inside ONE very wide directory',
    () => {
      const r = fresh();
      // The mirror shape, and the one the per-directory check cannot reach: a
      // single directory holding every file. Checked only on entry to a
      // directory, the deadline is read three times here — the walk's start, the
      // root, and this directory — and then not again until a readdir of 3,000
      // entries has been walked to the end. The entry counter is what bounds that,
      // and this is the only case that can tell whether it is still there.
      // Over two DEADLINE_CHECK_INTERVALs in one directory, which is all this
      // shape needs — 3,000 measured 7,354 ms of fixture build on Windows against
      // a 20 s per-test default, which is not the margin to leave a case on.
      flatFiles(r, 1_200, 1_200);

      // Budget sized so the clock crosses it only after the first entry-interval
      // check: the three directory reads reach 200, and the deadline is 250.
      let reads = 0;
      const now = () => reads++ * 100;
      const bounded = resolveProjectFiles(r.root, { bounds: { maxDepth: 64, budgetMs: 250 }, now });

      expect(bounded?.truncated).toBe(true);
      expect(bounded?.files.length).toBeLessThan(1_200);
      expect(bounded?.files.length).toBeGreaterThan(0);
      // More than the walk's own start plus the two directory checks, so the read
      // that tripped can only have come from the per-ENTRY schedule.
      expect(reads).toBeGreaterThan(3);

      // The control: same tree, real clock, whole walk, no truncation.
      const whole = resolveProjectFiles(r.root);
      expect(whole?.files.length).toBe(1_200);
      expect(whole?.truncated).toBe(false);
    },
    FIXTURE_TIMEOUT_MS,
  );

  it(
    'bounds the shape that outran the hook timeout, at the SHIPPED bounds',
    (ctx) => {
      const r = fresh();
      // The shape from the measurement above, driven at the defaults rather than
      // at an override — the one case here that reads what actually ships. Only
      // the depth matters, so the leaf is deliberately narrow: the assertion is
      // that the walk stops descending and says so, and the wall clock lives in
      // the bench, which gates nothing.
      const chain = nestedGitignoreChain(r, 100, 200);
      // GATED, for the reason `created: false` is gated elsewhere: Windows' default
      // MAX_PATH stops this chain wherever it stops, and a chain that never got
      // past the cap has nothing to say about the cap.
      if (chain.depth <= PROJECT_WALK_BOUNDS.maxDepth) {
        ctx.skip(`the chain reached depth ${String(chain.depth)}, at or under the cap`);
      }

      const scan = resolveProjectFiles(r.root);

      // The 200 leaf files sit at the bottom of the chain, past the cap, so the
      // walk reaches none of them — what it keeps is the `.gitignore` from each
      // level down to the cap. It must not report that as a complete tree.
      expect(scan?.truncated).toBe(true);
      expect(scan?.files.length).toBe(PROJECT_WALK_BOUNDS.maxDepth);
      for (const file of scan?.files ?? []) expect(file.name).toBe('.gitignore');
    },
    FIXTURE_TIMEOUT_MS,
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

  it.each(asCases(ROWS.filter((row) => !row.heavy)))(
    '%s',
    (_label, row) => {
      runRow(row);
    },
    FIXTURE_TIMEOUT_MS,
  );

  // Skipped on Windows on the same COST argument as the file-cap case above:
  // ~41 s to build 20k files and walk them four times, on a leg shared with
  // every other package's suite. The walk budget it asserts is a property of the
  // walk, not of the filesystem underneath it, and the lighter rows above cover
  // that property on this platform already.
  const heavyRows = ROWS.filter((row) => row.heavy);
  it.skipIf(process.platform === 'win32').each(asCases(heavyRows))(
    '%s',
    (_label, row) => {
      runRow(row);
    },
    FIXTURE_TIMEOUT_MS,
  );
});
