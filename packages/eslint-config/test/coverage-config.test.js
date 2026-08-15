import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { COVERAGE_FLOORS, coverageOptions } from '../../../test/vitest/coverage.ts';
import {
  readPackageManifest,
  REPO_ROOT,
  toPosix,
  trackedFiles,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

// Coverage measurement, guarded workspace-wide rather than per package.
//
// It lives in THIS package for the reason test-only-seam.test.js does: only
// @akasecurity/eslint-config#test declares turbo `inputs` covering the whole
// workspace, so only a suite here re-runs when a DIFFERENT package drops its
// coverage block. The same check inside each package would be the guard that
// cannot see the thing it guards against — a package silently opting out is
// exactly the edit that leaves its own hash the only one moving.
//
// What it holds, in one sentence each:
//
//   - every test-running package MEASURES coverage, through the one shared block
//   - every one of them has a FLOOR, and the floor set is exactly that set
//   - there is NO aggregate/global threshold anywhere
//   - turbo's `outputs: ["coverage/**"]` describes a directory that now exists
//
// The third is the one worth being careful about, because it is an ABSENCE and
// absences go vacuous quietly. It is asserted positively wherever possible: the
// floors table is pinned as an EXACT set against the packages that run tests, so
// a global threshold cannot be smuggled in as a table entry, and each config is
// required to source its block from the shared module rather than hand-roll one.

// Derived from the workspace globs, never a hardcoded list: a package added
// tomorrow has to appear here, which is what turns "we forgot to give it a
// floor" into a failing test rather than an untested package nobody notices.
const WORKSPACE_PACKAGES = workspacePackageDirs().map((dir) => ({
  dir,
  name: readPackageManifest(dir).name,
  testScript: readPackageManifest(dir).scripts?.test ?? '',
}));

/** Packages that actually run a suite — the ones a floor can apply to. */
const TEST_PACKAGES = WORKSPACE_PACKAGES.filter((p) => p.testScript !== '');

const configTextFor = (pkg) => readFileSync(join(REPO_ROOT, pkg.dir, 'vitest.config.ts'), 'utf8');

const optionsFor = (pkg) =>
  coverageOptions(pathToFileURL(join(REPO_ROOT, pkg.dir, 'vitest.config.ts')).href);

const TURBO = JSON.parse(
  // turbo.json carries comments (jsonc). Strip line comments before parsing —
  // block comments are not used in it, and a regex that tried to handle them
  // would eat the `**/*` globs.
  readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8').replace(/^\s*\/\/.*$/gm, ''),
);

describe('every package that runs tests measures coverage', () => {
  // A floor for a package nobody measures is decoration; a package measured with
  // no floor is one whose number can fall to zero silently. Pinning the two sets
  // EQUAL is what makes adding a package a decision rather than an omission —
  // and it is why a global threshold has nowhere to live in this table.
  it('the floors table names exactly the packages that run tests', () => {
    expect(Object.keys(COVERAGE_FLOORS).sort()).toEqual(TEST_PACKAGES.map((p) => p.name).sort());
  });

  it('each ships a vitest config that sources the SHARED coverage block', () => {
    // Sourcing it — rather than merely having SOME `coverage:` key — is the
    // property. A hand-rolled block in one package is how the excludes drift
    // apart, and how a package quietly stops counting a directory it ships.
    const missing = TEST_PACKAGES.filter((p) => {
      const text = configTextFor(p);
      return (
        !/import \{ coverageOptions \} from '(\.\.\/)+test\/vitest\/coverage\.ts';/.test(text) ||
        !text.includes('coverage: coverageOptions(import.meta.url)')
      );
    }).map((p) => p.dir);

    expect(missing, 'these packages do not use the shared coverage block').toEqual([]);
  });

  it('no vitest config declares a threshold of its own', () => {
    // The shared block is the only place a threshold is set, so a `thresholds`
    // key in a config is either a per-package override that bypasses the table
    // above, or an aggregate one. Both are the thing this suite exists to stop.
    const offenders = TEST_PACKAGES.filter((p) => /\bthresholds\b/.test(configTextFor(p))).map(
      (p) => p.dir,
    );

    expect(offenders).toEqual([]);
  });

  it('an unlisted package throws rather than defaulting to a floor of zero', () => {
    // The failure mode this closes: a new package added without a measured
    // floor. Defaulting to 0 would let it ship with no coverage at all AND no
    // signal, which is precisely the state ui-kit was in.
    //
    // Driven through a REAL temp package whose name no floor covers. Pointing
    // at a path with no package.json would throw ENOENT instead, satisfying a
    // bare `toThrow()` while the floor lookup never ran — so the message is
    // asserted, not merely the throw.
    const dir = mkdtempSync(join(tmpdir(), 'aka-coverage-floor-'));
    try {
      writeFileSync(
        join(dir, 'package.json'),
        JSON.stringify({ name: '@akasecurity/not-a-real-package' }),
      );

      expect(() => coverageOptions(pathToFileURL(join(dir, 'vitest.config.ts')).href)).toThrow(
        /no floor for "@akasecurity\/not-a-real-package"/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('no global coverage threshold exists', () => {
  // The stated rule: a repo-wide percentage would be satisfied by covering an
  // icon sheet while a mutating Server Action stayed at zero. Every floor is
  // therefore scoped to exactly one package.
  it('every floor is keyed to a real workspace package', () => {
    const names = new Set(WORKSPACE_PACKAGES.map((p) => p.name));
    const unknown = Object.keys(COVERAGE_FLOORS).filter((k) => !names.has(k));

    expect(unknown, 'a floor keyed to something that is not a package').toEqual([]);
  });

  it('the shared block scopes its threshold to the calling package alone', () => {
    // Two packages must not be handed the same reportsDirectory or the same
    // floor by construction — that would be an aggregate threshold wearing a
    // per-package name.
    const dirs = TEST_PACKAGES.map((p) => optionsFor(p).reportsDirectory);
    expect(new Set(dirs).size).toBe(TEST_PACKAGES.length);

    for (const pkg of TEST_PACKAGES) {
      expect(optionsFor(pkg).thresholds).toEqual({ lines: COVERAGE_FLOORS[pkg.name] });
    }
  });

  it('no tracked config file declares an aggregate coverage threshold', () => {
    // The last door: a vitest WORKSPACE file, or a root config, applying one
    // threshold across projects. Nothing like that exists today, and this is
    // what notices if one appears.
    const suspects = trackedFiles().filter((f) =>
      /(^|\/)(vitest\.workspace|vitest\.projects)\.[cm]?[jt]s$/.test(toPosix(f)),
    );

    expect(suspects, 'a workspace-level vitest config could hold a global threshold').toEqual([]);
  });
});

describe('CI reports coverage and uploads it', () => {
  const ci = readFileSync(join(REPO_ROOT, '.github/workflows/ci.yml'), 'utf8');

  // A step in the workflow is the whole of "coverage runs in CI" and "diff
  // coverage is reported per PR". Nothing else in the tree observes either, so
  // deleting a step is otherwise a silent, green removal of both.

  it('runs the diff-coverage gate on pull requests', () => {
    expect(ci).toMatch(/tools\/coverage-gate\/src\/check-diff-coverage\.ts/);
    expect(ci).toMatch(/- name: Diff coverage/);
  });

  it('checks out enough history for a merge base to exist', () => {
    // Anchored to a YAML key on its own line, NOT a bare `fetch-depth: 0`
    // substring. The step above this one carries a comment explaining why the
    // setting is there, and a loose match is satisfied by that PROSE — so
    // deleting the setting while keeping the comment left this green. It was,
    // until a mutation run said otherwise.
    expect(ci).toMatch(/^\s+fetch-depth: 0\s*$/m);
  });

  it('diffs against the merge base, not the base tip', () => {
    // A depth-1 checkout has no merge base, so the gate could only be handed the
    // base TIP — which attributes to this PR every line that landed on main
    // since the branch started. The step would still run and still print a
    // number; it would just be the wrong one, which is worse than no step.
    expect(ci).toMatch(/--base \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
  });

  it('writes the report to the PR step summary', () => {
    // "Reported per PR" means a human sees it without opening an artifact.
    expect(ci).toMatch(/--summary "\$GITHUB_STEP_SUMMARY"/);
  });

  it('uploads the coverage report as an artifact, even on a red floor', () => {
    // `always()` is the load-bearing half: the report explaining WHICH lines a
    // package lost is wanted precisely when that package failed its floor, and a
    // default `if` skips the upload on any earlier failure.
    const upload = /- name: Upload coverage report\n(?:.*\n)*?\s+uses: actions\/upload-artifact/;
    expect(ci).toMatch(upload);
    expect(ci).toMatch(/- name: Upload coverage report\n\s+if: always\(\)/);
  });
});

describe("turbo's declared coverage output is real", () => {
  // Before this landed, `outputs: ["coverage/**"]` named a directory nothing in
  // the repository ever produced. An output a task does not write is not merely
  // useless: turbo restores outputs on a cache hit, so a task that writes one
  // only SOMETIMES hands back a report belonging to another run.
  it('the test task still declares coverage/** as an output', () => {
    expect(TURBO.tasks.test.outputs).toContain('coverage/**');
  });

  it('the shared block writes into the directory turbo declares', () => {
    for (const pkg of TEST_PACKAGES) {
      const options = optionsFor(pkg);
      expect(toPosix(options.reportsDirectory)).toBe(
        `${toPosix(join(REPO_ROOT, pkg.dir))}/coverage`,
      );
    }
  });

  it('coverage is enabled without a flag, so the output is produced every run', () => {
    // Behind `--coverage`, the output would exist only on the runs that
    // remembered the flag — and a cache hit taken from a run without it
    // restores no report at all, while reading as a successful `test`.
    for (const pkg of TEST_PACKAGES) {
      const options = optionsFor(pkg);
      expect(options.enabled).toBe(true);
    }
  });

  it('turbo.json is hashed into THIS suite, so the two assertions above can fire', () => {
    // The subtlest entry in that inputs list, and the reason it is asserted
    // rather than trusted: the two checks above read turbo.json, and no
    // extension glob in that list reaches a .json at the repo root. Without this
    // entry, deleting the coverage output declaration moves no hash this suite
    // is keyed on — turbo replays a cached green and the guard never runs.
    expect(TURBO.tasks['@akasecurity/eslint-config#test'].inputs).toContain(
      '$TURBO_ROOT$/turbo.json',
    );
  });

  it('the shared coverage module is hashed into every test task', () => {
    // It holds the floors. Outside globalDependencies, lowering one would move
    // no package's hash and every package would replay a cached green taken
    // under the stricter floor — a false green for the one thing a floor is for.
    expect(TURBO.globalDependencies).toContain('test/vitest/**');
  });
});
