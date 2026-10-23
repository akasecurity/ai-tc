// Every plugin release workflow publishes a stable version only from a commit
// `main` holds.
//
// A stable plugin tag is cut after its release pull request merges, on the
// commit that merge put on `main`, so the commit a stable version's npm
// provenance names is one `main` holds. Each `release-plugin-*.yml` refuses a
// stable version whose commit `main` lacks, before anything publishes; a
// pre-release, which is tagged on its release branch, is exempt.
//
// Two halves, because they fail differently:
//
// 1. WHERE the check sits. It has to run in every run that publishes anything:
//    its gate is at least as wide as every publish gate, it comes before every
//    publish step in its own job, and every other job that publishes waits for
//    that job. A check that is present but gated off, or that runs after the
//    npm publish, refuses nothing that matters.
// 2. WHAT the check lets through. It is shell, so it is executed rather than
//    read, against a throwaway repository shaped like a release with
//    `origin/main` standing where the job's full checkout puts it.
//
// The workflows are read as parsed YAML, and the publish invocations through
// the shared release-workflow reader, so a publish this suite orders is a
// publish the dist-tag routing guard routes.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { publishCommands, releaseWorkflows } from './helpers/release-workflows.js';
import {
  envOf,
  isMapping,
  jobIds,
  jobOf,
  needsOf,
  parseWorkflow,
  scriptOf,
  stepIndex,
  stepNamed,
  stepsOf,
} from './helpers/workflow-yaml.js';

// Derived, so a plugin release workflow added later is held to the rule without
// an edit here. The four listed are the positive control: a derivation that
// matched nothing would leave every case below unwritten, which reads as green.
const PLUGIN_WORKFLOW_PATH = /^\.github\/workflows\/release-plugin-[^/]+\.ya?ml$/;
const PLUGIN_WORKFLOWS = releaseWorkflows().filter((f) => PLUGIN_WORKFLOW_PATH.test(f));
const KNOWN_PLUGIN_WORKFLOWS = [
  '.github/workflows/release-plugin-antigravity.yml',
  '.github/workflows/release-plugin-claude.yml',
  '.github/workflows/release-plugin-codex.yml',
  '.github/workflows/release-plugin-copilot.yml',
];

const ON_MAIN_CHECK = 'Verify a stable tag is on main';
const CHECK_JOB = 'release';

/** A tag push. */
const TAG_PUSH = "github.event_name == 'push'";
/** A tag push, or a manual dispatch asked to publish. */
const TAG_PUSH_OR_PUBLISH = `${TAG_PUSH} || inputs.publish`;
/** The gates the on-main check may carry; anything else is a falsified gate. */
const CHECK_GATES = [TAG_PUSH, TAG_PUSH_OR_PUBLISH];

/** The action that cuts a GitHub Release. */
const RELEASE_ACTION = 'softprops/action-gh-release@';

/** @param {string} workflow */
const readWorkflow = (workflow) => readFileSync(join(REPO_ROOT, workflow), 'utf8');

/** @param {string} workflow */
const parsed = (workflow) => parseWorkflow(readWorkflow(workflow));

/**
 * What a step publishes: each registry publish its `run:` carries, read by the
 * shared reader, plus a GitHub Release when it uses the release action.
 * @param {Record<string, unknown>} step
 * @returns {string[]}
 */
function publishesOf(step) {
  const out = typeof step.run === 'string' ? publishCommands(step.run) : [];
  if (typeof step.uses === 'string' && step.uses.startsWith(RELEASE_ACTION)) {
    out.push(`GitHub Release (${step.uses})`);
  }
  return out;
}

/**
 * The gate a step runs under: its own `if:`, else its job's, else none.
 * @param {Record<string, unknown>} job
 * @param {Record<string, unknown>} step
 */
const gateOf = (job, step) => String(step.if ?? job.if ?? '');

/**
 * The tag prefix a workflow's push trigger names, e.g. `plugin-codex-v`.
 * @param {Record<string, unknown>} workflow
 */
function tagPrefixOf(workflow) {
  const on = workflow.on;
  expect(isMapping(on) && isMapping(on.push), 'the workflow has no push trigger').toBe(true);
  const tags = /** @type {Record<string, unknown>} */ (on.push).tags;
  expect(Array.isArray(tags) && tags.length === 1, 'the push trigger names no single tag').toBe(
    true,
  );
  const pattern = String(/** @type {unknown[]} */ (tags)[0]);
  expect(pattern, 'the tag pattern is not `<prefix>*`').toMatch(/^plugin-[a-z-]+-v\*$/);
  return pattern.slice(0, -1);
}

describe('the plugin release workflows are derived, not listed', () => {
  it('finds every known plugin release workflow (positive control)', () => {
    expect(PLUGIN_WORKFLOWS).toEqual(expect.arrayContaining(KNOWN_PLUGIN_WORKFLOWS));
  });

  it('runs the same check script in every one of them', () => {
    const scripts = PLUGIN_WORKFLOWS.map((workflow) =>
      scriptOf(stepNamed(jobOf(parsed(workflow), CHECK_JOB), ON_MAIN_CHECK)),
    );
    // One script, not four drifting copies. Each is still executed on its own
    // below, so equality is a guard against drift and not a substitute.
    for (const [index, script] of scripts.entries()) {
      expect(script, `${PLUGIN_WORKFLOWS[index]} carries a different on-main check`).toBe(
        scripts[0],
      );
    }
  });
});

describe.each(PLUGIN_WORKFLOWS)('%s: the on-main check runs before anything publishes', (path) => {
  it('gates the check on every run that can publish', () => {
    const workflow = parsed(path);
    const release = jobOf(workflow, CHECK_JOB);
    const check = stepNamed(release, ON_MAIN_CHECK);
    const checkGate = gateOf(release, check);
    // Equal to one of the two, not containing: `… || false`-style rewrites and
    // `false` itself are both a falsified gate.
    expect(CHECK_GATES, `the on-main check is gated on \`${checkGate}\``).toContain(checkGate);
    expect(release.if, 'the release job carries a gate of its own').toBeUndefined();
    expect(check['continue-on-error'], 'a failing on-main check would not stop the job').toBe(
      undefined,
    );
    expect(
      release['continue-on-error'],
      'a failing release job would not stop its dependants',
    ).toBe(undefined);

    // Every publish runs under the check's gate or the narrower tag push, so no
    // run publishes in which the check was skipped.
    let found = 0;
    for (const id of jobIds(workflow)) {
      const job = jobOf(workflow, id);
      for (const step of stepsOf(job)) {
        for (const publish of publishesOf(step)) {
          found += 1;
          expect(
            [TAG_PUSH, checkGate],
            `\`${publish}\` in \`${id}\` runs under \`${gateOf(job, step)}\`, which the on-main check does not cover`,
          ).toContain(gateOf(job, step));
        }
      }
    }
    // Non-vacuity: an npm publish, a GitHub Packages publish and a Release.
    expect(found, 'no publish was found, so the loop asserted nothing').toBeGreaterThanOrEqual(3);
  });

  it('places the check before every publish in its job, and makes every other publishing job wait for it', () => {
    const workflow = parsed(path);
    const release = jobOf(workflow, CHECK_JOB);
    const checkAt = stepIndex(release, ON_MAIN_CHECK);
    let found = 0;
    for (const id of jobIds(workflow)) {
      const job = jobOf(workflow, id);
      for (const [index, step] of stepsOf(job).entries()) {
        for (const publish of publishesOf(step)) {
          found += 1;
          if (id === CHECK_JOB) {
            expect(index, `\`${publish}\` runs before the on-main check`).toBeGreaterThan(checkAt);
          } else {
            expect(
              needsOf(job),
              `\`${id}\` publishes \`${publish}\` without waiting for the job that checks main`,
            ).toContain(CHECK_JOB);
            expect(job['continue-on-error'], `\`${id}\` sets continue-on-error`).toBe(undefined);
          }
        }
      }
    }
    // Every publish the text carries was attributed to a step of some job; a
    // publish the job walk missed would otherwise go unordered in silence.
    expect(found, 'the job walk missed a publish the workflow text carries').toBe(
      publishCommands(readWorkflow(path)).length +
        jobIds(workflow)
          .flatMap((id) => stepsOf(jobOf(workflow, id)))
          .filter((s) => typeof s.uses === 'string' && s.uses.startsWith(RELEASE_ACTION)).length,
    );
    expect(found).toBeGreaterThanOrEqual(3);
  });

  it('reads the version the publish ships, from a step that runs before it', () => {
    const release = jobOf(parsed(path), CHECK_JOB);
    expect(envOf(stepNamed(release, ON_MAIN_CHECK)).PKG_VERSION).toBe(
      '${{ steps.manifest.outputs.version }}',
    );
    const manifestAt = stepsOf(release).findIndex((step) => step.id === 'manifest');
    expect(manifestAt, 'no step with `id: manifest` sets the version').toBeGreaterThanOrEqual(0);
    expect(manifestAt).toBeLessThan(stepIndex(release, ON_MAIN_CHECK));
  });

  it("checks out main's history in the release job, which the check reads", () => {
    const checkouts = stepsOf(jobOf(parsed(path), CHECK_JOB)).filter(
      (step) => typeof step.uses === 'string' && step.uses.startsWith('actions/checkout@'),
    );
    expect(checkouts, 'the release job has no single checkout step').toHaveLength(1);
    const inputs = /** @type {Record<string, unknown>} */ (checkouts[0].with ?? {});
    expect(inputs['fetch-depth']).toBe(0);
  });
});

// The executed half.
const BASH = '/bin/bash';

// A fixed search path rather than the developer's own: what resolves `git`
// here must not depend on what someone has earlier on their PATH.
const TOOL_PATH = [
  dirname(process.execPath),
  '/usr/local/bin',
  '/usr/bin',
  '/bin',
  '/usr/sbin',
  '/sbin',
].join(':');

/** Where a tool resolves on TOOL_PATH, or null. */
function resolveTool(name) {
  for (const dir of TOOL_PATH.split(':')) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Skip on a host that cannot run the extracted block. A skip and never a bare
 * return: a returning body is a passing body, and these cases are worth
 * something only because they ran the block.
 * @param {{ skip: (note?: string) => void }} ctx
 */
function requireGitAndBash(ctx) {
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the extracted block is POSIX shell, as GitHub runs it`);
  }
  if (resolveTool('git') === null) {
    ctx.skip('needs git on a real PATH; the extracted block runs it');
  }
}

const SCRATCH_DIRS = [];
afterAll(() => {
  for (const dir of SCRATCH_DIRS) rmSync(dir, { recursive: true, force: true });
});

/**
 * A repository shaped like a release: `main` with one commit, a release branch
 * one commit ahead of it, and `origin/main` at `main`. Its git reads no config
 * but its own, so a developer's signing or hook settings cannot change it.
 */
function releaseRepo() {
  const root = mkdtempSync(join(tmpdir(), 'aka-tag-on-main-'));
  SCRATCH_DIRS.push(root);
  const repo = join(root, 'repo');
  mkdirSync(repo);
  const globalConfig = join(root, 'gitconfig');
  writeFileSync(globalConfig, '');
  const env = {
    PATH: TOOL_PATH,
    HOME: root,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: globalConfig,
    GIT_AUTHOR_NAME: 'Release Fixture',
    GIT_AUTHOR_EMAIL: 'release-fixture@example.invalid',
    GIT_COMMITTER_NAME: 'Release Fixture',
    GIT_COMMITTER_EMAIL: 'release-fixture@example.invalid',
  };
  const git = (...args) =>
    execFileSync(resolveTool('git'), args, {
      cwd: repo,
      env,
      encoding: 'utf8',
      timeout: 30_000,
    }).trim();
  git('init', '-q', '-b', 'main');
  git('commit', '-q', '--allow-empty', '-m', 'base');
  const base = git('rev-parse', 'HEAD');
  git('checkout', '-q', '-b', 'release/fixture');
  git('commit', '-q', '--allow-empty', '-m', 'chore(release): fixture');
  const releaseCommit = git('rev-parse', 'HEAD');
  git('checkout', '-q', 'main');
  git('update-ref', 'refs/remotes/origin/main', base);
  return { repo, env, git, base, releaseCommit };
}

/** Point `origin/main` at `main`'s current commit, as a fresh checkout would. */
const publishMain = (fixture) =>
  fixture.git('update-ref', 'refs/remotes/origin/main', fixture.git('rev-parse', 'HEAD'));

// The executed cases each build a throwaway git repository and spawn the check
// script, some 8 to 18 git and bash processes run synchronously. That is well
// inside the default 5 s alone but not on a loaded host, and a timeout on the
// tag push would turn the very release run this suite protects red. The
// deadline is named here, generous on purpose: the cases finish in well under
// a second when the host is idle.
const GIT_FIXTURE_TIMEOUT_MS = 60_000;

describe.each(PLUGIN_WORKFLOWS)(
  '%s: a stable version publishes only from a commit main holds',
  (path) => {
    /**
     * Run the step's own `run:` script, as the workflow spells it, for one
     * version and one tagged commit, with the tag name a push of that version
     * would carry.
     *
     * `detached` first checks the tagged commit out with a detached HEAD, which
     * is where a tag push's checkout leaves the job. Without it HEAD stays on
     * `main`, and in every case that leaves it there `origin/main` points at
     * that same commit whenever the check reaches its comparison, so a check
     * that compared against HEAD instead of `origin/main` could not be told
     * apart.
     * @param {ReturnType<typeof releaseRepo>} fixture
     * @param {{ version: string, sha: string, detached?: boolean }} tag
     */
    function runOnMainCheck(fixture, { version, sha, detached = false }) {
      if (detached) fixture.git('checkout', '-q', '--detach', sha);
      const workflow = parsed(path);
      const script = scriptOf(stepNamed(jobOf(workflow, CHECK_JOB), ON_MAIN_CHECK));
      const refName = `${tagPrefixOf(workflow)}${version}`;
      try {
        const output = execFileSync(BASH, ['-c', script], {
          cwd: fixture.repo,
          encoding: 'utf8',
          env: { ...fixture.env, PKG_VERSION: version, GITHUB_SHA: sha, GITHUB_REF_NAME: refName },
          timeout: 30_000,
        });
        return { passed: true, output, refName };
      } catch (err) {
        return {
          passed: false,
          output: `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`,
          refName,
        };
      }
    }

    it(
      'passes a stable tag on a commit main contains',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.base });
        expect(result.passed, result.output).toBe(true);
        expect(result.output).toContain(`${fixture.base} is on main`);
      },
    );

    it(
      'refuses a stable tag on a release-branch commit main does not contain',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.releaseCommit });
        expect(result.passed, result.output).toBe(false);
        expect(result.output).toContain(
          `::error::${result.refName} is at ${fixture.releaseCommit}, which main does not contain`,
        );
      },
    );

    it(
      'compares against main, not the tagged commit the job has checked out',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        const result = runOnMainCheck(fixture, {
          version: '0.9.15',
          sha: fixture.releaseCommit,
          detached: true,
        });
        // The premise, read back from the repository: HEAD is the tagged
        // release-branch commit, detached, with `origin/main` somewhere else.
        // If the checkout did nothing, the refusal below would prove nothing.
        expect(fixture.git('rev-parse', 'HEAD')).toBe(fixture.releaseCommit);
        expect(fixture.git('rev-parse', 'refs/remotes/origin/main')).toBe(fixture.base);
        expect(() => fixture.git('symbolic-ref', '--quiet', 'HEAD')).toThrow();
        expect(result.passed, result.output).toBe(false);
        expect(result.output).toContain(
          `::error::${result.refName} is at ${fixture.releaseCommit}, which main does not contain`,
        );
      },
    );

    it(
      'reads main from origin, since a tag checkout creates no local main branch',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        // A tag checkout is detached and has no local `main`. In every other
        // case the local `main` equals `origin/main`, so a check that read the
        // local branch would pass them all and refuse every stable tag here.
        fixture.git('checkout', '-q', '--detach', fixture.base);
        fixture.git('update-ref', '-d', 'refs/heads/main');
        const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.base });
        expect(fixture.git('rev-parse', 'HEAD')).toBe(fixture.base);
        expect(fixture.git('rev-parse', 'refs/remotes/origin/main')).toBe(fixture.base);
        expect(() => fixture.git('symbolic-ref', '--quiet', 'HEAD')).toThrow();
        expect(() => fixture.git('rev-parse', '--verify', '--quiet', 'refs/heads/main')).toThrow();
        expect(result.passed, result.output).toBe(true);
        expect(result.output).toContain(`${fixture.base} is on main`);
      },
    );

    // One row per pre-release suffix: beta, nightly, rc, and an arbitrary other
    // suffix, which the dist-tag block's catch-all arm publishes under `rc`. A
    // skip arm narrowed to `*-beta.*`, or one naming the suffixes one by one,
    // would refuse a row. `it.for`, not `it.each`: only `for` hands the
    // callback the TestContext the skip needs.
    it.for([
      ['beta', '0.10.0-beta.1'],
      ['nightly', '0.10.0-nightly.1'],
      ['rc', '0.10.0-rc.1'],
      ['any other suffix', '0.10.0-alpha.1'],
    ])(
      'passes a pre-release tag on its release branch (%s)',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      ([, version], ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        // The premise, read back from the repository: the tagged commit is off
        // main, so a stable version there is refused. Without it the pass
        // below would prove only that the check let a commit through.
        expect(() =>
          fixture.git(
            'merge-base',
            '--is-ancestor',
            fixture.releaseCommit,
            'refs/remotes/origin/main',
          ),
        ).toThrow();
        const result = runOnMainCheck(fixture, { version, sha: fixture.releaseCommit });
        expect(result.passed, result.output).toBe(true);
        expect(result.output).toContain(`pre-release ${version}`);
      },
    );

    it(
      'passes both the merge commit and the release commit once a merge commit lands',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        fixture.git(
          'merge',
          '-q',
          '--no-ff',
          '--no-edit',
          '-m',
          'Merge release',
          'release/fixture',
        );
        publishMain(fixture);
        const merge = fixture.git('rev-parse', 'HEAD');
        for (const sha of [merge, fixture.releaseCommit]) {
          const result = runOnMainCheck(fixture, { version: '0.9.15', sha });
          expect(result.passed, result.output).toBe(true);
        }
      },
    );

    it(
      'refuses the release commit after a squash merge left it off main',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        // What a squash merge leaves: a new commit on main carrying the
        // change, and the release branch's own commit on no branch main
        // contains.
        fixture.git('commit', '-q', '--allow-empty', '-m', 'chore(release): fixture (squash)');
        publishMain(fixture);
        const squash = fixture.git('rev-parse', 'HEAD');
        expect(
          runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.releaseCommit }).passed,
        ).toBe(false);
        expect(runOnMainCheck(fixture, { version: '0.9.15', sha: squash }).passed).toBe(true);
      },
    );

    it(
      'refuses, and names the cause, when main was not fetched',
      { timeout: GIT_FIXTURE_TIMEOUT_MS },
      (ctx) => {
        requireGitAndBash(ctx);
        const fixture = releaseRepo();
        fixture.git('update-ref', '-d', 'refs/remotes/origin/main');
        const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.base });
        expect(result.passed, result.output).toBe(false);
        expect(result.output).toContain('origin/main is not fetched');
      },
    );
  },
);
