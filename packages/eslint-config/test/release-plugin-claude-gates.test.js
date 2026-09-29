// The Claude Code plugin's release workflow publishes on a tag push and on
// nothing else.
//
// Three properties, each invisible in a green run once lost:
//
// 1. A manual dispatch is a dry run. It takes no input that turns it into a
//    publish: a dispatch can start from any branch, and the check that the tag
//    equals both manifests runs only on a tag push, so a publish input would
//    ship whatever version a branch declares, as npm `latest`.
// 2. Every publish runs behind that tag check. The npm publish sits in the same
//    job AFTER the check, under the same gate; the GitHub Packages job waits
//    for that job instead of running beside it.
// 3. The workflow reads no credential but its own token. npm publishes through
//    OIDC, so a secret here would be one every run of this file can reach, and
//    a job handing off to another workflow is where one would come in.
//
// Every read goes through the shared comment-dropping job reader, because this
// workflow's own comments name its gates, jobs and checks in prose.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import {
  blockScalarText,
  dropComments,
  jobBlock,
  rawStepNamed,
  stepNamed,
  steps,
} from './helpers/workflow.js';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'release-plugin-claude.yml');

const readWorkflow = () => readFileSync(WORKFLOW, 'utf8');

/** The one gate every publishing step and job carries, exactly. */
const TAG_PUSH = "github.event_name == 'push'";

const TAG_CHECK = 'Verify tag matches manifest versions';
const NPM_PUBLISH = 'Publish to npm';
const GITHUB_RELEASE = 'Create GitHub Release';

// Listed rather than derived, on purpose: a new job in a release workflow runs
// with the release's permissions, and the diff that adds one should have to
// say here how it is gated.
const EXPECTED_JOBS = ['verify', 'release', 'github-packages'];

/**
 * Every job id the workflow declares, in file order. Scoped to the `jobs:`
 * mapping, since `on:` and `concurrency:` carry two-space keys of their own.
 * @param {string} source
 */
function jobIds(source) {
  const jobs = /^jobs:[^\S\n]*$([\s\S]*)$/m.exec(dropComments(source));
  expect(jobs, 'release-plugin-claude.yml declares no jobs block').not.toBeNull();
  const ids = [...jobs[1].matchAll(/^ {2}([A-Za-z_][A-Za-z0-9_-]*):[^\S\n]*$/gm)].map((m) => m[1]);
  expect(ids.length, 'the jobs block captured no job id').toBeGreaterThan(0);
  return ids;
}

/**
 * The job ids one job declares a `needs:` edge to, in any shape YAML takes: a
 * scalar, a flow sequence or a block sequence. An absent key is an empty list.
 * @param {string} jobBody
 */
function needsOf(jobBody) {
  const key = /^ {4}needs:[^\S\n]*(.*)$/m.exec(jobBody);
  if (key === null) return [];
  const inline = key[1].trim();
  if (inline !== '') {
    return inline
      .replace(/^\[/, '')
      .replace(/\]$/, '')
      .split(',')
      .map((id) => id.trim())
      .filter((id) => id !== '');
  }
  const out = [];
  for (const line of jobBody
    .slice(key.index + key[0].length)
    .split('\n')
    .slice(1)) {
    const item = /^ {6}- (\S+)[^\S\n]*$/.exec(line);
    if (item === null) break;
    out.push(item[1]);
  }
  return out;
}

/**
 * The one `if:` condition inside a slice, asserted to occur exactly once. `if: `
 * with the colon, so a shell `if [ … ]` inside a `run:` block is not a gate.
 * @param {string} slice
 * @param {string} where
 */
function soleIfCondition(slice, where) {
  const all = [...slice.matchAll(/^[^\S\n]*if: (.+?)[^\S\n]*$/gm)].map((m) => m[1]);
  expect(all, `${where} declares no single \`if:\` gate`).toHaveLength(1);
  return all[0];
}

/**
 * A named step's index among a job's steps, asserted present.
 * @param {string} jobBody
 * @param {string} name
 */
function positionOf(jobBody, name) {
  const names = steps(jobBody).map((step) => /^name: (.+?)[^\S\n]*$/m.exec(step)?.[1]);
  const at = names.indexOf(name);
  expect(at, `the job has no step named \`${name}\``).toBeGreaterThanOrEqual(0);
  return at;
}

/**
 * Every secret name a text reads through `secrets.<NAME>`.
 * @param {string} text
 */
const secretNames = (text) =>
  [...text.matchAll(/\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]);

describe('a manual dispatch of the Claude Code plugin release is a dry run', () => {
  it('keeps the dispatch trigger and gives it no inputs', () => {
    const text = dropComments(readWorkflow());
    // The positive control: the dry-run path itself is kept.
    expect(text, 'the workflow no longer takes a manual dispatch').toMatch(
      /^ {2}workflow_dispatch:[^\S\n]*$/m,
    );
    expect(text, 'the dispatch declares inputs').not.toMatch(/^ {4}inputs:/m);
    expect(text, 'the workflow reads a dispatch input').not.toMatch(/\binputs\./);
  });
});

describe('every publish runs behind the tag check, on a tag push only', () => {
  it('gates the tag check, the npm publish and the GitHub Release on the tag push exactly', () => {
    const release = jobBlock(readWorkflow(), 'release');
    for (const name of [TAG_CHECK, NPM_PUBLISH, GITHUB_RELEASE]) {
      // Equal, not containing: `github.event_name == 'push' || <anything>`
      // contains the gate and publishes on the dispatch it was meant to refuse.
      expect(
        soleIfCondition(stepNamed(release, name), `\`${name}\``),
        `\`${name}\` is gated on something other than the tag push`,
      ).toBe(TAG_PUSH);
    }
  });

  it('checks the tag before it publishes, and publishes before it cuts the Release', () => {
    const release = jobBlock(readWorkflow(), 'release');
    expect(positionOf(release, TAG_CHECK)).toBeLessThan(positionOf(release, NPM_PUBLISH));
    expect(positionOf(release, NPM_PUBLISH)).toBeLessThan(positionOf(release, GITHUB_RELEASE));
  });

  it('keeps the release job waiting on verify', () => {
    expect(needsOf(jobBlock(readWorkflow(), 'release'))).toContain('verify');
  });

  it('publishes to GitHub Packages only after the release job, on the tag push exactly', () => {
    const job = jobBlock(readWorkflow(), 'github-packages');
    expect(
      needsOf(job),
      'the GitHub Packages job does not wait for the job that checks the tag',
    ).toContain('release');
    // Sole, which is also the claim that no step inside carries a gate of its
    // own that could differ from the job's.
    expect(soleIfCondition(job, 'the GitHub Packages job')).toBe(TAG_PUSH);
  });
});

describe('the release reads no credential but its own token', () => {
  it('reads secret names the way the scan below expects (positive control)', () => {
    expect(secretNames('a: ${{ secrets.EXAMPLE_ONE }} b: ${{ secrets.GITHUB_TOKEN }}')).toEqual([
      'EXAMPLE_ONE',
      'GITHUB_TOKEN',
    ]);
  });

  it('references no secret except GITHUB_TOKEN', () => {
    const foreign = secretNames(dropComments(readWorkflow())).filter(
      (name) => name !== 'GITHUB_TOKEN',
    );
    expect(
      foreign,
      'npm publishes through OIDC; a secret here is a credential every run of this file reaches',
    ).toEqual([]);
  });

  it('runs exactly the jobs it lists, each on a runner of its own', () => {
    const source = readWorkflow();
    expect(jobIds(source)).toEqual(EXPECTED_JOBS);
    for (const id of EXPECTED_JOBS) {
      // A job that `uses:` another workflow hands this run's context to a file
      // the gates above never read.
      expect(jobBlock(source, id), `\`${id}\` calls a reusable workflow`).not.toMatch(
        /^ {4}uses: /m,
      );
    }
  });
});

// A stable version is published only from a commit `main` holds. The check is
// SHELL, so it is executed rather than read: a token check passes on a block
// that asks git the question backwards, and the only question worth asking is
// which tagged commits it lets through. It runs against a throwaway repository
// shaped like a release, with `origin/main` standing where the job's full
// checkout puts it.
const ON_MAIN_CHECK = 'Verify a stable tag is on main';
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

/**
 * Run the step's own `run:` script, as the workflow spells it, for one version
 * and one tagged commit.
 * @param {ReturnType<typeof releaseRepo>} fixture
 * @param {{ version: string, sha: string }} tag
 */
function runOnMainCheck(fixture, { version, sha }) {
  const script = blockScalarText(rawStepNamed(readWorkflow(), ON_MAIN_CHECK), 'run');
  try {
    const output = execFileSync(BASH, ['-c', script], {
      cwd: fixture.repo,
      encoding: 'utf8',
      env: { ...fixture.env, PKG_VERSION: version, GITHUB_SHA: sha },
      timeout: 30_000,
    });
    return { passed: true, output };
  } catch (err) {
    return { passed: false, output: `${String(err.stdout ?? '')}${String(err.stderr ?? '')}` };
  }
}

describe('a stable version publishes only from a commit main holds', () => {
  it('runs the on-main check on the tag push exactly, before the npm publish', () => {
    const release = jobBlock(readWorkflow(), 'release');
    expect(soleIfCondition(stepNamed(release, ON_MAIN_CHECK), 'the on-main check')).toBe(TAG_PUSH);
    expect(positionOf(release, ON_MAIN_CHECK)).toBeLessThan(positionOf(release, NPM_PUBLISH));
  });

  it("checks out main's history in the release job, which the check reads", () => {
    const checkouts = steps(jobBlock(readWorkflow(), 'release')).filter((step) =>
      /^uses: actions\/checkout@/m.test(step),
    );
    expect(checkouts, 'the release job has no single checkout step').toHaveLength(1);
    expect(checkouts[0]).toMatch(/^[^\S\n]*fetch-depth: 0[^\S\n]*$/m);
  });

  it('passes a stable tag on a commit main contains', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.base });
    expect(result.passed, result.output).toBe(true);
    expect(result.output).toContain(`${fixture.base} is on main`);
  });

  it('refuses a stable tag on a release-branch commit main does not contain', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.releaseCommit });
    expect(result.passed, result.output).toBe(false);
    expect(result.output).toContain(`::error::plugin-claude-v0.9.15 tags ${fixture.releaseCommit}`);
  });

  it('passes a pre-release tag on its release branch', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    const result = runOnMainCheck(fixture, {
      version: '0.10.0-beta.1',
      sha: fixture.releaseCommit,
    });
    expect(result.passed, result.output).toBe(true);
    expect(result.output).toContain('pre-release 0.10.0-beta.1');
  });

  it('passes both the merge commit and the release commit once a merge commit lands', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    fixture.git('merge', '-q', '--no-ff', '--no-edit', '-m', 'Merge release', 'release/fixture');
    publishMain(fixture);
    const merge = fixture.git('rev-parse', 'HEAD');
    for (const sha of [merge, fixture.releaseCommit]) {
      const result = runOnMainCheck(fixture, { version: '0.9.15', sha });
      expect(result.passed, result.output).toBe(true);
    }
  });

  it('refuses the release commit after a squash merge left it off main', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    // What a squash merge leaves: a new commit on main carrying the change,
    // and the release branch's own commit on no branch main contains.
    fixture.git('commit', '-q', '--allow-empty', '-m', 'chore(release): fixture (#1)');
    publishMain(fixture);
    const squash = fixture.git('rev-parse', 'HEAD');
    expect(runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.releaseCommit }).passed).toBe(
      false,
    );
    expect(runOnMainCheck(fixture, { version: '0.9.15', sha: squash }).passed).toBe(true);
  });

  it('refuses, and names the cause, when main was not fetched', (ctx) => {
    requireGitAndBash(ctx);
    const fixture = releaseRepo();
    fixture.git('update-ref', '-d', 'refs/remotes/origin/main');
    const result = runOnMainCheck(fixture, { version: '0.9.15', sha: fixture.base });
    expect(result.passed, result.output).toBe(false);
    expect(result.output).toContain('origin/main is not fetched');
  });
});
