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

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { dropComments, jobBlock, stepNamed, steps } from './helpers/workflow.js';

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
