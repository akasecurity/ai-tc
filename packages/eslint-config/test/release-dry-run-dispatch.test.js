// The release workflows whose manual dispatch is a dry run, and nothing else.
//
// A dispatch can start from any branch, and the check that the tag equals the
// manifests runs only on a tag push — so a dispatch that could publish would
// ship whatever version a branch declares, as npm `latest`. Two workflows
// promise that a dispatch only builds, packs and smoke-tests; their header
// comments say so, and this suite is what holds the comment true:
//
// 1. The dispatch takes no input, and nothing reads one — `inputs.publish` is
//    the shape the other plugin workflows use to turn a dispatch into a publish.
// 2. Every publish invocation, and every step that cuts a GitHub Release, is
//    gated on the tag push EXACTLY: by its own step-level `if:`, or — for a
//    step carrying none — by the job-level `if:` of the job it runs in.
//
// The publish invocations come from the shared release-workflow reader, the
// same one the dist-tag routing guard uses, so a publish this suite gates is a
// publish that guard routes. The Claude Code workflow's own suite
// (`release-plugin-claude-gates.test.js`) additionally pins its job list, its
// step order and its on-main check; this one holds only the dry-run promise,
// across every workflow that makes it.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { publishSteps, releaseWorkflows, stepSlices } from './helpers/release-workflows.js';
import { dropComments, jobBlock } from './helpers/workflow.js';

// Listed rather than derived, on purpose: deriving "makes the promise" from
// "takes no dispatch input" would drop a workflow from this set the moment it
// broke the promise.
const DRY_RUN_WORKFLOWS = [
  '.github/workflows/release-plugin-claude.yml',
  '.github/workflows/release-plugin-copilot.yml',
];

/** The one gate every publishing step and job carries, exactly. */
const TAG_PUSH = "github.event_name == 'push'";

/** The action that cuts a GitHub Release. */
const RELEASE_ACTION = /^[^\S\n]*(?:- )?uses: softprops\/action-gh-release@/m;

/** @param {string} workflow */
const readWorkflow = (workflow) => readFileSync(join(REPO_ROOT, workflow), 'utf8');

/**
 * Every `if:` condition at one indentation inside a slice, comments dropped.
 * `if: ` with the colon, so a shell `if [ … ]` inside a `run:` block is not a
 * gate.
 * @param {string} slice
 * @param {number} indent
 */
const ifConditions = (slice, indent) =>
  [...dropComments(slice).matchAll(new RegExp(`^ {${indent}}if: (.+?)[^\\S\\n]*$`, 'gm'))].map(
    (m) => m[1],
  );

/**
 * Every job id the workflow declares, scoped to the `jobs:` mapping.
 * @param {string} source
 */
function jobIds(source) {
  const jobs = /^jobs:[^\S\n]*$([\s\S]*)$/m.exec(dropComments(source));
  expect(jobs, 'the workflow declares no jobs block').not.toBeNull();
  return [...jobs[1].matchAll(/^ {2}([A-Za-z_][A-Za-z0-9_-]*):[^\S\n]*$/gm)].map((m) => m[1]);
}

/**
 * The gate a step runs under: its own step-level `if:` when it has one, else
 * the job-level `if:` of the one job whose body carries it. `undefined` when
 * neither gates it.
 * @param {string} source
 * @param {string} step a step slice
 * @param {string} where
 */
function gateOf(source, step, where) {
  const own = ifConditions(step, 8);
  expect(own.length, `${where} carries more than one step-level \`if:\``).toBeLessThanOrEqual(1);
  if (own.length === 1) return own[0];
  const body = dropComments(step).trim();
  const owners = jobIds(source).filter((id) => jobBlock(source, id).includes(body));
  expect(owners, `${where} sits in no single job`).toHaveLength(1);
  const job = ifConditions(jobBlock(source, owners[0]), 4);
  expect(
    job.length,
    `job \`${owners[0]}\` carries more than one job-level \`if:\``,
  ).toBeLessThanOrEqual(1);
  return job[0];
}

describe('the dry-run workflows are the tracked release workflows they name', () => {
  it.each(DRY_RUN_WORKFLOWS)('%s is tracked', (workflow) => {
    expect(releaseWorkflows()).toContain(workflow);
  });
});

describe.each(DRY_RUN_WORKFLOWS)('%s: a manual dispatch is a dry run', (workflow) => {
  it('keeps the dispatch trigger and gives it no inputs', () => {
    const text = dropComments(readWorkflow(workflow));
    // The positive control: the dry-run path itself is kept.
    expect(text, 'the workflow no longer takes a manual dispatch').toMatch(
      /^ {2}workflow_dispatch:[^\S\n]*$/m,
    );
    expect(text, 'the dispatch declares inputs').not.toMatch(/^ {4}inputs:/m);
    expect(text, 'the workflow reads a dispatch input').not.toMatch(/\binputs\./);
  });

  it('gates every publish on the tag push exactly', () => {
    const source = readWorkflow(workflow);
    const publishes = publishSteps().filter((s) => s.workflow === workflow);
    // Non-vacuity: an npm publish and a GitHub Packages publish, at least. With
    // none found, the loop below asserts nothing.
    expect(publishes.length, 'no publish invocation was found').toBeGreaterThanOrEqual(2);
    for (const publish of publishes) {
      // Equal, not containing: `github.event_name == 'push' || inputs.publish`
      // contains the gate and publishes on the dispatch it was meant to refuse.
      expect(
        gateOf(source, publish.step, `\`${publish.name || publish.command}\``),
        `\`${publish.name || publish.command}\` is not gated on the tag push exactly`,
      ).toBe(TAG_PUSH);
    }
  });

  it('cuts a GitHub Release only on the tag push', () => {
    const source = readWorkflow(workflow);
    const releases = stepSlices(source).filter((step) => RELEASE_ACTION.test(dropComments(step)));
    expect(releases.length, 'no GitHub Release step was found').toBeGreaterThanOrEqual(1);
    for (const step of releases) {
      expect(gateOf(source, step, 'the GitHub Release step')).toBe(TAG_PUSH);
    }
  });
});
