// The CLI and plugin release workflows upload to a draft, publish to npm, then
// publish the draft.
//
// GitHub locks a Release the moment it is published and refuses any file added
// after that. softprops/action-gh-release publishes a prerelease before it
// uploads unless told `draft: true`, and every 0.x tag is a prerelease, so a step
// without it fails after npm has already published and leaves an empty Release
// that can never be repaired. That is what happened to all five 0.9.23 Releases.
//
// The order is what makes a failure recoverable: an upload that fails leaves npm
// untouched, and a re-run gets past a version npm already holds only because the
// npm step skips it. See "GitHub Releases are immutable" in conventions/releasing.md.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { CLI_AND_PLUGIN_WORKFLOW_PATH, releaseWorkflows } from './helpers/release-workflows.js';
import {
  inputsOf,
  jobIds,
  jobOf,
  parseWorkflow,
  scriptOf,
  stepIndex,
  stepNamed,
  stepsOf,
} from './helpers/workflow-yaml.js';

const WORKFLOWS = releaseWorkflows().filter((f) => CLI_AND_PLUGIN_WORKFLOW_PATH.test(f));
const KNOWN = [
  '.github/workflows/release-cli.yml',
  '.github/workflows/release-plugin-antigravity.yml',
  '.github/workflows/release-plugin-claude.yml',
  '.github/workflows/release-plugin-codex.yml',
  '.github/workflows/release-plugin-copilot.yml',
];
const RELEASE_ACTION = 'softprops/action-gh-release@';
const UPLOAD = 'Create GitHub Release';
const NPM = 'Publish to npm';
const PUBLISH = 'Publish GitHub Release';
const EXPLAIN = 'Explain a draft Release left unpublished';

/** @param {string} workflow */
const parsed = (workflow) => parseWorkflow(readFileSync(join(REPO_ROOT, workflow), 'utf8'));

/**
 * Every release step in the workflow, whichever job carries it.
 * @param {string} workflow
 */
function releaseSteps(workflow) {
  const source = parsed(workflow);
  return jobIds(source).flatMap((id) =>
    stepsOf(jobOf(source, id)).filter(
      (step) => typeof step.uses === 'string' && step.uses.startsWith(RELEASE_ACTION),
    ),
  );
}

/**
 * A step's input names, lower-cased: GitHub matches input names without regard to case.
 * @param {Record<string, unknown>} step
 */
const inputNames = (step) => Object.keys(inputsOf(step)).map((key) => key.toLowerCase());

describe('the release workflows are derived, not listed', () => {
  it('finds every known workflow (positive control)', () => {
    expect(WORKFLOWS).toEqual(expect.arrayContaining(KNOWN));
  });
});

describe.each(WORKFLOWS)('%s: draft, then npm, then publish', (workflow) => {
  const job = () => jobOf(parsed(workflow), 'release');

  it('runs exactly two release steps in the whole workflow', () => {
    expect(releaseSteps(workflow).map((step) => step.name)).toEqual([UPLOAD, PUBLISH]);
  });

  it('uploads before npm, and publishes the Release after it', () => {
    expect(stepIndex(job(), UPLOAD)).toBeLessThan(stepIndex(job(), NPM));
    expect(stepIndex(job(), NPM)).toBeLessThan(stepIndex(job(), PUBLISH));
  });

  it('uploads its files to a draft, and fails when no file matches', () => {
    const inputs = inputsOf(stepNamed(job(), UPLOAD));
    expect(inputs.draft, 'the upload step would publish before uploading').toBe('true');
    expect(inputs.files, 'the upload step names no files').toBeTruthy();
    expect(inputs.fail_on_unmatched_files, 'no match would lock an empty Release').toBe('true');
  });

  it('publishes with nothing but the draft and prerelease flags', () => {
    const step = stepNamed(job(), PUBLISH);
    expect(inputNames(step).sort()).toEqual(['draft', 'prerelease']);
    expect(inputsOf(step).draft, 'the publish step leaves the Release a draft').toBe('false');
  });

  it('gives both steps the same pin, gate and prerelease flag', () => {
    const upload = stepNamed(job(), UPLOAD);
    const publish = stepNamed(job(), PUBLISH);
    expect(publish.uses).toBe(upload.uses);
    expect(publish.if).toBe(upload.if);
    expect(inputsOf(publish).prerelease).toBe(inputsOf(upload).prerelease);
  });

  it('skips npm for a version the public registry already holds', () => {
    const script = scriptOf(stepNamed(job(), NPM));
    const guard = script.indexOf('npm view');
    expect(guard, 'a re-run would stop at E409 and strand the draft').toBeGreaterThanOrEqual(0);
    expect(script).toContain('--@akasecurity:registry=https://registry.npmjs.org');
    expect(guard).toBeLessThan(script.indexOf(' publish --no-git-checks'));
  });

  it('names a draft left unpublished in the log', () => {
    const step = stepNamed(job(), EXPLAIN);
    expect(stepIndex(job(), EXPLAIN)).toBeGreaterThan(stepIndex(job(), PUBLISH));
    expect(step.if).toBe("failure() && steps.draft.outcome == 'success'");
    expect(stepNamed(job(), UPLOAD).id).toBe('draft');
  });
});
