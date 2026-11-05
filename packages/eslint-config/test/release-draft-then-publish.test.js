// The CLI and plugin release workflows upload to a draft and publish it afterwards.
//
// GitHub locks a Release the moment it is published and refuses any file added
// after that. softprops/action-gh-release publishes a prerelease before it
// uploads unless told `draft: true`, and every 0.x tag is a prerelease, so a step
// without it fails after npm has already published and leaves an empty Release
// that can never be repaired. That is what happened to all five 0.9.23 Releases.
//
// release-binaries.yml is not held to this yet: its rolling `bin-latest` Release
// needs its own answer (see conventions/releasing.md), so its release job is left
// out of the derived list below on purpose.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { releaseWorkflows } from './helpers/release-workflows.js';
import { jobOf, parseWorkflow, stepsOf } from './helpers/workflow-yaml.js';

const WORKFLOW_PATH = /^\.github\/workflows\/release-(?:plugin-[^/]+|cli)\.ya?ml$/;
const WORKFLOWS = releaseWorkflows().filter((workflow) => WORKFLOW_PATH.test(workflow));
const KNOWN = [
  '.github/workflows/release-cli.yml',
  '.github/workflows/release-plugin-antigravity.yml',
  '.github/workflows/release-plugin-claude.yml',
  '.github/workflows/release-plugin-codex.yml',
  '.github/workflows/release-plugin-copilot.yml',
];
const RELEASE_ACTION = 'softprops/action-gh-release@';

/** @param {string} workflow */
function releaseSteps(workflow) {
  const parsed = parseWorkflow(readFileSync(join(REPO_ROOT, workflow), 'utf8'));
  return stepsOf(jobOf(parsed, 'release')).filter(
    (step) => typeof step.uses === 'string' && step.uses.startsWith(RELEASE_ACTION),
  );
}

describe('the release workflows are derived, not listed', () => {
  it('finds every known workflow (positive control)', () => {
    expect(WORKFLOWS).toEqual(expect.arrayContaining(KNOWN));
  });
});

describe.each(WORKFLOWS)('%s: a Release is uploaded as a draft, then published', (workflow) => {
  it('runs exactly two release steps: upload, then publish', () => {
    expect(releaseSteps(workflow).map((step) => step.name)).toEqual([
      'Create GitHub Release',
      'Publish GitHub Release',
    ]);
  });

  it('uploads its files to a draft', () => {
    const [upload] = releaseSteps(workflow);
    expect(upload.with.draft, 'the upload step would publish before uploading').toBe(true);
    expect(upload.with.files, 'the upload step names no files').toBeTruthy();
  });

  it('publishes without files, and without replacing the notes', () => {
    const [, publish] = releaseSteps(workflow);
    expect(publish.with.draft, 'the publish step leaves the Release a draft').toBe(false);
    expect(publish.with, 'the publish step uploads files').not.toHaveProperty('files');
    expect(publish.with, 'the publish step replaces the notes').not.toHaveProperty('body');
  });

  it('gives both steps the same pin, gate and prerelease flag', () => {
    const [upload, publish] = releaseSteps(workflow);
    expect(publish.uses).toBe(upload.uses);
    expect(publish.if).toBe(upload.if);
    expect(publish.with.prerelease).toBe(upload.with.prerelease);
  });
});
