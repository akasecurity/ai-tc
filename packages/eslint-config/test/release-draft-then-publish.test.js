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

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

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
    expect(inputs.files).toBe('${{ runner.temp }}/*.tgz');
    expect(inputs.fail_on_unmatched_files, 'no match would lock an empty Release').toBe('true');
  });

  // A re-run repairs a draft by replacing its files. With this off, the action keeps the
  // old file and returns without an error, and that file is what gets published.
  it('replaces the files of a draft it finds', () => {
    expect(inputsOf(stepNamed(job(), UPLOAD)).overwrite_files ?? 'true').toBe('true');
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

  it('asks the public registry whether it holds the version', () => {
    expect(scriptOf(stepNamed(job(), NPM))).toContain(
      '--@akasecurity:registry=https://registry.npmjs.org',
    );
  });

  // Executed, because the whole recovery story rests on the answer deciding the
  // publish: reading the text passes on `npm view … || true` and an unconditional publish.
  it.each([
    ['holds the version', 'held', false],
    ['does not hold it', 'absent', true],
  ])('when the registry %s, publish=%s', (_label, registry, published, ctx) => {
    if (process.platform === 'win32' || !existsSync('/bin/bash')) ctx.skip();
    const dir = mkdtempSync(join(tmpdir(), 'aka-npm-guard-'));
    try {
      const log = join(dir, 'pnpm.log');
      writeFileSync(log, '');
      // `npm view @scope/name@1.2.3 version` answers the version, or nothing and exit 1,
      // which is how npm answers for a version it does not have.
      writeFileSync(
        join(dir, 'npm'),
        '#!/bin/sh\n[ "$REGISTRY" = held ] || exit 1\necho "${2##*@}"\n',
      );
      writeFileSync(join(dir, 'pnpm'), '#!/bin/sh\necho "$*" >> "$PNPM_LOG"\n');
      chmodSync(join(dir, 'npm'), 0o755);
      chmodSync(join(dir, 'pnpm'), 0o755);

      const stdout = execFileSync('/bin/bash', ['-c', scriptOf(stepNamed(job(), NPM))], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        env: {
          PATH: [dir, dirname(process.execPath), '/usr/bin', '/bin'].join(delimiter),
          PKG_VERSION: '1.2.3',
          PNPM_LOG: log,
          REGISTRY: registry,
        },
        timeout: 30_000,
      });

      const calls = readFileSync(log, 'utf8');
      if (published) {
        expect(calls).toContain(' publish --no-git-checks');
      } else {
        expect(calls, 'a re-run would stop at E409 and strand the draft').toBe('');
        expect(stdout).toContain('::notice::');
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('names a draft left unpublished in the log', () => {
    const step = stepNamed(job(), EXPLAIN);
    expect(stepIndex(job(), EXPLAIN)).toBeGreaterThan(stepIndex(job(), PUBLISH));
    expect(step.if).toBe("failure() && steps.draft.outcome == 'success'");
    expect(stepNamed(job(), UPLOAD).id).toBe('draft');
  });
});
