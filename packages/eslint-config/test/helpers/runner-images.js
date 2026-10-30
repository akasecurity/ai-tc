import { expect } from 'vitest';

import { isMapping, jobOf } from './workflow-yaml.js';

// The runner labels a binary-building matrix must not pin, and the one reader of
// a matrix leg's label — shared by the suites over build-binaries.yml and
// release-binaries.yml, because both fan-outs pin the same four targets and a
// label retired by GitHub is retired for both of them.
//
// A DENY list of retired labels rather than an allow list of the current one: the
// macOS image moves forward roughly yearly, and an allow list would have to be
// edited on every move, with the guard red in the meantime for a label that is
// fine. A retired label, by contrast, stays retired.
//
// Retirement is not a lint-level inconvenience. GitHub terminates a job queued on
// a retired image instead of giving it a runner, so the leg comes back `cancelled`
// with no runner name and zero steps — and the binary channel renders its Homebrew
// formula and Scoop manifest from the SHA256SUMS of the release that produced the
// archives, so a `darwin-arm64` leg that cannot start takes the macOS binary
// channel with it rather than merely reporting red.

/**
 * The macOS runner images GitHub retires on 2026-11-02, with daily brownout
 * windows before then in which a job on one is terminated rather than scheduled
 * (actions/runner-images#13518). Both arm64 labels and the x64 one, because the
 * retirement is of the macOS 14 image and not of one size of it.
 * @type {readonly string[]}
 */
export const RETIRED_RUNNER_IMAGES = Object.freeze([
  'macos-14',
  'macos-14-large',
  'macos-14-xlarge',
]);

/**
 * The runner label a job's build matrix pins for one target, read out of the
 * workflow rather than restated here.
 *
 * `runs-on:` is asserted to be the matrix's own `os` key first. Without that the
 * `os` read below is a value nothing resolves: a job whose `runs-on:` names a
 * label directly, or a different matrix key, would carry an `os` entry the runner
 * never looks at, and every claim made about that entry would be about nothing.
 *
 * Exactly one entry for the target, for the reason `stepNamed` asserts the same:
 * a claim checked against the wrong leg passes for the wrong reason, and a target
 * spelled twice makes the answer whichever leg came first.
 *
 * @param {Record<string, unknown>} workflow a parsed workflow
 * @param {string} jobId the job carrying the matrix
 * @param {string} target the `target:` value of the leg to read
 * @returns {string} the leg's `os:` value
 */
export function runnerImageForTarget(workflow, jobId, target) {
  const job = jobOf(workflow, jobId);
  expect(job['runs-on'], `\`${jobId}\` does not take its runner from the matrix`).toBe(
    '${{ matrix.os }}',
  );
  const strategy = job.strategy;
  expect(isMapping(strategy), `\`${jobId}\` declares no strategy block`).toBe(true);
  const matrix = /** @type {Record<string, unknown>} */ (strategy).matrix;
  expect(isMapping(matrix), `\`${jobId}\` declares no matrix`).toBe(true);
  const include = /** @type {Record<string, unknown>} */ (matrix).include;
  expect(
    Array.isArray(include) && include.length > 0,
    `\`${jobId}\`'s matrix declares no include list — every leg read from it would be about nothing`,
  ).toBe(true);
  const matching = /** @type {unknown[]} */ (include).filter(
    (leg) => isMapping(leg) && /** @type {Record<string, unknown>} */ (leg).target === target,
  );
  expect(
    matching,
    `\`${jobId}\`'s matrix has no single leg for the target \`${target}\``,
  ).toHaveLength(1);
  const os = /** @type {Record<string, unknown>} */ (matching[0]).os;
  expect(
    typeof os === 'string' && os !== '',
    `the \`${target}\` leg declares no \`os:\` label`,
  ).toBe(true);
  return /** @type {string} */ (os);
}
