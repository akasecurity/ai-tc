import { expect } from 'vitest';

import { isMapping, jobOf } from './workflow-yaml.js';

// The one reader of a binary fan-out's matrix legs, and the one assertion over
// the runner image each leg pins — shared by the suites over build-binaries.yml
// and release-binaries.yml, because both fan-outs pin the same four targets and
// a label retired by GitHub is retired for both of them.
//
// Two separate questions are asked of every leg, and neither answers the other.
//
// A DENY list of retired labels rather than an allow list of the current one:
// the macOS image moves forward roughly yearly, and an allow list of versions
// would have to be edited on every move, with the guard red in the meantime for
// a label that is fine. A retired label, by contrast, stays retired.
//
// And a SHAPE per target, which is an allow list that does not move: `macos-15`
// and `macos-26` are both the arm64 image and both match it, while
// `macos-15-large` and `macos-15-intel` are the x64 ones and do not. The deny
// list cannot ask this — a label GitHub still serves is not retired — and it is
// the half that matters most here, since the target names the architecture the
// archive is published under.
//
// Retirement is not a lint-level inconvenience. GitHub terminates a job queued
// on a retired image instead of giving it a runner, so the leg comes back
// `cancelled` with no runner name and zero steps — and the binary channel
// renders its Homebrew formula and Scoop manifest from the SHA256SUMS of the
// release that produced the archives, so a leg that cannot start takes that
// platform's binary channel with it rather than merely reporting red. A leg
// that starts on the WRONG image is quieter still: it runs green and publishes
// an archive named for the architecture it was built on, which is not the one
// the target promises.

/**
 * The runner images GitHub has retired, as labels.
 *
 * The macOS 14 family retires on 2026-11-02, with daily brownout windows before
 * then in which a job on one is terminated rather than scheduled
 * (actions/runner-images#13518); macOS 11–13 and the Ubuntu and Windows labels
 * below went the same way earlier. Each macOS family carries all three sizes,
 * because the retirement is of an image and not of one size of it.
 *
 * Lower case, and compared against a lower-cased label: GitHub matches runner
 * labels case-insensitively, so `MacOS-14` reaches the retired image exactly as
 * `macos-14` does.
 * @type {readonly string[]}
 */
const RETIRED_RUNNER_IMAGES = Object.freeze([
  'macos-11',
  'macos-12',
  'macos-12-large',
  'macos-13',
  'macos-13-large',
  'macos-13-xlarge',
  'macos-14',
  'macos-14-large',
  'macos-14-xlarge',
  'ubuntu-18.04',
  'ubuntu-20.04',
  'windows-2019',
]);

/**
 * The shape of runner label each build target requires.
 *
 * A shape rather than a list of versions, so a move to the next image is not an
 * edit here: what each pattern pins is the architecture and the family, which
 * is what the target name promises, and the explicit version pin the house
 * style asks for (a bare `-latest` matches none of these, and moves under the
 * channel rather than being a reviewable decision).
 *
 * For macOS the bare label is Apple silicon; `-large` and `-intel` are the x64
 * images. For Ubuntu the arm64 image is the `-arm` suffix of the same version.
 * @type {Readonly<Record<string, RegExp>>}
 */
const TARGET_RUNNER_IMAGES = Object.freeze({
  'darwin-arm64': /^macos-\d+$/,
  'linux-x64': /^ubuntu-\d+\.\d+$/,
  'linux-arm64': /^ubuntu-\d+\.\d+-arm$/,
  'win32-x64': /^windows-\d+$/,
});

/**
 * A `runs-on:` that defers to the matrix, with the key it reads. Whitespace
 * inside the braces is optional to GitHub, so it is optional here: a reader
 * that pinned one spelling would redden a workflow the runner is happy with.
 */
const MATRIX_RUNS_ON = /^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$/;

/** A label as GitHub matches one: trimmed, and case-folded. */
const labelOf = (image) => image.trim().toLowerCase();

/**
 * Whether a runner label names an image GitHub has retired.
 * @param {string} image a runner label as the workflow spells it
 */
const isRetiredRunnerImage = (image) => RETIRED_RUNNER_IMAGES.includes(labelOf(image));

/**
 * Every leg of a job's build matrix, as the target it builds and the runner
 * label it pins — read out of the workflow rather than restated here.
 *
 * The runner label is read through the matrix key the job's own `runs-on:`
 * names, rather than through a hard-coded `os`. Both halves matter: a job whose
 * `runs-on:` names a label directly, or a key its legs do not carry, would make
 * every claim below about an entry the runner never looks at — and a job that
 * spells its key `image` is answered correctly instead of refused.
 *
 * Targets are asserted unique, for the reason `stepNamed` asserts the same: a
 * claim checked against the wrong leg passes for the wrong reason, and a target
 * spelled twice makes the answer whichever leg came first.
 *
 * @param {Record<string, unknown>} workflow a parsed workflow
 * @param {string} jobId the job carrying the matrix
 * @returns {{ target: string, image: string }[]} one entry per leg, in file order
 */
export function matrixLegs(workflow, jobId) {
  const job = jobOf(workflow, jobId);
  const runsOn = typeof job['runs-on'] === 'string' ? job['runs-on'].trim() : '';
  const reference = MATRIX_RUNS_ON.exec(runsOn);
  expect(reference, `\`${jobId}\` does not take its runner from the matrix`).not.toBeNull();
  const key = /** @type {RegExpExecArray} */ (reference)[1];

  const strategy = job.strategy;
  expect(isMapping(strategy), `\`${jobId}\` declares no strategy block`).toBe(true);
  const matrix = /** @type {Record<string, unknown>} */ (strategy).matrix;
  expect(isMapping(matrix), `\`${jobId}\` declares no matrix`).toBe(true);
  const include = /** @type {Record<string, unknown>} */ (matrix).include;
  expect(
    Array.isArray(include) && include.length > 0,
    `\`${jobId}\`'s matrix declares no include list — every leg read from it would be about nothing`,
  ).toBe(true);

  const legs = /** @type {unknown[]} */ (include).map((leg) => {
    expect(isMapping(leg), `\`${jobId}\`'s matrix has a leg that is not a mapping`).toBe(true);
    const entry = /** @type {Record<string, unknown>} */ (leg);
    expect(
      typeof entry.target === 'string' && entry.target !== '',
      `\`${jobId}\`'s matrix has a leg declaring no \`target:\``,
    ).toBe(true);
    const target = /** @type {string} */ (entry.target);
    expect(
      typeof entry[key] === 'string' && entry[key] !== '',
      `the \`${target}\` leg declares no \`${key}:\` label, which is what its job's \`runs-on:\` reads`,
    ).toBe(true);
    return { target, image: /** @type {string} */ (entry[key]) };
  });

  const targets = legs.map((leg) => leg.target);
  expect(
    new Set(targets).size,
    `\`${jobId}\`'s matrix spells a target twice (${targets.join(', ')}) — a claim about one of them would be about whichever leg came first`,
  ).toBe(legs.length);
  return legs;
}

/**
 * Assert that every leg of a job's build matrix runs on an image GitHub still
 * serves, and on the one its own target requires.
 *
 * Every leg rather than the one a caller names: the reader already walks the
 * whole include list, and a retired label is the same defect on the Ubuntu and
 * Windows legs as on the macOS one.
 *
 * @param {Record<string, unknown>} workflow a parsed workflow
 * @param {string} jobId the job carrying the matrix
 * @returns {{ target: string, image: string }[]} the legs that were checked
 */
export function expectSupportedRunnerImages(workflow, jobId) {
  const legs = matrixLegs(workflow, jobId);
  for (const { target, image } of legs) {
    expect(
      isRetiredRunnerImage(image),
      `the \`${target}\` leg pins \`${image}\`, a retired runner image: GitHub terminates a job queued on one rather than giving it a runner, so the archive this leg produces — and the Homebrew formula and Scoop manifest rendered from it — is never built`,
    ).toBe(false);
    const shape = TARGET_RUNNER_IMAGES[target];
    expect(
      shape,
      `no runner image shape is declared for the target \`${target}\` — add one beside the others in helpers/runner-images.js rather than leaving the leg unchecked`,
    ).toBeDefined();
    expect(
      shape.test(labelOf(image)),
      `the \`${target}\` leg pins \`${image}\`, which is not the explicitly pinned image that target needs (${String(shape)}) — an archive built here is published under the architecture the runner had, not the one the target names`,
    ).toBe(true);
  }
  return legs;
}
