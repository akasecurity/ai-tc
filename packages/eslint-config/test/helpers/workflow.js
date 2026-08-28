import { expect } from 'vitest';

// One reader for "what is a job block in a GitHub workflow", shared by every
// suite that asks. Two readers of one YAML file are free to disagree about where
// a job body ends and about what counts as a comment, which is how a job ends up
// covered by one guard and inspected vacuously by another — the second copy of
// this lived in packaged-cli-egress.test.js without the body assertions below,
// so its absence checks would have passed on a block that captured nothing.
//
// These ASSERT rather than throw, deliberately, and unlike the doc parser next
// door: they are called from `it` bodies, where an assertion is a test failure.
// Called from a `describe` body an assertion is a collection error, which vitest
// reports as `(0 test)` and which takes every other suite in the file down with
// it — so call these inside the case, not beside it.

/**
 * Drop `#` comment lines.
 *
 * Line-based rather than a regex over the whole text: `/^\s*#.*$/gm` lets `\s*`
 * span newlines, so it can start on a blank line and swallow up to a `#` further
 * down. Stripping is load-bearing rather than tidying — the block readers match
 * patterns against text whose own comments name the very thing being looked for.
 *
 * @param {string} text
 */
export const dropComments = (text) =>
  text
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');

/**
 * One job's body, comments dropped.
 *
 * @param {string} source the workflow file's text
 * @param {string} key the job id
 */
export function jobBlock(source, key) {
  // Escaped even though GitHub constrains job ids to [A-Za-z_][A-Za-z0-9_-]*,
  // where nothing is a metacharacter: the cost is one call, and a caller that
  // ever passes a step name instead would otherwise get `.` as a wildcard.
  const pattern = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const block = new RegExp(
    `^ {2}${pattern}:[^\\S\\n]*$([\\s\\S]*?)(?=^ {2}\\S|\\s*$(?![\\s\\S]))`,
    'm',
  ).exec(source);
  expect(block, `no job \`${key}\` in the workflow`).not.toBeNull();
  const body = dropComments(block[1]);
  // The structural positive control, and the reason this is worth sharing at
  // all: every caller below it asserts something is ABSENT from the body, and an
  // absence assertion passes on a body that was never captured.
  //
  // A job comes in two shapes and only one of them has steps. A job that CALLS a
  // reusable workflow carries a four-space `uses:` and neither `runs-on:` nor
  // `steps:` — GitHub rejects a job carrying both — so demanding a runner of it
  // fails a valid job rather than catching a truncated block. Accepting either
  // shape keeps the control: a body cut short matches neither, which is the
  // property every absence check downstream rests on.
  const isRunnerJob = / {4}runs-on: /m.test(body);
  const isCallerJob = / {4}uses: /m.test(body);
  expect(
    isRunnerJob || isCallerJob,
    `\`${key}\` captured neither a runs-on nor a uses — not a job body`,
  ).toBe(true);
  if (isRunnerJob) {
    expect(body, `\`${key}\` captured no steps — the body was cut short`).toMatch(/^ {6}- /m);
  }
  return body;
}
