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

// One step of a workflow, and nothing else.
//
// Steps are list items at six spaces, so splitting on that anchor gives one
// slice per step running from its own first key to the next step's `- `. Deeper
// list items — a `subject-path:`/`files:` block scalar's lines, a build matrix's
// `- { os: … }` at ten — are indented past the anchor and cannot split it.
//
// The slice matters rather than being tidy: matching a value against a whole job
// is INERT wherever a neighbouring step names the same string, which is the
// normal case for a list of assets published by one step and attested by
// another. Read inside the step or read nothing.
//
// @param {string} source a job body, or the whole workflow
export function steps(source) {
  return source.split(/^ {6}- /m).slice(1);
}

/** A name as a regular-expression literal. */
const escape = (name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The one step carrying a `name:`, asserted to occur exactly once.
 *
 * Exactly one rather than the first: every assertion a caller makes over a slice
 * is a presence check, and one against a slice that captured the WRONG step
 * passes for the wrong reason.
 *
 * @param {string} source a job body, or the whole workflow
 * @param {string} name the step's `name:` value
 */
export function stepNamed(source, name) {
  const matching = steps(source).filter((step) =>
    new RegExp(`^name: ${escape(name)}[^\\S\\n]*$`, 'm').test(step),
  );
  expect(
    matching,
    `the workflow has no single step named \`${name}\` — the slice below would read nothing`,
  ).toHaveLength(1);
  return matching[0];
}

/**
 * The same step, read from the workflow's OWN BYTES, comments and all.
 *
 * Every structural reader here goes through the comment-dropping job reader, and
 * for structure that is what keeps a sentence about a step from being mistaken
 * for the step. A `run:` script is the one place it would be wrong: a `#` line
 * inside a shell block is part of that shell block, so executing a copy with
 * them removed is executing something the repository does not contain.
 *
 * @param {string} source the workflow file's own text
 * @param {string} name the step's `name:` value
 */
export function rawStepNamed(source, name) {
  // The control that makes executing an extracted `run:` faithful: this has to
  // be the file's own text and not a job body another reader has already
  // stripped, which is what the `jobs:` key at column 0 distinguishes. Handed a
  // stripped body, every executing case below a caller would run a script this
  // repository does not contain.
  expect(
    /^jobs:[^\S\n]*$/m.test(source),
    'this reader takes the workflow file, not a job body',
  ).toBe(true);
  return stepNamed(source, name);
}

/**
 * The entries of one block-scalar input of a step, and only those.
 *
 * An entry sitting under a NEIGHBOURING key in the same step is not one of them,
 * and the difference is the whole property: the same three lines moved under a
 * mistyped or neighbouring key leave the action with no input at all, at which
 * point it falls back to a default nobody chose.
 *
 * @param {string} step one step slice
 * @param {string} key the input key
 */
export function blockScalarLines(step, key) {
  const opener = new RegExp(`^([^\\S\\n]*)${escape(key)}: \\|[^\\S\\n]*$`, 'm').exec(step);
  expect(opener, `the step declares no \`${key}:\` block scalar`).not.toBeNull();
  const indent = opener[1].length;
  const entries = [];
  for (const line of step
    .slice(opener.index + opener[0].length)
    .split('\n')
    .slice(1)) {
    if (line.trim() === '') continue;
    // A line indented no further than the opener closes the scalar.
    if (line.search(/\S/) <= indent) break;
    entries.push(line.trim());
  }
  // Non-emptiness first. Every assertion the caller makes over this list is
  // satisfied vacuously by an empty one, which is the exact failure a glob list
  // emptied of its entries would be.
  expect(entries.length, `\`${key}:\` opens a block scalar with no entries`).toBeGreaterThan(0);
  return entries;
}

/**
 * One block-scalar input of a step as TEXT, dedented, relative indentation kept.
 *
 * The sibling above returns trimmed entries, which is right for a glob list and
 * wrong for a script: a `case` arm's own indentation is part of the bytes a
 * shell is handed, and the body's offset is read from its first non-empty line
 * rather than assumed, because YAML takes it from there too.
 *
 * @param {string} step one step slice
 * @param {string} key the input key
 */
export function blockScalarText(step, key) {
  const opener = new RegExp(`^([^\\S\\n]*)${escape(key)}: \\|[^\\S\\n]*$`, 'm').exec(step);
  expect(opener, `the step declares no \`${key}:\` block scalar`).not.toBeNull();
  const keyIndent = opener[1].length;
  const body = [];
  for (const line of step
    .slice(opener.index + opener[0].length)
    .split('\n')
    .slice(1)) {
    // A non-blank line indented no further than the opener closes the scalar.
    if (line.trim() !== '' && line.search(/\S/) <= keyIndent) break;
    body.push(line);
  }
  while (body.length > 0 && body[body.length - 1].trim() === '') body.pop();
  // Non-emptiness first, for the reason the entry reader asserts it: a script
  // that came back empty is a shell that exits 0 and routes nothing, which every
  // acceptance case reading it would take for a pass.
  expect(body.length, `\`${key}:\` opens a block scalar with no body`).toBeGreaterThan(0);
  const offsets = body.filter((line) => line.trim() !== '').map((line) => line.search(/\S/));
  return body.map((line) => line.slice(Math.min(...offsets))).join('\n');
}
