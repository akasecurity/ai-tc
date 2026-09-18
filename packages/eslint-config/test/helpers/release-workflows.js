import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT, trackedFiles } from './lint-invocations.js';

// The ONE reader of the release workflows, shared by the suites next to it for
// the reason the lint-invocation walk is one: two readers of the same YAML are
// free to disagree about where a step ends and about which publish a `case`
// block feeds, which is how a publish step ends up routed by one guard and
// audited by neither. Both questions asked here have a single answer — which
// packages a release publishes, and which shell decides each publish's
// dist-tag — and every suite that asks gets it from here.
//
// Everything is pure over its inputs except `releaseWorkflows`, which reads the
// real checkout. Nothing here executes anything: running an extracted `case` is
// the caller's business, so a suite that only wants the inventory pays no
// subprocess.

/** A release workflow's path: the files a `release-*` tag drives. */
export const RELEASE_WORKFLOW_PATH = /^\.github\/workflows\/release-[^/]+\.ya?ml$/;

/**
 * Every git-tracked release workflow, repo-relative and posix, sorted.
 *
 * Derived from the tracked tree rather than a list: a release workflow added
 * tomorrow is audited without an edit here, and one deleted stops being
 * asserted rather than failing as a missing file.
 * @returns {string[]}
 */
export const releaseWorkflows = () =>
  trackedFiles()
    .filter((f) => RELEASE_WORKFLOW_PATH.test(f))
    .sort();

/**
 * One workflow's steps, each as the raw slice of the file it occupies.
 *
 * A step is a six-space list item under `steps:`. Its body runs until the next
 * such item or until the first line that dedents out of the steps list — a new
 * job, or a job-level key — so a `run: |` block keeps its own indentation and a
 * step never swallows the job that follows it. Blank and comment lines are
 * skipped when looking for that dedent: a comment sitting at column zero
 * between two steps would otherwise end the slice early, and the `case` block a
 * caller is looking for lives BELOW the comments that describe it in every one
 * of these files.
 * @param {string} source the workflow file's text
 * @returns {string[]}
 */
export function stepSlices(source) {
  const lines = source.split('\n');
  /** @type {number[]} */
  const starts = [];
  lines.forEach((line, index) => {
    if (/^ {6}- /.test(line)) starts.push(index);
  });
  return starts.map((start, n) => {
    let end = n + 1 < starts.length ? starts[n + 1] : lines.length;
    for (let i = start + 1; i < end; i += 1) {
      const line = lines[i];
      if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
      if (/^ {0,4}\S/.test(line)) {
        end = i;
        break;
      }
    }
    return lines.slice(start, end).join('\n');
  });
}

/**
 * Every `case … esac` block in a slice of shell, with the word it switches on.
 *
 * The closing `esac` is matched at the OPENING `case`'s own indentation, so a
 * nested block cannot end the outer one early and a block whose `esac` was
 * deleted is not silently closed by the next one further down.
 * @param {string} text
 * @returns {{ block: string, subject: string }[]}
 */
export function caseBlocks(text) {
  const pattern = /^([^\S\n]*)case[^\S\n]+(\S+)[^\S\n]+in[^\S\n]*$[\s\S]*?^\1esac[^\S\n]*$/gm;
  return [...text.matchAll(pattern)].map((m) => ({ block: m[0], subject: m[2] }));
}

/**
 * The shell variable a `"$name"` / `"${name}"` / `$name` reference reads, or
 * undefined for anything else — a literal, a command substitution, a parameter
 * expansion carrying an operator.
 *
 * Returning undefined rather than guessing is what lets a caller bind a value
 * through the ENVIRONMENT: a subject it cannot name is a subject it cannot set,
 * and interpolating a version into the shell text instead would make the test's
 * own fixture part of the script under test.
 * @param {string} token
 * @returns {string|undefined}
 */
export function shellVariableOf(token) {
  const m = /^"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?$/.exec(token);
  return m ? m[1] : undefined;
}

/**
 * A publish invocation, the step it sits in, and the shell that decides its
 * dist-tag.
 *
 * @typedef {object} PublishStep
 * @property {string} workflow repo-relative posix path of the workflow
 * @property {string} name the step's `name:`, or '' when it declares none
 * @property {string} packageName the `pnpm --filter <name> publish` target
 * @property {string} step the step's own slice of the workflow
 * @property {string} command the publish line, as written
 * @property {string|undefined} tagVariable the variable the `--tag` argument reads
 * @property {string|undefined} caseBlock the `case … esac` that assigns it
 * @property {string|undefined} caseSubject the variable that case switches on
 */

/** A `pnpm --filter <name> publish` invocation. */
const PUBLISH = /pnpm\s+--filter\s+(\S+)\s+publish\b[^\n]*/g;

/**
 * Every publish invocation across the tracked release workflows, ordered by
 * workflow path and then by position within it, so a failure names a stable
 * coordinate whatever order the filesystem hands the files back in.
 *
 * The `case` block paired with a publish is the one assigning the variable that
 * publish's own `--tag` reads — not simply the first block in the step. That
 * pairing is what makes the guard survive a rename: spell the variable
 * differently in both places and it still resolves, drop the block and it
 * resolves to nothing, which is the defect.
 * @returns {PublishStep[]}
 */
export function publishSteps() {
  /** @type {PublishStep[]} */
  const found = [];
  for (const workflow of releaseWorkflows()) {
    const source = readFileSync(join(REPO_ROOT, workflow), 'utf8');
    for (const step of stepSlices(source)) {
      const nameMatch = /^ {6}- name:[^\S\n]*(.*)$/m.exec(step);
      const name = nameMatch ? nameMatch[1].trim() : '';
      for (const publish of step.matchAll(PUBLISH)) {
        const command = publish[0];
        const tagMatch = /--tag\s+(\S+)/.exec(command);
        const tagVariable = tagMatch ? shellVariableOf(tagMatch[1]) : undefined;
        const blocks = caseBlocks(step);
        const feeding = tagVariable
          ? blocks.filter((b) => new RegExp(String.raw`(^|\s)${tagVariable}=`, 'm').test(b.block))
          : [];
        found.push({
          workflow,
          name,
          packageName: publish[1],
          step,
          command,
          tagVariable,
          caseBlock: feeding.length === 1 ? feeding[0].block : undefined,
          caseSubject: feeding.length === 1 ? shellVariableOf(feeding[0].subject) : undefined,
        });
      }
    }
  }
  return found;
}

/**
 * Every publish invocation in a workflow's raw text, ignoring step structure.
 *
 * Read for one purpose: a publish the step walk above does not attribute to a
 * step is a publish both suites go quiet about, and the step walk is the half of
 * this reader that can drift. Counting the same invocations a second way — over
 * the text, with no notion of a step — is what turns that drift into a failure
 * rather than a shorter loop.
 * @param {string} source the workflow file's text
 * @returns {string[]}
 */
export const publishCommands = (source) => [...source.matchAll(PUBLISH)].map((m) => m[0]);

/**
 * Each tracked release workflow with the publish invocations its text carries.
 * @returns {{ workflow: string, commands: string[] }[]}
 */
export function publishCommandsByWorkflow() {
  return releaseWorkflows().map((workflow) => ({
    workflow,
    commands: publishCommands(readFileSync(join(REPO_ROOT, workflow), 'utf8')),
  }));
}

/**
 * The package names the release workflows publish.
 *
 * The publish invocation is read rather than a workflow's prose or the name of
 * the file it lives in — it is the one signal that is code in all of them, and
 * it is what npm actually serves.
 * @returns {Set<string>}
 */
export const publishedPackageNames = () => new Set(publishSteps().map((s) => s.packageName));
