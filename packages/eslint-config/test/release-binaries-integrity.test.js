// The binary channel's integrity story is four things, and every one of them is
// invisible in a green run once removed.
//
// 1. The release job ATTESTS the assets it publishes. Nothing in the tree executes
//    that step: release-binaries.yml has no `pull_request` trigger and the step is
//    gated on `push`, so its first run is the first real `bin-v*` tag — after four
//    build runners have already spent. A missing permission, an unpinned action or a
//    dropped subject glob all surface there and nowhere earlier.
// 2. The packaged Windows binary has Node's Authenticode signature taken off BEFORE
//    the blob injection, which is the order Node's single-executable-application
//    docs give. Injecting first leaves a signature that fails verification, which
//    reads as tampering rather than as the unsigned binary this channel ships.
// 3. The same holds for macOS, where it already did — and the one edit that breaks
//    it is a tidy-up: moving the strip down beside the ad-hoc re-sign, where a
//    reader would expect both signing calls to live.
// 4. The channel takes BARE tags only, and a suffixed one is refused before the
//    fan-out spends four runners. There is no pre-release lane here: both install
//    one-liners resolve their default ref by taking the newest `bin-v*` release and
//    read no pre-release flag, and both are fetched from `bin-latest` — so a
//    `bin-v0.10.0-beta.1` tag would make the beta the default install and serve the
//    beta commit's own installer. That refusal is SHELL, so it is executed rather
//    than read: a token check passes on a pattern with the wrong arm order, and the
//    only question worth asking is which tags this block actually lets through.
//
//    WHICH TAGS IT LETS THROUGH IS HALF OF IT, AND THE OTHER HALF IS STRUCTURAL.
//    Every executing case hands bash the `run:` body directly, so all of them stay
//    green over a step that never runs and over a failure nothing acts on — three
//    one-line edits reach that (a gate that is false on a push, `continue-on-error`
//    on the job being waited for, a job-level `if:` on the waiter), and all three
//    were measured green against the executed cases. So whether the block is
//    REACHED, and whether its `exit 1` stops anything, are asserted separately from
//    what it decides.
//
// The STEP SLICE below is load-bearing rather than tidy. Matching a subject glob
// against the whole release job is INERT: the Create GitHub Release step three lines
// down lists `dist/aka-*.tar.gz`, `dist/aka-*.zip` and `dist/SHA256SUMS` in its own
// `files:`, so deleting a glob from `subject-path` leaves all three strings in the
// job and a job-wide assertion green — while every Windows release ships unattested.
// Read inside the step or read nothing.
//
// Two readings go one level finer than the step, because a step slice is still not
// the position these defects live in. The subject globs are read as the ENTRIES of
// the `subject-path` block scalar, so the same three lines moved under a mistyped or
// neighbouring key are not mistaken for them; and package-sea.mjs is read with its
// comment lines dropped, so a call that was commented OUT is not mistaken for one
// that runs.

import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';

import { afterAll, describe, expect, it } from 'vitest';

// jobBlock drops `#` lines before returning a body, which is load-bearing here
// rather than cosmetic: this workflow's own comments name the attest step, both
// permission scopes and the neighbouring Release step in prose, so a reader that
// kept them would satisfy several assertions below against sentences.
//
// The step and block-scalar readers live beside it rather than here: a second
// suite reads the same workflow, and two readers of one YAML file are free to
// disagree about where a step ends — which is how a step ends up covered by one
// guard and inspected vacuously by another.
import {
  blockScalarLines,
  blockScalarText,
  dropComments,
  jobBlock,
  rawStepNamed as rawStepIn,
  stepNamed,
  steps,
} from './helpers/workflow.js';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'release-binaries.yml');
const PACKAGE_SEA = join(REPO_ROOT, 'cli', 'scripts', 'package-sea.mjs');

const readWorkflow = () => readFileSync(WORKFLOW, 'utf8');

// Whole-line comments dropped, for the reason jobBlock drops the YAML kind: every
// claim below package-sea.mjs is either an ORDER or a PRESENCE, and both are
// satisfied by a line that was commented out. `// if (isWin)
// stripWindowsSignature(exePath);` still contains the call, still sits above the
// inject, and reports green while no Windows binary is ever stripped; the three
// outcome lines demoted to a comment report green while the strip is silent.
// Both were measured green before this reader existed.
//
// Line-based rather than a regex over the whole text, and only a line whose FIRST
// non-space characters open a comment: a trailing `// …` after real code leaves the
// code, which is right, and a `//` inside a string literal is never at the start of
// a line in this file.
const dropJsComments = (text) =>
  text
    .split('\n')
    .filter((line) => !/^\s*(?:\/\/|\/\*|\*)/.test(line))
    .join('\n');

const readPackageSea = () => dropJsComments(readFileSync(PACKAGE_SEA, 'utf8'));

// The index of a needle that occurs EXACTLY ONCE, asserted found first.
//
// Both halves are load-bearing. An indexOf that returns -1 satisfies
// `toBeLessThan`, which is the shape that reads as an ordering check and is not
// one; and a second occurrence makes indexOf answer about whichever came first, so
// an ordering claim over it is about a position nobody chose.
const soleIndexOf = (source, needle, where) => {
  const first = source.indexOf(needle);
  expect(first, `${where} does not contain \`${needle}\``).toBeGreaterThanOrEqual(0);
  expect(
    source.indexOf(needle, first + 1),
    `${where} contains \`${needle}\` more than once — indexOf answers about the wrong one`,
  ).toBe(-1);
  return first;
};

// A step read from the workflow's OWN BYTES, comments and all.
//
// Every other reader here goes through the comment-dropping job reader, and for
// structure that is what keeps a sentence about a step from being mistaken for
// the step. A `run:` script is the one place it would be wrong: a `#` line inside
// a shell block is part of that shell block, so executing a copy with them
// removed is executing something this repository does not contain.
//
// Split over the whole file rather than one job: a step name is asserted to occur
// exactly once, which is the stronger claim anyway, and the only other six-space
// list item in this workflow is the tag filter under `on:` — a slice carrying no
// `name:` line at all.
const rawStepNamed = (name) => rawStepIn(readWorkflow(), name);

// Every job id the workflow declares, in file order.
//
// Derived rather than listed, because the absence checks below are per job: a
// list would have gone on naming two jobs the day a third was added, leaving the
// new one inspected by nothing. Scoped to the `jobs:` mapping, since `on:` and
// `concurrency:` carry two-space keys of their own.
function jobIds() {
  const jobs = /^jobs:[^\S\n]*$([\s\S]*)$/m.exec(dropComments(readWorkflow()));
  expect(jobs, 'release-binaries.yml declares no jobs block').not.toBeNull();
  const ids = [...jobs[1].matchAll(/^ {2}([A-Za-z_][A-Za-z0-9_-]*):[^\S\n]*$/gm)].map((m) => m[1]);
  expect(ids.length, 'the jobs block captured no job id').toBeGreaterThan(0);
  return ids;
}

// The job ids one job declares a `needs:` edge to.
//
// Accepted in every shape GitHub takes — a scalar, a flow sequence, a block
// sequence — because which one is written is a formatting choice while the edge
// is the property. An absent key returns an empty list, which the caller asserts
// against: that is the defect being read for.
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

// The one `if:` condition inside a slice, asserted to occur exactly once.
//
// A gate is not a spelling to match but a VALUE to compare, because the property
// is that two steps fire under the same condition rather than that either is
// written a particular way. Exactly once, for the reason soleIndexOf demands it:
// a slice carrying two gates answers about whichever came first.
//
// `if: ` with the colon, so the shell's own `if [ … ]` inside a `run:` block —
// which this reader sees, because a job body carries its steps' scripts — is not
// mistaken for a step key.
function soleIfCondition(slice, where) {
  const all = [...slice.matchAll(/^[^\S\n]*if: (.+?)[^\S\n]*$/gm)].map((m) => m[1]);
  expect(all, `${where} declares no single \`if:\` gate`).toHaveLength(1);
  return all[0];
}

const releaseJob = () => jobBlock(readWorkflow(), 'release');
const buildJob = () => jobBlock(readWorkflow(), 'build');
const verifyTagJob = () => jobBlock(readWorkflow(), 'verify-tag');

// A first-party GitHub attestation action, pinned by full commit SHA with the version
// it resolves to alongside. Either spelling is accepted: `actions/attest` is where the
// vendor points new workflows and `actions/attest-build-provenance` is the wrapper on
// top of it, so which one is in use is a decision to make in a diff rather than a
// property to break a guard.
//
// `[0-9a-f]{40}` is the whole point. A tag — even `@v4.2.2` — is a movable pointer:
// whoever can move it chooses what signs this repository's releases, with a workflow
// file that has not changed.
// `[^\S\n]*` rather than `\s*` for every line anchor read out of a step slice:
// splitting on the `- ` prefix leaves the step's FIRST line unindented and every
// later line carrying its original eight spaces, and `\s*` would let an anchor run
// back across newlines and match a key belonging to a different step.
const PINNED_ATTEST_ACTION =
  /^[^\S\n]*uses: actions\/attest(?:-build-provenance)?@[0-9a-f]{40} # v\d+\.\d+\.\d+$/m;

// The two scopes the attestation needs, as they appear under a job's `permissions:`
// (job keys at four spaces, their entries at six). A trailing `#` comment is allowed
// because dropComments only removes a line whose FIRST non-space character is `#`,
// and this repo annotates each scope in place.
const permissionLine = (scope) => new RegExp(`^ {6}${scope}: write(?:[^\\S\\n]+#.*)?$`, 'm');

const ATTEST_SCOPES = ['id-token', 'attestations'];

// The assets this release is known to publish, kept as the NON-VACUITY CONTROL
// for the two derived reads below and nothing more. SHA256SUMS is on it for a
// reason that is easy to trim: the installers verify an archive against it, so an
// attested archive beside an unattested sums file leaves the file the whole trust
// chain pivots on outside the attestation.
//
// It is a FLOOR on each list rather than an equality with either. The property is
// that the attested set and the published set AGREE, and pinning either of them
// to a literal here would put the drift straight back into a hand-maintained
// list: this was that list, and a fourth asset added to the Release step alone
// shipped unattested with all 22 cases green. Measured, not supposed.
// `dist-latest/SHA256SUMS` is on it for the same reason and one more: the alias
// archives are renamed copies, so the versioned attestation covers their bytes —
// but the checksum file naming them is DIFFERENT bytes, produced here and
// covered by nothing else.
const SUBJECT_GLOBS = [
  'dist/aka-*.tar.gz',
  'dist/aka-*.zip',
  'dist/SHA256SUMS',
  'dist-latest/SHA256SUMS',
];

const attestStep = () => stepNamed(releaseJob(), 'Attest build provenance');
const releaseStep = () => stepNamed(releaseJob(), 'Create GitHub Release');
const rollingStep = () => stepNamed(releaseJob(), 'Publish the rolling bin-latest release');

/** The release job's one artifact upload: the rendered manifests. */
function manifestUploadStep() {
  const matching = steps(releaseJob()).filter((step) =>
    /^[^\S\n]*uses: actions\/upload-artifact@v\d+$/m.test(step),
  );
  expect(matching, 'the release job uploads no single artifact').toHaveLength(1);
  return matching[0];
}

// The release-cutting action, pinned by full commit SHA with the version it
// resolves to alongside — the property `PINNED_ATTEST_ACTION` states, for the
// other vendor action this job runs.
const PINNED_RELEASE_ACTION =
  /^[^\S\n]*uses: softprops\/action-gh-release@[0-9a-f]{40} # v\d+\.\d+\.\d+$/m;

/**
 * Every step of the release job that cuts a Release through that action.
 *
 * DERIVED rather than named, because the property below is about what this job
 * publishes in total: a second publish step naming assets the first does not is
 * exactly the drift that leaves bytes downloadable with no provenance, and a
 * reader pinned to one step's name cannot see it. Two is the floor rather than
 * the count — a third would be read, not ignored.
 */
function releasePublishSteps() {
  const matching = steps(releaseJob()).filter((step) => PINNED_RELEASE_ACTION.test(step));
  expect(
    matching.length,
    'the release job runs fewer than two pinned action-gh-release steps — the union below would read one release or none',
  ).toBeGreaterThanOrEqual(2);
  return matching;
}

/** The globs the attestation covers, as the entries of its own `subject-path`. */
const attestedGlobs = () => blockScalarLines(attestStep(), 'subject-path');

/** Everything this job publishes, as the union of every Release step's `files`. */
const publishedGlobs = () => [
  ...new Set(releasePublishSteps().flatMap((step) => blockScalarLines(step, 'files'))),
];

describe('the release job attests the assets it publishes', () => {
  it('carries a step named for the attestation, which every case below reads inside', () => {
    // The structural control for the presence checks that follow: a slice holding
    // only its own `name:` line would satisfy none of them for a reason worth
    // telling apart from a missing glob.
    expect(attestStep()).toMatch(/^[^\S\n]*uses: /m);
  });

  it('pins the action by commit SHA, not by a movable tag', () => {
    expect(attestStep()).toMatch(PINNED_ATTEST_ACTION);
  });

  // Read as the block scalar's entries rather than as text anywhere in the step, so
  // a glob is neither satisfied by a longer one that contains it (`dist/SHA256SUMS`
  // by `dist/SHA256SUMS.asc`) nor by the same line parked under another key.
  it.each(SUBJECT_GLOBS)('names %s as a subject-path entry', (glob) => {
    expect(attestedGlobs()).toContain(glob);
  });

  // And EXACTLY the set the Releases publish, which is the half the per-asset
  // cases cannot state — in BOTH directions, because the two failures are
  // different: an asset published but not attested ships without provenance,
  // while one attested but not published makes this release claim to have
  // produced bytes nobody can download.
  //
  // DERIVED from the publishing steps rather than compared with a literal. That
  // is the whole repair: an extra `files:` entry is a real drift, and the
  // literal this used to compare against could not see one. Read as the UNION
  // over every publishing step, because this job now cuts two Releases and a
  // reader pinned to one of them calls the other's assets unpublished while
  // they sit on a download page.
  it('attests exactly the assets the Releases publish, and nothing else', () => {
    const attested = attestedGlobs();
    const published = publishedGlobs();

    // The control. Two reads that both came back empty agree with each other
    // perfectly, and `blockScalarLines` refusing an empty scalar is only half of
    // that — a scalar holding one unrelated line is non-empty too.
    for (const glob of SUBJECT_GLOBS) {
      expect(attested, `subject-path no longer names ${glob}`).toContain(glob);
      expect(published, `no Release step publishes ${glob} any more`).toContain(glob);
    }

    expect(
      published.filter((glob) => !attested.includes(glob)),
      'published by a Release step and NOT attested — these ship without provenance',
    ).toEqual([]);
    expect(
      attested.filter((glob) => !published.includes(glob)),
      'attested and NOT published — provenance for bytes this release does not publish',
    ).toEqual([]);
  });

  // The agreement above is between two lists of GLOB STRINGS, and a glob that
  // matches nothing agrees with itself perfectly. So the Windows leg failing to
  // upload leaves `dist/aka-*.zip` on both lists, the sets still equal, and a
  // three-archive release published under a tag that promises four. This is the
  // key that turns the textual agreement into a claim about bytes, and it is a
  // refusal newly added to the path every binary release has already taken.
  it('refuses to publish the versioned Release with an asset list that matched nothing', () => {
    expect(releaseStep()).toMatch(/^[^\S\n]*fail_on_unmatched_files: true$/m);
  });

  // The versioned Release carries the rendered formula and manifest as audit
  // copies beside the archives. The union agreement above cannot see them go:
  // dropped from this step's `files:` and the `subject-path` together, the two
  // lists still agree and the floor names neither. So they are read from the
  // artifact the publish jobs push from — the one list that must hold them.
  it('publishes the rendered manifests on the versioned Release too', () => {
    const rendered = blockScalarLines(manifestUploadStep(), 'path');
    const versioned = blockScalarLines(releaseStep(), 'files');

    expect(rendered.length, 'the artifact carries no rendered file').toBeGreaterThan(0);
    expect(
      rendered.filter((file) => !versioned.includes(file)),
      'rendered and pushed to a package manager, but not on the versioned Release',
    ).toEqual([]);
  });

  // The alias archives are the versioned bytes under a name that does not
  // change, so the versioned attestation already covers them by digest. Naming
  // them one by one rather than by a shared glob is what keeps the two lists
  // from AGREEING while covering half the set: `dist-latest/aka-*.tar.gz` on
  // both sides reads as a match whatever the directory actually holds.
  //
  // EXACTLY the staged set, not a floor over it. The names are the ones the
  // executing cases further down assert the staging block writes, so the two
  // ends of this hand-off are held to one list: a rolling entry renamed on this
  // side alone names a file the staging block never produces, which
  // `fail_on_unmatched_files` would only report once a tag had been pushed.
  it('names each rolling asset literally, so a glob cannot stand in for four', () => {
    const rolling = blockScalarLines(rollingStep(), 'files');

    expect(
      rolling.filter((entry) => entry.includes('*')),
      'these rolling entries are globs — a glob covers whatever is there, not what was staged',
    ).toEqual([]);
    expect([...rolling].sort()).toEqual([...ALIAS_ASSETS].map(stagedPath).sort());
    for (const entry of rolling) {
      expect(attestedGlobs(), `${entry} is published on bin-latest and not attested`).toContain(
        entry,
      );
    }
  });

  // The release body is written by the staging block too, and it is the one
  // staged file `files:` does not carry — so the case above cannot see it, and a
  // `body_path` naming something that block never writes fails the action at
  // release time rather than here.
  it('takes its release body from a file the staging block writes', () => {
    expect(rollingStep()).toMatch(
      new RegExp(`^[^\\S\\n]*body_path: ${stagedPath(ALIAS_NOTES)}$`, 'm'),
    );
  });

  // Without this the step runs on workflow_dispatch too, where no Release is cut:
  // it would mint an OIDC identity and sign a dry run's artifacts, publishing
  // provenance for bytes nobody can download.
  it('runs only on a tag push, so the dry run signs nothing', () => {
    expect(attestStep()).toMatch(/^[^\S\n]*if: github\.event_name == 'push'$/m);
  });

  // Ordering, not mere presence. Attesting AFTER the Release means a failed
  // attestation leaves published, unattested assets behind — and the assets are
  // already downloadable by the time it runs.
  it('attests before the Release is created, never after', () => {
    const job = releaseJob();
    const attest = soleIndexOf(job, '- name: Attest build provenance', 'the release job');
    const release = soleIndexOf(job, '- name: Create GitHub Release', 'the release job');
    expect(attest).toBeLessThan(release);
  });

  it.each(ATTEST_SCOPES)('grants %s: write on the release job', (scope) => {
    expect(releaseJob()).toMatch(permissionLine(scope));
  });

  // The build fan-out is four runners that only compile and upload, and the tag
  // check reads one environment variable. Neither scope belongs on either, and a
  // scope granted to a matrix job is granted to every leg of it.
  //
  // Read over every job but the release, DERIVED from the file: named jobs, this
  // case would have gone on inspecting two of them the day a third was added —
  // which is exactly what adding the tag-refusal job did. Absence-only, so it is
  // paired with the release job as the positive control: without that pair a
  // reader whose job blocks all captured nothing would pass this.
  it.each(ATTEST_SCOPES)('grants %s: write on no job but the release', (scope) => {
    expect(releaseJob(), `the release job does not grant ${scope}: write either`).toMatch(
      permissionLine(scope),
    );

    const others = jobIds().filter((id) => id !== 'release');
    expect(others.length, 'the workflow declares no job besides the release').toBeGreaterThan(0);

    const granting = others.filter((id) =>
      permissionLine(scope).test(jobBlock(readWorkflow(), id)),
    );
    expect(granting, `these jobs grant ${scope}: write and must not`).toEqual([]);
  });

  // The other place a scope can be granted, and the one the per-job check cannot
  // see: a write scope at the TOP LEVEL is inherited by every job that declares no
  // `permissions:` of its own — which is the build fan-out — so it reaches the four
  // runners by a key neither job block contains. Granting both scopes there was
  // measured green against the per-job checks alone.
  it('grants no write scope at the workflow top level, so the fan-out inherits none', () => {
    const block = /^permissions:[^\S\n]*$([\s\S]*?)(?=^\S)/m.exec(dropComments(readWorkflow()));
    expect(block, 'release-binaries.yml declares no top-level permissions block').not.toBeNull();
    // The control: an absence check over a block that captured nothing passes.
    expect(block[1], 'the top-level permissions block captured no scope').toMatch(
      /^ {2}contents: read$/m,
    );
    expect(block[1]).not.toMatch(/:[^\S\n]*write/);
  });
});

// A tag the channel accepts, and the ones it must not.
//
// The refused list is every shape that has a way of reading as a release and is
// not one: the three pre-release identifiers the npm side routes to `beta`,
// `nightly` and `rc`, a build-metadata suffix, a two-component version, a word,
// and the bare prefix with nothing after it. Each of those would today build on
// four runners, cut a Release, and move `bin-latest` — the tag the install
// one-liners fetch themselves from.
const BARE_TAGS = ['bin-v0.9.12', 'bin-v1.0.0'];
const REFUSED_TAGS = [
  'bin-v0.10.0-beta.1',
  'bin-v1.0.0-rc.1',
  'bin-v0.10.0-nightly.20260918.gabc1234',
  'bin-v0.9.12+build.7',
  'bin-v0.9',
  'bin-vlatest',
  'bin-v',
];

const BASH = '/bin/bash';

/**
 * Skip on a host that cannot run the extracted shell.
 *
 * A skip rather than a bare return: a returning body is a PASSING body, so on
 * Windows every executing case here would report as covered while asserting
 * nothing.
 * @param {{ skip: (note?: string) => void }} ctx
 */
function requirePosixShell(ctx) {
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the extracted block is POSIX shell, as GitHub runs it`);
  }
}

/** The refusal step's own `run:` script, as the workflow spells it. */
const refusalScript = () =>
  blockScalarText(rawStepNamed('Refuse a tag that is not a bare version'), 'run');

/**
 * The environment an extracted block runs under: an empty PATH, plus the tag.
 *
 * The tag is bound through the ENVIRONMENT and never written into the script,
 * the way GITHUB_REF_NAME reaches it on a runner. Interpolating it would put the
 * fixture inside the program under test, so a tag carrying a quote or a `$`
 * would be testing this harness instead.
 *
 * `PATH` is bound to the EMPTY STRING rather than left out. Leaving it out does
 * not give the script an empty search path: bash falls back to a compiled-in
 * default when PATH is unset, and that default includes the WORKING DIRECTORY —
 * measured here as `/usr/gnu/bin:/usr/local/bin:/bin:/usr/bin:.`. Bound empty,
 * the block runs on builtins alone.
 *
 * Read that as HYGIENE and not as a sandbox. The script is repository text this
 * suite already trusts to run; what the empty environment buys is that the
 * answer cannot come out differently because of what happens to be installed on
 * the machine running the suite, or of what sits in the directory it runs from.
 * It confines nothing.
 *
 * One function rather than an object literal per call site, so the case below
 * pins the PATH this really hands the shell rather than one it built itself.
 * @param {string} tag
 */
const shellEnv = (tag) => ({ PATH: '', GITHUB_REF_NAME: tag });

/**
 * What the refusal does with one tag: `refused` plus the status and the output.
 * @param {string} tag
 */
function runRefusal(tag) {
  const script = refusalScript();
  try {
    const stdout = execFileSync(BASH, ['-c', script], {
      encoding: 'utf8',
      env: shellEnv(tag),
      timeout: 30_000,
    });
    return { refused: false, status: 0, stdout };
  } catch (err) {
    return { refused: true, status: err.status, stdout: String(err.stdout ?? '') };
  }
}

describe('the binary channel refuses a tag that is not a bare version', () => {
  it('carries a refusal step, which every case below reads inside', () => {
    // The structural control for the executing cases: a slice that captured only
    // its own `name:` line would leave `blockScalarText` with nothing to return,
    // and a shell handed an empty script exits 0 — which every acceptance case
    // would read as a pass.
    const script = refusalScript();
    expect(script).toContain('GITHUB_REF_NAME');
    expect(script).toMatch(/^case /m);
    expect(script).toMatch(/\bexit 1\b/);
  });

  // `it.for` rather than `it.each`, so the case body is handed the test context
  // and can skip: these RUN the block, and a host with no bash must report a skip
  // rather than a pass.
  it.for(BARE_TAGS)('%s is a bare version and builds', (tag, ctx) => {
    requirePosixShell(ctx);
    const { refused, stdout } = runRefusal(tag);

    expect(refused, `${tag} was refused and must not be:\n${stdout}`).toBe(false);
  });

  it.for(REFUSED_TAGS)('%s is refused before the build fan-out', (tag, ctx) => {
    requirePosixShell(ctx);
    const { refused, status, stdout } = runRefusal(tag);

    expect(refused, `${tag} was accepted and must not be:\n${stdout}`).toBe(true);
    // A refusal, not a shell that died: bash reports a syntax error as 2 and a
    // kill as a null status, and both would satisfy `refused` while proving the
    // block runs at all rather than what it decides.
    expect(status, `${tag} ended the shell some way other than \`exit 1\``).toBe(1);
    // And it says why, on the channel a runner surfaces. A silent exit 1 is a
    // release that stops with nothing for the person who tagged it to read.
    expect(stdout).toMatch(/^::error::/m);
    expect(stdout).toContain(tag);
  });

  it('runs the refusal on builtins alone, with no reachable PATH', (ctx) => {
    requirePosixShell(ctx);
    // The environment `runRefusal` really hands the shell, not one built here: a
    // control over its own literal would go on passing after `PATH: ''` was
    // dropped from the call site it describes.
    const env = shellEnv('bin-v0.9.12');
    const under = (script) =>
      execFileSync(BASH, ['-c', script], { encoding: 'utf8', env, timeout: 30_000 }).trim();

    // Bound, and bound EMPTY — an absent key is what leaves bash's compiled-in
    // fallback search path in force, `.` and all.
    expect(env.PATH, 'the extracted shell is handed a PATH it can resolve tools through').toBe('');

    // And what that leaves reachable, in both directions: a builtin still runs,
    // nothing installed on the machine does. Without the second half an `env`
    // key misspelled `Path` would satisfy every case above.
    expect(under('printf ok')).toBe('ok');
    expect(under('case "$GITHUB_REF_NAME" in bin-v*) printf yes ;; *) printf no ;; esac')).toBe(
      'yes',
    );
    expect(() => under('uname -s')).toThrow();
  });

  // The refusal is worth one runner and not four, so the fan-out waits on it.
  // Read as the EDGE rather than as step order, because the two jobs run on
  // different machines and nothing but `needs:` sequences them.
  it('the build fan-out needs the refusal, so it cannot start first', () => {
    const needs = needsOf(buildJob());

    expect(needs.length, 'the build job declares no needs: edge at all').toBeGreaterThan(0);
    expect(needs).toContain('verify-tag');
  });

  // It reads one environment variable and checks out nothing, so it is granted
  // nothing. The per-scope case above covers the two attestation scopes; this is
  // the whole job, against any write at all.
  it('grants the refusal job no write scope of any kind', () => {
    const job = verifyTagJob();

    // The control: an absence check over a body that captured nothing passes.
    // jobBlock demands a runner and a step, and this demands the step is the one
    // the executing cases read.
    expect(job).toMatch(/^ {6}- name: Refuse a tag that is not a bare version$/m);
    expect(job).not.toMatch(/:[^\S\n]*write/);
  });

  // WHETHER the block runs, which every executing case above takes for granted.
  //
  // Each of those reads the `run:` body and hands it to bash, so a gate that is
  // false on a tag push leaves all eleven of them green while no tag is ever
  // checked — `if: github.event_name == 'never'` was measured green against the
  // whole file. Compared with the attest step's gate rather than matched against
  // a literal: the property is that the two fire under the SAME condition, and
  // the attest case a few lines up is what pins that condition to a real push.
  it('fires on the same event the Release does, so a tag push really reaches it', () => {
    const gate = soleIfCondition(verifyTagJob(), 'the refusal job');

    expect(gate).toBe(soleIfCondition(attestStep(), 'the attest step'));
  });

  // And that nothing downstream is allowed past a refusal. The `needs:` edge is
  // the only thing sequencing the two jobs, and two keys make an edge advisory:
  // `continue-on-error` on the job being waited for, which reports success when
  // it failed, and a job-level `if:` on the waiter, which runs it whatever the
  // result was. Both were measured green against the edge case above.
  //
  // Derived over every job rather than the two named ones, so a third job cannot
  // arrive carrying either key uninspected.
  it('makes that edge binding — no job may fail softly or run regardless', () => {
    const ids = jobIds();
    expect(ids.length, 'the workflow declares no jobs').toBeGreaterThan(0);

    const soft = ids.filter((id) => /continue-on-error/.test(jobBlock(readWorkflow(), id)));
    expect(
      soft,
      'these jobs report success when they fail, which satisfies any needs: edge',
    ).toEqual([]);

    // A job-level key, at four spaces: a step's own `if:` sits at eight and is
    // what the case above reads.
    expect(
      buildJob(),
      'the fan-out carries a job-level if:, so it can run whatever the refusal decided',
    ).not.toMatch(/^ {4}if:/m);
  });

  // The executing cases stand in for the runner by spawning `/bin/bash`, which is
  // what GitHub's own default (`bash -e {0}` on ubuntu) is. A `shell:` override
  // would make the block a different language from the one they run, so they
  // would go on passing over a script the runner never interprets that way.
  it('leaves the refusal on the runner default shell the cases above stand in for', () => {
    const job = verifyTagJob();

    expect(job).toMatch(/^ {6}- name: Refuse a tag that is not a bare version$/m);
    expect(job).not.toMatch(/^[^\S\n]*shell:/m);
  });

  // Defence in depth, and the reason it is worth having: `bin-latest` is where
  // the install one-liners fetch install.sh and install.ps1 from, so moving it
  // onto a pre-release commit serves the pre-release INSTALLER as well as the
  // pre-release binary. Executed, like the refusal, because the property is which
  // versions reach the `git push` and not which words the block contains.
  it('moves bin-latest for a bare version only', (ctx) => {
    requirePosixShell(ctx);
    const step = rawStepNamed('Point bin-latest at this release');
    const move = blockScalarText(step, 'run');

    // The control: the two git lines are what a bare version must reach, and the
    // substitution below is what makes running this safe. If they are not there
    // the case is reading something else.
    expect(move).toContain('git tag -f bin-latest');
    expect(move).toContain(LEASE_PUSH);

    const probe = move.replace(
      /git tag -f bin-latest\n(\s*)git push --force-with-lease="refs\/tags\/bin-latest:\$\{LEASE\}" origin refs\/tags\/bin-latest/,
      'echo MOVED',
    );
    expect(probe, 'the git pair was not substituted, so this would push').not.toContain('git push');

    const movedFor = (tag) =>
      execFileSync(BASH, ['-c', probe], {
        encoding: 'utf8',
        env: shellEnv(tag),
        timeout: 30_000,
      }).includes('MOVED');

    for (const tag of BARE_TAGS) {
      expect(movedFor(tag), `${tag} is a release and must move bin-latest`).toBe(true);
    }
    for (const tag of ['bin-v0.10.0-beta.1', 'bin-v1.0.0-rc.1', 'bin-v0.9.12-nightly.1']) {
      expect(movedFor(tag), `${tag} is a pre-release and must not move bin-latest`).toBe(false);
    }
  });
});

describe('the packaged binary is stripped before the blob is injected', () => {
  // The order Node's single-executable-application docs give, on both platforms:
  // remove the signature, then inject. The macOS half is the one already shipping
  // and the one a refactor moves, because a reader expects `--remove-signature` to
  // sit beside the ad-hoc `--sign` two steps below it.
  it('strips the macOS signature before injecting, not after', () => {
    const source = readPackageSea();
    expect(soleIndexOf(source, "'--remove-signature'", 'package-sea.mjs')).toBeLessThan(
      soleIndexOf(source, 'await inject(', 'package-sea.mjs'),
    );
  });

  it('strips the Windows signature before injecting too', () => {
    const source = readPackageSea();
    expect(soleIndexOf(source, 'stripWindowsSignature(exePath)', 'package-sea.mjs')).toBeLessThan(
      soleIndexOf(source, 'await inject(', 'package-sea.mjs'),
    );
  });
});

// The Windows strip cannot be exercised anywhere in this workspace: it needs a
// win32 host AND an installed Windows SDK, and the only leg that has both is
// build-binaries.yml's win32-x64 matrix entry, which runs the real packaging. So
// what is pinned here is the shape the reasoning rests on — plus the one piece of it
// that IS executable from any host, the version comparator.
describe('the Windows signature strip is best-effort and resolved by path', () => {
  // A named function's own declaration, sliced from its `function` keyword to the
  // next column-0 `}`. This file has an unrelated try/finally around the dependency
  // install, so a claim over the whole file would answer about that one.
  const declarationOf = (name) => {
    const source = readPackageSea();
    const start = soleIndexOf(source, `function ${name}(`, 'package-sea.mjs');
    const end = source.indexOf('\n}', start);
    expect(end, `${name} has no closing brace at column 0`).toBeGreaterThan(start);
    return source.slice(start, end + 2);
  };

  const stripFunction = () => {
    const body = declarationOf('stripWindowsSignature');
    // The control: a slice cut short would satisfy the absence check below while
    // saying nothing about the spawn it is supposed to be describing.
    expect(body, 'the stripWindowsSignature slice captured no spawn').toContain('execFileSync(');
    return body;
  };

  // Architecture principle 7: Windows searches the working directory ahead of PATH,
  // so a bare `signtool.exe` runs whatever sits in the repository the build started
  // from. The spawn takes the enumerated absolute path instead.
  it('spawns the resolved path rather than a bare name', () => {
    const body = stripFunction();
    expect(body).toMatch(/execFileSync\(signtool, \['remove', '\/s'/);
    expect(body).not.toMatch(/execFileSync\(\s*['"`]signtool/);
  });

  // A failure here must never fail the build, so the spawn sits inside a try/catch
  // within this function — not merely somewhere in the file.
  it('cannot fail the build, because the spawn is caught', () => {
    const body = stripFunction();
    const tryAt = body.indexOf('try {');
    const spawnAt = body.indexOf('execFileSync(signtool');
    const catchAt = body.indexOf('} catch');
    expect(tryAt, 'the spawn is not wrapped in a try').toBeGreaterThanOrEqual(0);
    expect(spawnAt, 'no signtool spawn in stripWindowsSignature').toBeGreaterThanOrEqual(0);
    expect(catchAt, 'the try has no catch').toBeGreaterThanOrEqual(0);
    expect(tryAt).toBeLessThan(spawnAt);
    expect(spawnAt).toBeLessThan(catchAt);
  });

  // Four outcomes, four distinct lines. A silent no-op and a silent success read
  // identically in a build log, which is the whole reason this prints at all — so a
  // branch that stopped reporting is a defect rather than a tidier function. Read
  // from the comment-stripped source, or the four phrases survive as prose about a
  // function that has gone quiet.
  it.each([
    ['stripped', /windows signature: stripped by/],
    ['signtool not found', /windows signature: not stripped — no SDK/],
    ['SDK lookup threw', /windows signature: not stripped — SDK lookup failed/],
    ['strip failed', /windows signature: strip failed/],
  ])('says which of the four outcomes happened: %s', (_label, pattern) => {
    expect(stripFunction()).toMatch(pattern);
  });

  // The LOOKUP is inside the try, not just the spawn.
  //
  // Positional, and then driven: the read says where the call sits and the drive
  // says what happens when it throws. Enumerating the SDK directories reads the
  // filesystem, so `readdirSync` can fail on its own — EACCES on a locked-down
  // machine, or ENOENT when a directory goes between the `existsSync` and the
  // read — and with the call outside the try that ended `package:sea`, which is
  // the negation of this function's own best-effort contract. Reproduced against
  // the shipped shape before this existed.
  it('resolves signtool inside the try, not ahead of it', () => {
    const body = stripFunction();
    const tryAt = body.indexOf('try {');
    const lookupAt = body.indexOf('findSigntool()');
    const catchAt = body.indexOf('} catch');

    expect(tryAt, 'the strip function opens no try').toBeGreaterThanOrEqual(0);
    expect(lookupAt, 'the strip function never calls findSigntool()').toBeGreaterThanOrEqual(0);
    expect(catchAt, 'the try has no catch').toBeGreaterThanOrEqual(0);
    expect(tryAt).toBeLessThan(lookupAt);
    expect(lookupAt).toBeLessThan(catchAt);
  });

  /**
   * Run the real `stripWindowsSignature` over injected dependencies.
   *
   * The three declarations are sliced out of the source and evaluated in a fresh
   * context whose globals ARE the seams — so the enumeration, the spawn and the
   * reporting channel are all this suite's, and the branching is the file's. It
   * runs from any host: nothing here touches a Windows path or spawns anything.
   *
   * This is what a positional read cannot do. The call moving back outside the
   * try is one edit, and the only observable difference is whether a throw
   * escapes — which nothing that matches text can see.
   * @param {{ readdirSync: () => unknown, execFileSync: () => unknown }} seams
   */
  const runStrip = (seams) => {
    const source = readPackageSea();
    const code =
      `${declarationOf('bySdkVersionDesc')}\n` +
      `${declarationOf('findSigntool')}\n` +
      `${declarationOf('stripWindowsSignature')}\n` +
      'stripWindowsSignature';
    const printed = [];
    const fn = runInNewContext(code, {
      existsSync: () => true,
      readdirSync: seams.readdirSync,
      join: (...parts) => parts.filter((part) => part !== '').join('\\'),
      execFileSync: seams.execFileSync,
      process: { stdout: { write: (line) => printed.push(line) } },
    });
    expect(typeof fn, 'the sliced declarations did not evaluate to a function').toBe('function');
    fn('C:\\out\\aka.exe');
    return printed;
  };

  const sdkEntries = () => [{ isDirectory: () => true, name: '10.0.26100.0' }];

  it('reports a stripped signature on the happy path', () => {
    // The positive control for the two failure cases: with both seams behaving,
    // the function reaches its success line. Without it a body that printed
    // nothing but the failure line would satisfy them both.
    const printed = runStrip({ readdirSync: sdkEntries, execFileSync: () => undefined });

    expect(printed).toHaveLength(1);
    expect(printed[0]).toMatch(/windows signature: stripped by/);
  });

  it('swallows an enumeration failure instead of ending the packaging run', () => {
    const boom = () => {
      const err = new Error('EACCES: permission denied, scandir');
      err.code = 'EACCES';
      throw err;
    };

    const printed = runStrip({ readdirSync: boom, execFileSync: () => undefined });

    expect(printed).toHaveLength(1);
    expect(printed[0]).toMatch(/windows signature: not stripped/);
    expect(printed[0]).toContain('EACCES');
  });

  it('swallows a failed strip and names it as that, not as a missing SDK', () => {
    const failing = () => {
      const err = new Error('signtool exited 1');
      err.status = 1;
      throw err;
    };

    const printed = runStrip({ readdirSync: sdkEntries, execFileSync: failing });

    expect(printed).toHaveLength(1);
    expect(printed[0]).toMatch(/windows signature: strip failed/);
  });

  // Resolution walks the SDK's version directories and takes the highest, and the
  // comparator is the only part of this that can be RUN from a non-Windows host —
  // it reads no filesystem and spawns nothing. So it is run, in a fresh context over
  // its own source, rather than having its name matched: a body swapped for
  // `b.localeCompare(a)` keeps the name, keeps the `.sort(bySdkVersionDesc)` call
  // site, orders 10.0.9999.0 above 10.0.26100.0, and was measured green against a
  // name match.
  const sdkComparator = () => {
    const declaration = declarationOf('bySdkVersionDesc');
    // The control: a slice that captured no comparison would return undefined for
    // every pair, which `Array.prototype.sort` reads as "leave the order alone" —
    // and an already-sorted fixture would then satisfy the assertions below.
    expect(declaration, 'the comparator slice returns nothing').toMatch(/\breturn\b/);
    const fn = runInNewContext(`${declaration}\nbySdkVersionDesc`);
    expect(typeof fn, 'the comparator slice did not evaluate to a function').toBe('function');
    return fn;
  };

  it('orders SDK version directories numerically, newest first', () => {
    const cmp = sdkComparator();
    // The pair a string sort gets backwards, which is the defect this exists for.
    expect(['10.0.9999.0', '10.0.26100.0'].sort(cmp)).toEqual(['10.0.26100.0', '10.0.9999.0']);
    // Deliberately handed to sort() in ascending order, so a comparator that sorted
    // ASCENDING — the other one-character mutation — cannot pass by leaving it be.
    expect(['10.0.19041.0', '10.0.22621.0', '10.0.26100.0'].sort(cmp)).toEqual([
      '10.0.26100.0',
      '10.0.22621.0',
      '10.0.19041.0',
    ]);
    // A shorter version string is the older SDK, not the newer one: the missing
    // segment has to compare as zero rather than as absent.
    expect(['10.0.26100', '10.0.26100.1'].sort(cmp)).toEqual(['10.0.26100.1', '10.0.26100']);
  });

  // And that the comparator is REACHED. A correct one the enumeration never calls
  // leaves resolution on whatever order the directory happens to be read in.
  it('sorts the enumerated version directories with that comparator', () => {
    const source = readPackageSea();
    expect(source).toContain('Windows Kits\\\\10\\\\bin');
    expect(source).toMatch(/\.sort\(bySdkVersionDesc\)/);
  });
});

// The four targets the build fan-out produces, and the archive each one is
// packed into — a zip on Windows and a tarball everywhere else.
const TRIPLES = ['darwin-arm64', 'linux-x64', 'linux-arm64', 'win32-x64'];
const archiveSuffix = (triple) => (triple.startsWith('win32-') ? 'zip' : 'tar.gz');

// The version-less names the rolling release renames them to, derived from the
// versioned ones rather than written out twice: a fixture whose archive names
// do not match what the block strips would make it stage nothing, and every
// assertion below would then be about a directory the block never filled.
const versionedArchive = (version, triple) => `aka-${version}-${triple}.${archiveSuffix(triple)}`;
const aliasArchive = (triple) => `aka-${triple}.${archiveSuffix(triple)}`;
const ALIAS_ARCHIVES = TRIPLES.map(aliasArchive);

// Everything the rolling release carries: the four renamed archives, the
// checksum file naming them, and the two package-manager manifests plus the
// plain-text version the tools' own update checks read.
const ALIAS_ASSETS = [...ALIAS_ARCHIVES, 'SHA256SUMS', 'aka.rb', 'aka.json', 'VERSION'];

// The body the rolling release is published with. Staged beside the assets and
// deliberately not one of them — nothing downloads it, so the `files:` case
// cannot see it and the `body_path` case reads it here instead.
const ALIAS_NOTES = 'RELEASE_NOTES.md';

// Where the staging block puts them, which is the one place this directory name
// is spelled: the structural cases read the workflow's `files:`/`body_path` and
// the executing cases read the fixture it filled, and they have to be the same
// directory or neither is checking the other.
const ALIAS_DIR = 'dist-latest';
const stagedPath = (name) => `${ALIAS_DIR}/${name}`;

// A search path the executing cases build for themselves rather than inheriting.
//
// The sibling refusal cases bind PATH to the empty string, which is right for a
// block that runs on builtins alone and impossible here: staging copies files
// and proves them with `sha256sum`, so the block needs real tools. Built rather
// than inherited so the answer cannot come out differently because of what a
// developer happens to have earlier on their own PATH, and it carries the
// running Node first because the block reads `cli/package.json` through it.
const TOOL_PATH = [
  dirname(process.execPath),
  '/usr/local/bin',
  '/usr/bin',
  '/bin',
  '/usr/sbin',
  '/sbin',
].join(':');

/** Where a tool resolves on that path, or null. */
function resolveTool(name) {
  for (const dir of TOOL_PATH.split(':')) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Skip on a host missing a tool the extracted block runs.
 *
 * `sha256sum` is the one worth naming: it is GNU rather than POSIX, so a host
 * that has `shasum` and not this is a real configuration rather than a fault.
 * A skip and never a bare return — a returning body is a PASSING body, and this
 * case's whole value is that it RAN the block.
 * @param {{ skip: (note?: string) => void }} ctx
 * @param {string[]} tools
 */
function requireTools(ctx, tools) {
  requirePosixShell(ctx);
  for (const tool of tools) {
    if (resolveTool(tool) === null) {
      ctx.skip(`needs ${tool} on a real PATH; the extracted block runs it`);
    }
  }
}

// Every fixture directory the executing cases create, removed once the file has
// run: the cases read what a block wrote after it returns, so a per-call removal
// would delete the evidence before the assertions reach it.
const SCRATCH_DIRS = [];
afterAll(() => {
  for (const dir of SCRATCH_DIRS) rmSync(dir, { recursive: true, force: true });
});

/** A fresh temp directory, removed after the file has run. */
function scratchDir(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  SCRATCH_DIRS.push(dir);
  return dir;
}

/** The `$GITHUB_OUTPUT` a step wrote, as a mapping. */
function readStepOutputs(file) {
  const out = {};
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (line === '') continue;
    const at = line.indexOf('=');
    expect(at, `\`${line}\` is not a key=value output line`).toBeGreaterThan(0);
    out[line.slice(0, at)] = line.slice(at + 1);
  }
  return out;
}

/**
 * A throwaway release directory the staging block can run against.
 *
 * The checksums are produced by the same `sha256sum` the block verifies with,
 * so what the case proves is that the copies the block made are the bytes the
 * file describes — not that two implementations of the digest agree.
 * @param {string} version
 * @param {string[]} triples the targets whose archives the build delivered
 */
function releaseFixture(version, triples) {
  const root = scratchDir('aka-rolling-');
  mkdirSync(join(root, 'cli'), { recursive: true });
  writeFileSync(
    join(root, 'cli', 'package.json'),
    `${JSON.stringify({ name: '@akasecurity/cli', version }, null, 2)}\n`,
  );

  const dist = join(root, 'dist');
  mkdirSync(dist);
  const archives = triples.map((triple) => versionedArchive(version, triple));
  archives.forEach((name, index) => writeFileSync(join(dist, name), `archive ${index}\n`));
  writeFileSync(
    join(dist, 'SHA256SUMS'),
    execFileSync(resolveTool('sha256sum'), archives, { cwd: dist, encoding: 'utf8' }),
  );
  for (const rendered of ['aka.rb', 'aka.json', 'VERSION']) {
    writeFileSync(join(dist, rendered), `${rendered}\n`);
  }
  return { root, dist, archives };
}

/** The staging step's own `run:` script, as the workflow spells it. */
const stagingScript = () =>
  blockScalarText(rawStepNamed('Stage the rolling bin-latest assets'), 'run');

/**
 * Run the staging block over a fresh fixture.
 * @param {{ tag: string, version?: string, corrupt?: boolean, triples?: string[] }} options
 */
function runStaging({ tag, version = '0.9.12', corrupt = false, triples = TRIPLES }) {
  const { root, dist, archives } = releaseFixture(version, triples);
  // A SOURCE archive, disagreeing with the checksums the build wrote. The
  // staged copies cannot be tampered with instead: the block is what creates
  // them, so by the time they exist it has already finished.
  if (corrupt) writeFileSync(join(dist, archives[0]), 'a short or truncated download\n');

  const outputFile = join(root, 'step-output');
  writeFileSync(outputFile, '');

  const run = {
    cwd: root,
    encoding: 'utf8',
    env: {
      PATH: TOOL_PATH,
      GITHUB_REF_NAME: tag,
      GITHUB_OUTPUT: outputFile,
      GITHUB_REPOSITORY: 'akasecurity/ai-tc',
    },
    timeout: 120_000,
  };

  try {
    const stdout = execFileSync(BASH, ['-c', stagingScript()], run);
    return { root, staged: true, status: 0, stdout, outputs: readStepOutputs(outputFile) };
  } catch (err) {
    return {
      root,
      staged: false,
      status: err.status,
      stdout: `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`,
      outputs: readStepOutputs(outputFile),
    };
  }
}

describe('the release job renders the package-manager manifests', () => {
  const renderStep = () => rawStepNamed('Render the package-manager manifests');

  // The runner image ships a Node, and which one is not this repository's
  // choice. The renderer runs under type stripping, so the line it runs on is
  // pinned the way the build fan-out pins the runtime it embeds.
  it('pins the runtime the renderer runs under', () => {
    const matching = steps(releaseJob()).filter((step) =>
      /^[^\S\n]*uses: actions\/setup-node@v\d+$/m.test(step),
    );
    expect(matching, 'the release job runs no single setup-node step').toHaveLength(1);
    expect(matching[0]).toMatch(/^[^\S\n]*node-version: 24$/m);
    // This job installs nothing, so a package-manager cache has no lockfile
    // install to serve and would only restore a store nothing reads.
    expect(matching[0], 'the release job caches a store it never installs into').not.toMatch(
      /^[^\S\n]*cache:/m,
    );
  });

  // Every OTHER step this job runs after the download is gated on `push`, so the
  // workflow_dispatch dry run is the one thing that exercises the renderer
  // before a tag exists. Gate it and a renderer that crashes, or a checksum file
  // it refuses, first surfaces on a real tag — after four build runners have
  // spent, with the Release step next in line.
  it('renders on the dry run too, which is the only rehearsal it gets', () => {
    expect(renderStep(), 'the renderer no longer runs on a workflow_dispatch').not.toMatch(
      /^[^\S\n]*if:/m,
    );
  });

  // Ordering, three times over, and each edge is a different failure. Before
  // the version check the job would spend an install on a tag it is about to
  // refuse; after the render it would run the renderer on whatever Node the
  // image happens to ship.
  it('installs that runtime after the version check and before the render', () => {
    const job = releaseJob();
    const check = soleIndexOf(job, '- name: Verify tag matches package version', 'the release job');
    const setup = soleIndexOf(job, '- uses: actions/setup-node@v6', 'the release job');
    const render = soleIndexOf(
      job,
      '- name: Render the package-manager manifests',
      'the release job',
    );

    expect(check).toBeLessThan(setup);
    expect(setup).toBeLessThan(render);
  });

  // The renderer reads the checksum file, and the attestation covers what it
  // writes. Rendering before the aggregation leaves it nothing to read;
  // rendering after the attestation publishes a formula nobody signed.
  it('renders after the checksums are aggregated and before the attestation', () => {
    const job = releaseJob();
    const aggregate = soleIndexOf(job, '- name: Aggregate SHA256SUMS', 'the release job');
    const render = soleIndexOf(
      job,
      '- name: Render the package-manager manifests',
      'the release job',
    );
    const attest = soleIndexOf(job, '- name: Attest build provenance', 'the release job');

    expect(aggregate).toBeLessThan(render);
    expect(render).toBeLessThan(attest);
  });

  // Staging copies the rendered files into the rolling set, and the artifact the
  // publish jobs download is those same files: either one ahead of the render
  // reads files that do not exist yet.
  it('renders before anything that copies or uploads what it wrote', () => {
    const job = releaseJob();
    const render = soleIndexOf(
      job,
      '- name: Render the package-manager manifests',
      'the release job',
    );
    const stage = soleIndexOf(
      job,
      '- name: Stage the rolling bin-latest assets',
      'the release job',
    );
    const attest = soleIndexOf(job, '- name: Attest build provenance', 'the release job');
    const upload = soleIndexOf(job, '- uses: actions/upload-artifact@', 'the release job');

    expect(render).toBeLessThan(stage);
    expect(stage).toBeLessThan(attest);
    expect(render).toBeLessThan(upload);
  });

  // The version comes from the manifest rather than from the tag, which is what
  // lets the dry run render at all — and the repository comes through the
  // environment, because a `${{ }}` expression is pasted into the script before
  // the shell reads it.
  it('reads the version from the package manifest and the repository from the environment', () => {
    // Read with the script's own comment lines dropped: a `#` line quoting the
    // manifest read would otherwise satisfy these while `version` came from the
    // tag, which on the dry run is a branch name.
    const script = dropComments(blockScalarText(renderStep(), 'run'));

    expect(script).toMatch(
      /^version=\$\(node -p "require\('\.\/cli\/package\.json'\)\.version"\)$/m,
    );
    expect(script).not.toMatch(/^version=.*GITHUB_REF/m);
    expect(script).toMatch(/^[^\S\n]*--version "\$version" \\$/m);
    expect(script).toMatch(/^[^\S\n]*--sums dist\/SHA256SUMS \\$/m);
    expect(script).toMatch(/^[^\S\n]*--repo "\$GITHUB_REPOSITORY" \\$/m);
    // Where the attest subjects, the versioned Release and the artifact read
    // the rendered files from.
    expect(script).toMatch(/^[^\S\n]*--out dist$/m);
    expect(script).not.toContain('${{');
  });
});

describe('the rolling bin-latest assets are the versioned bytes, renamed', () => {
  it('carries a staging step, which every case below reads inside', () => {
    // The structural control for the executing cases: a slice that captured only
    // its own `name:` line would leave `blockScalarText` with nothing to return,
    // and a shell handed an empty script exits 0 — which the acceptance case
    // would read as a pass.
    const script = stagingScript();

    expect(script).toContain('GITHUB_REF_NAME');
    expect(script).toContain('sha256sum -c');
    expect(script).toContain('GITHUB_OUTPUT');
  });

  // Ungated for the reason the renderer is: this block refuses a short copy and
  // a source archive that no longer matches its checksum, and the dry run is
  // where those refusals are worth having. The publish gate does not rest on it
  // being skipped — the step below reads the EVENT as well as this step's
  // answer, which is what keeps a dispatch from reaching bin-latest.
  it('stages on the dry run too, so its refusals are exercised before a tag', () => {
    expect(
      rawStepNamed('Stage the rolling bin-latest assets'),
      'staging no longer runs on a workflow_dispatch',
    ).not.toMatch(/^[^\S\n]*if:/m);
  });

  it('stages every alias asset and proves each copy against its checksum', (ctx) => {
    requireTools(ctx, ['sha256sum', 'basename', 'cp', 'mkdir', 'wc']);
    const { root, staged, status, stdout, outputs } = runStaging({ tag: 'bin-v0.9.12' });

    expect(staged, `the staging block exited ${status}:\n${stdout}`).toBe(true);

    for (const asset of ALIAS_ASSETS) {
      expect(existsSync(join(root, ALIAS_DIR, asset)), `${asset} was not staged`).toBe(true);
    }
    // The body the rolling release is published with, which is not one of the
    // assets and would go unnoticed by the loop above.
    expect(existsSync(join(root, ALIAS_DIR, ALIAS_NOTES)), `${ALIAS_NOTES} was not staged`).toBe(
      true,
    );

    // Verified again here, independently of the block's own check: dropping
    // `sha256sum -c` from the script leaves every assertion above satisfied by
    // four files of any content whatever.
    const verified = execFileSync(resolveTool('sha256sum'), ['-c', 'SHA256SUMS'], {
      cwd: join(root, ALIAS_DIR),
      encoding: 'utf8',
      env: { PATH: TOOL_PATH },
      timeout: 60_000,
    });
    for (const archive of ALIAS_ARCHIVES) expect(verified).toContain(archive);

    expect(outputs.publish).toBe('yes');
    expect(outputs.version).toBe('0.9.12');
  });

  // A source archive that disagrees with the checksums the build wrote is a
  // short or corrupted download between two runners, and it must stop here
  // rather than on a user's machine.
  it('refuses to stage a source archive that no longer matches its checksum', (ctx) => {
    requireTools(ctx, ['sha256sum', 'basename', 'cp', 'mkdir', 'wc']);
    const { staged, status, outputs } = runStaging({ tag: 'bin-v0.9.12', corrupt: true });

    expect(staged, 'a tampered source archive was staged anyway').toBe(false);
    expect(status, 'the block ended some way other than a non-zero exit').toBeGreaterThan(0);
    // And nothing downstream is told to publish it.
    expect(outputs.publish ?? 'no').not.toBe('yes');
  });

  // A target whose archive never arrived — its checksum line missing with it,
  // which is what aggregating the uploads that DID land produces. Every file
  // present verifies, so only the count stands between this and a rolling
  // release a documentation link on the missing platform resolves to nothing on.
  it('refuses a release that delivered fewer than four archives', (ctx) => {
    requireTools(ctx, ['sha256sum', 'basename', 'cp', 'mkdir', 'wc']);
    const delivered = TRIPLES.filter((triple) => triple !== 'win32-x64');
    expect(delivered, 'the fixture dropped no target').toHaveLength(TRIPLES.length - 1);

    const { staged, status, stdout, outputs } = runStaging({
      tag: 'bin-v0.9.12',
      triples: delivered,
    });

    expect(staged, 'a three-archive release was staged as complete').toBe(false);
    expect(status, 'the block ended some way other than a non-zero exit').toBeGreaterThan(0);
    expect(stdout).toMatch(/::error::/);
    expect(outputs.publish ?? 'no').not.toBe('yes');
  });

  // The refs this step really receives. A tag push carries the tag; the only
  // other trigger this workflow has carries a BRANCH name, and a branch is what
  // the arm order has to route away — `main` has no hyphen in it, so a `case`
  // that merely refuses a hyphen sends a feature build to the download surface
  // a documentation page links to.
  it.for([
    ['bin-v0.9.12', 'yes'],
    ['bin-v1.0.0', 'yes'],
    ['bin-v0.10.0-beta.1', 'no'],
    ['bin-v1.0.0-rc.1', 'no'],
    ['bin-v0.9', 'no'],
    ['bin-vlatest', 'no'],
    ['main', 'no'],
    ['feat/x-y', 'no'],
  ])('%s routes to publish=%s', ([ref, expected], ctx) => {
    requireTools(ctx, ['sha256sum', 'basename', 'cp', 'mkdir', 'wc']);
    const { staged, status, stdout, outputs } = runStaging({ tag: ref });

    expect(staged, `the staging block exited ${status} on ${ref}:\n${stdout}`).toBe(true);
    expect(outputs.publish, `${ref} routed the wrong way`).toBe(expected);
  });
});

describe('the rolling bin-latest release is published only by a real tag push', () => {
  // BOTH halves, and the event half is the one that matters. The staging step
  // is ungated so the dry run exercises it, which means its output alone is
  // satisfied on a workflow_dispatch from a branch whose name happens to read
  // like a version — and this job holds contents: write.
  it('gates on the event, on what staging decided, and on bin-latest moving forward', () => {
    const gate = soleIfCondition(rollingStep(), 'the rolling release step');

    expect(gate).toContain("github.event_name == 'push'");
    expect(gate).toContain("steps.rolling.outputs.publish == 'yes'");
    expect(gate).toContain("steps.advance.outputs.move == 'yes'");
    expect(gate).toContain('&&');
    // EXACTLY those three conjuncts. Containing all three is satisfied by a
    // gate that ORs a fourth term onto them — `… || github.event_name ==
    // 'workflow_dispatch'` keeps every substring above and publishes the dry
    // run's unattested build.
    expect(
      gate
        .split('&&')
        .map((term) => term.trim())
        .sort(),
    ).toEqual([
      "github.event_name == 'push'",
      "steps.advance.outputs.move == 'yes'",
      "steps.rolling.outputs.publish == 'yes'",
    ]);
  });

  // The same event the attestation fires on: the alias archives are attested by
  // digest through the versioned subjects, and the alias checksum file in its
  // own right, so publishing them on an event that attests nothing would put
  // unsigned bytes behind a link a documentation page points at.
  it('publishes on the same event the attestation covers', () => {
    const gate = soleIfCondition(rollingStep(), 'the rolling release step');

    expect(gate.startsWith(soleIfCondition(attestStep(), 'the attest step'))).toBe(true);
  });

  it('pins the release action by commit SHA, not by a movable tag', () => {
    expect(rollingStep()).toMatch(PINNED_RELEASE_ACTION);
  });

  // `prerelease` keeps this out of the repository's latest-release election,
  // which six tag prefixes share here; `make_latest: false` says the same thing
  // a second way and is what still holds if `prerelease` is ever flipped.
  // `overwrite_files` is what makes the second release of the same tag replace
  // the assets rather than fail.
  it.each([
    ['tag_name: bin-latest', /^[^\S\n]*tag_name: bin-latest$/m],
    ['prerelease: true', /^[^\S\n]*prerelease: true$/m],
    ['make_latest: false', /^[^\S\n]*make_latest: false$/m],
    ['overwrite_files: true', /^[^\S\n]*overwrite_files: true$/m],
    ['fail_on_unmatched_files: true', /^[^\S\n]*fail_on_unmatched_files: true$/m],
  ])('declares %s', (_label, pattern) => {
    expect(rollingStep()).toMatch(pattern);
  });

  // One tag carrying whatever the last release put there, so the release's own
  // title is the only place the page says which version it holds. It reads the
  // staging step's other output, which is what gives that output a consumer at
  // all — the executing case below pins the value it carries.
  it('titles itself with the version staging resolved', () => {
    expect(rollingStep()).toMatch(
      /^[^\S\n]*name: aka \$\{\{ steps\.rolling\.outputs\.version \}\}/m,
    );
  });

  // The REST releases API ignores this key when the tag already exists, so a
  // value here reads as a decision the release does not make.
  it('names no commitish, because the tag already exists by then', () => {
    expect(rollingStep()).not.toMatch(/^[^\S\n]*target_commitish:/m);
  });

  // Ordering. The tag is moved by the step above; a release cut before that
  // move names the previous commit.
  it('is published after bin-latest has been moved to this commit', () => {
    const job = releaseJob();
    const move = soleIndexOf(job, '- name: Point bin-latest at this release', 'the release job');
    const publish = soleIndexOf(
      job,
      '- name: Publish the rolling bin-latest release',
      'the release job',
    );

    expect(move).toBeLessThan(publish);
  });

  // The two publish jobs re-render nothing, so what they push has to leave this
  // runner as an artifact.
  it('uploads the rendered manifests for the jobs that publish them', () => {
    const upload = manifestUploadStep();

    expect(upload).toMatch(/^[^\S\n]*name: package-manifests$/m);
    expect(blockScalarLines(upload, 'path')).toEqual([
      'dist/aka.rb',
      'dist/aka.json',
      'dist/VERSION',
    ]);
    expect(upload).toMatch(/^[^\S\n]*if-no-files-found: error$/m);
  });
});

// The one push the move step makes: a compare-and-swap against the value the
// decision step read, never a plain force.
const LEASE_PUSH =
  'git push --force-with-lease="refs/tags/bin-latest:${LEASE}" origin refs/tags/bin-latest';

/**
 * Run the decision step against a stubbed `git` that answers for origin.
 *
 * What is executed is the ordering, which is the part that cannot be read: a
 * `sort` without the numeric keys orders 0.9.9 after 0.9.12, and a fault read
 * as "no tag yet" moves the tag with nothing to compare it against.
 * @param {{ version?: string, mode: 'found' | 'missing' | 'fault', current?: string }} options
 */
function runAdvance({ version = '0.9.12', mode, current = '' }) {
  const root = scratchDir('aka-advance-');
  const bin = join(root, 'bin');
  mkdirSync(bin);
  mkdirSync(join(root, 'cli'));
  writeFileSync(join(root, 'cli', 'package.json'), JSON.stringify({ version }));

  const outputFile = join(root, 'step-output');
  writeFileSync(outputFile, '');
  writeFileSync(
    join(bin, 'git'),
    [
      '#!/bin/sh',
      'case "$1" in',
      '  ls-remote)',
      '    case "$GIT_MODE" in',
      "      found) printf '%s\\trefs/tags/bin-latest\\n' c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00 ;;",
      '      missing) exit 2 ;;',
      "      *) echo 'fatal: unable to access origin' >&2; exit 128 ;;",
      '    esac ;;',
      '  fetch) exit 0 ;;',
      '  show) printf \'{"version":"%s"}\\n\' "$GIT_CURRENT" ;;',
      '  *) echo "unexpected git $*" >&2; exit 99 ;;',
      'esac',
      '',
    ].join('\n'),
  );
  chmodSync(join(bin, 'git'), 0o755);

  const run = {
    cwd: root,
    encoding: 'utf8',
    env: {
      PATH: [bin, TOOL_PATH].join(delimiter),
      GITHUB_OUTPUT: outputFile,
      GIT_MODE: mode,
      GIT_CURRENT: current,
    },
    timeout: 60_000,
  };
  const script = blockScalarText(rawStepNamed('Decide whether bin-latest moves forward'), 'run');
  try {
    const stdout = execFileSync(BASH, ['-c', script], run);
    return { ok: true, status: 0, stdout, outputs: readStepOutputs(outputFile) };
  } catch (err) {
    return {
      ok: false,
      status: err.status,
      stdout: `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`,
      outputs: readStepOutputs(outputFile),
    };
  }
}

describe('bin-latest only moves forward', () => {
  const TOOLS = ['cut', 'sort', 'tail'];
  const LEASE = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';

  it.for([
    ['an older release', '0.9.11', 'yes'],
    // The same version is a re-run, which is how a half-finished rolling
    // upload is repaired — refusing it would leave that state for good.
    ['the same release, re-run', '0.9.12', 'yes'],
    ['a newer release', '0.9.13', 'no'],
    // Ordered as numbers, not text: as text 0.9.9 sorts after 0.9.12.
    ['0.9.9, which sorts after 0.9.12 as text', '0.9.9', 'yes'],
    ['0.10.0, which sorts before 0.9.12 as text', '0.10.0', 'no'],
  ])('against %s (%s at bin-latest), decides move=%s for 0.9.12', ([, current, expected], ctx) => {
    requireTools(ctx, TOOLS);
    const { ok, status, stdout, outputs } = runAdvance({ mode: 'found', current });

    expect(ok, `the decision exited ${status}:\n${stdout}`).toBe(true);
    expect(outputs.move).toBe(expected);
    expect(outputs.lease, 'the lease is not the value origin answered with').toBe(LEASE);
  });

  it('moves a tag that does not exist yet, leased against its absence', (ctx) => {
    requireTools(ctx, TOOLS);
    const { ok, status, stdout, outputs } = runAdvance({ mode: 'missing' });

    expect(ok, `the decision exited ${status}:\n${stdout}`).toBe(true);
    expect(outputs.move).toBe('yes');
    expect(outputs.lease, 'an absent tag must lease against absence').toBe('');
  });

  // A failed read is not an absent tag: taken for one, it moves bin-latest
  // with nothing to compare against — backwards as easily as forwards.
  it('refuses to decide when origin cannot be read', (ctx) => {
    requireTools(ctx, TOOLS);
    const { ok, status, stdout, outputs } = runAdvance({ mode: 'fault' });

    expect(ok, 'a failed read was taken for an absent tag').toBe(false);
    expect(status).toBeGreaterThan(0);
    expect(stdout).toMatch(/::error::/);
    expect(outputs.move, 'a refused decision still wrote an answer').toBeUndefined();
  });

  it('refuses to order against a version that is not bare', (ctx) => {
    requireTools(ctx, TOOLS);
    const { ok, stdout, outputs } = runAdvance({ mode: 'found', current: '0.10.0-beta.1' });

    expect(ok, 'a pre-release at bin-latest was ordered as if it were bare').toBe(false);
    expect(stdout).toMatch(/::error::/);
    expect(outputs.move).toBeUndefined();
  });

  it('decides on the same event the release fires on', () => {
    expect(
      soleIfCondition(
        stepNamed(releaseJob(), 'Decide whether bin-latest moves forward'),
        'the decision step',
      ),
    ).toBe(soleIfCondition(attestStep(), 'the attest step'));
  });

  // EXACTLY these two: a third term ORed on (`… || always()`) keeps both
  // substrings and moves the tag whatever was decided.
  it('moves the tag only when the decision says so', () => {
    const move = stepNamed(releaseJob(), 'Point bin-latest at this release');
    const gate = soleIfCondition(move, 'the move step');

    expect(
      gate
        .split('&&')
        .map((term) => term.trim())
        .sort(),
    ).toEqual(["github.event_name == 'push'", "steps.advance.outputs.move == 'yes'"]);
    expect(move).toMatch(/^[^\S\n]*id: move$/m);
  });

  it('pushes against the lease the decision read, never with a plain force', () => {
    const step = rawStepNamed('Point bin-latest at this release');
    const script = blockScalarText(step, 'run');

    expect(step).toMatch(/^[^\S\n]*LEASE: \$\{\{ steps\.advance\.outputs\.lease \}\}$/m);
    expect(script).toContain(LEASE_PUSH);
    expect(script, 'the tag is also pushed with a plain force').not.toMatch(
      /git push\b(?:(?!--force-with-lease)[^\n])*(?:\s-f\b|--force\b(?!-with-lease))/,
    );
  });

  // Executed, because the lease is only as good as the value that reaches the
  // push: an unmapped LEASE expands to empty, which leases against the tag not
  // existing — and fails every release after the first rather than none.
  it.for([
    ['a tag that exists', LEASE, `refs/tags/bin-latest:${LEASE}`],
    ['no tag yet', '', 'refs/tags/bin-latest:'],
  ])('hands git the lease for %s', ([, lease, expected], ctx) => {
    requirePosixShell(ctx);
    const root = scratchDir('aka-move-');
    const bin = join(root, 'bin');
    mkdirSync(bin);
    const calls = join(root, 'git-calls');
    writeFileSync(join(bin, 'git'), '#!/bin/sh\necho "$*" >> "$GIT_CALLS"\n');
    chmodSync(join(bin, 'git'), 0o755);

    execFileSync(
      BASH,
      ['-c', blockScalarText(rawStepNamed('Point bin-latest at this release'), 'run')],
      {
        cwd: root,
        encoding: 'utf8',
        env: {
          PATH: [bin, TOOL_PATH].join(delimiter),
          GITHUB_REF_NAME: 'bin-v0.9.12',
          LEASE: lease,
          GIT_CALLS: calls,
        },
        timeout: 30_000,
      },
    );

    expect(readFileSync(calls, 'utf8').split('\n')).toContain(
      `push --force-with-lease=${expected} origin refs/tags/bin-latest`,
    );
  });

  it('decides, then moves, then publishes, then explains a failure, then uploads', () => {
    const job = releaseJob();
    const at = (needle) => soleIndexOf(job, needle, 'the release job');
    const order = [
      at('- name: Decide whether bin-latest moves forward'),
      at('- name: Point bin-latest at this release'),
      at('- name: Publish the rolling bin-latest release'),
      at('- name: Explain a bin-latest left half-published'),
      at('- uses: actions/upload-artifact@'),
    ];

    expect(order).toEqual([...order].sort((a, b) => a - b));
  });

  // The tag moves first and the assets follow one upload at a time, so the
  // window between them is where a run can fail and leave the two disagreeing.
  // `failure()` alone would also fire for a failure BEFORE the move, when
  // nothing has been left half-done.
  it('explains a failure only once the tag has moved', () => {
    const step = stepNamed(releaseJob(), 'Explain a bin-latest left half-published');

    expect(soleIfCondition(step, 'the explanation step')).toBe(
      "failure() && steps.move.outcome == 'success'",
    );
    expect(blockScalarText(step, 'run')).toMatch(/^echo "::error::.*re-run/im);
  });
});

// The two jobs that push a rendered manifest into a repository this workflow
// does not own.
const PUBLISH_JOBS = [
  {
    id: 'publish-homebrew-tap',
    tokenName: 'HOMEBREW_TAP_TOKEN',
    repo: 'akasecurity/homebrew-tap',
    path: 'Formula/aka.rb',
    failStep: 'Fail if the Homebrew tap token is not configured',
    pushStep: 'Push Formula/aka.rb to the tap',
    source: 'aka.rb',
  },
  {
    id: 'publish-scoop-bucket',
    tokenName: 'SCOOP_BUCKET_TOKEN',
    repo: 'akasecurity/scoop-bucket',
    path: 'bucket/aka.json',
    failStep: 'Fail if the Scoop bucket token is not configured',
    pushStep: 'Push bucket/aka.json to the bucket',
    source: 'aka.json',
  },
];

// A job's own bytes, comments and all.
//
// `jobBlock` drops `#` lines, which is right for structure and wrong for a
// script: what a `run:` block is handed includes its own comments, so a case
// executing one has to read it unaltered.
function rawJobBlock(id) {
  const block = new RegExp(
    `^ {2}${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:[^\\S\\n]*$([\\s\\S]*?)(?=^ {2}\\S|\\s*$(?![\\s\\S]))`,
    'm',
  ).exec(readWorkflow());
  expect(block, `no job \`${id}\` in the workflow`).not.toBeNull();
  expect(block[1], `\`${id}\` captured no steps — the body was cut short`).toMatch(/^ {6}- /m);
  return block[1];
}

/**
 * One plain value from a step's `env:` mapping, asserted to occur exactly once.
 * @param {string} step one step slice
 * @param {string} key the variable
 */
function stepEnvValue(step, key) {
  const all = [...step.matchAll(new RegExp(`^[^\\S\\n]*${key}: (\\S+)[^\\S\\n]*$`, 'gm'))];
  expect(all, `the step maps no single \`${key}\``).toHaveLength(1);
  return all[0][1];
}

/**
 * Every `run:` script a job declares, in either form: a `run: |` block, or a
 * one-line `run: <command>`. A reader that took only the block form would pass
 * every absence check below over a one-line step that prints the token.
 */
function runBlocksOf(jobText) {
  const blocks = steps(jobText)
    .filter((step) => /^[^\S\n]*run: /m.test(step))
    .map((step) =>
      /^[^\S\n]*run: \|[^\S\n]*$/m.test(step)
        ? blockScalarText(step, 'run')
        : (/^[^\S\n]*run: (.+)$/m.exec(step)?.[1] ?? ''),
    );
  // Non-emptiness first: every assertion below is an absence check, and an
  // absence check over no scripts at all passes.
  expect(blocks.length, 'the job declares no run: block').toBeGreaterThan(0);
  return blocks;
}

describe.each(PUBLISH_JOBS)('$id', (target) => {
  it('waits on the release and runs only for a tag push', () => {
    const job = jobBlock(readWorkflow(), target.id);

    expect(needsOf(job), `${target.id} declares no needs: edge`).toContain('release');
    expect(job).toMatch(/^ {4}if: github\.event_name == 'push'$/m);
  });

  // It writes into ANOTHER repository with a token scoped to that one. A write
  // scope on THIS repository would be a second, broader credential on the same
  // runner for no reason, and nothing is checked out, so no repository token is
  // persisted either.
  it('reads this repository and writes nothing in it', () => {
    const job = jobBlock(readWorkflow(), target.id);

    expect(job, `${target.id} declares no permissions block`).toMatch(/^ {6}contents: read$/m);
    expect(job).not.toMatch(/:[^\S\n]*write/);
    expect(job).not.toMatch(/^[^\S\n]*uses: actions\/checkout/m);
  });

  // The target is a literal rather than a repository variable, because both
  // READMEs name it and a reader cannot observe a variable.
  it('names its target repository and path in the file', () => {
    const job = jobBlock(readWorkflow(), target.id);

    expect(job).toContain(target.repo);
    expect(job).toContain(target.path);
  });

  // Per step rather than per job: both publish jobs have the same shape, and a
  // push step aimed at its sibling's repository or file keeps both strings in
  // the job through its fail-closed step while writing a Scoop manifest over
  // the formula.
  it('aims the fail-closed and push steps at its own target', () => {
    const job = jobBlock(readWorkflow(), target.id);

    for (const name of [target.failStep, target.pushStep]) {
      const step = stepNamed(job, name);
      expect(stepEnvValue(step, 'TARGET_REPO'), name).toBe(target.repo);
      expect(stepEnvValue(step, 'TARGET_PATH'), name).toBe(target.path);
    }
  });

  // A released binary whose formula was never pushed is a tap serving the
  // previous version with a green tick on the run that should have moved it.
  it('fails closed on the canonical repository when the token is missing', () => {
    const step = stepNamed(rawJobBlock(target.id), target.failStep);
    const gate = soleIfCondition(step, `the ${target.id} fail-closed step`);
    const script = blockScalarText(step, 'run');

    // Exactly, not by containment: a third conjunct (`&& false`) keeps both
    // substrings and makes the refusal unreachable.
    expect(gate).toBe(
      `github.repository == 'akasecurity/ai-tc' && env.${target.tokenName}_SET != 'true'`,
    );
    expect(script).toMatch(/^echo "::error::/m);
    expect(script).toContain(target.tokenName);
    expect(script).toMatch(/\bexit 1\b/);
  });

  // And the push itself happens only with a token, which is what makes a fork
  // inert rather than broken.
  it('pushes only when a token is configured', () => {
    const gate = soleIfCondition(
      stepNamed(rawJobBlock(target.id), target.pushStep),
      `the ${target.id} push step`,
    );

    expect(gate).toBe(`env.${target.tokenName}_SET == 'true'`);
  });

  // Secrets are unreadable from an `if:`, so the job carries whether the token
  // is set as a boolean, and the value itself is mapped exactly once: onto
  // GH_TOKEN, in the step that calls the API. A job-level mapping of the value
  // reads the same to every gate below while handing the token to every step's
  // environment — the artifact download included.
  it('maps the token value once, onto GH_TOKEN in the push step', () => {
    const raw = rawJobBlock(target.id);

    expect(raw, `${target.id} carries no boolean for its gates`).toMatch(
      new RegExp(
        `^ {6}${target.tokenName}_SET: \\$\\{\\{ secrets\\.${target.tokenName} != '' \\}\\}$`,
        'm',
      ),
    );

    // Any expression reading the secret, whatever it does with it. The boolean
    // above is one; the GH_TOKEN mapping must be the only other.
    const reads = [
      ...raw.matchAll(
        new RegExp(`\\$\\{\\{[^}]*\\bsecrets\\.${target.tokenName}\\b[^}]*\\}\\}`, 'g'),
      ),
    ].map((m) => m[0]);
    expect(reads, `${target.id} reads ${target.tokenName} somewhere else`).toEqual([
      `\${{ secrets.${target.tokenName} != '' }}`,
      `\${{ secrets.${target.tokenName} }}`,
    ]);
    expect(
      stepNamed(raw, target.pushStep),
      `the push step does not map ${target.tokenName} onto GH_TOKEN`,
    ).toMatch(
      new RegExp(`^[^\\S\\n]*GH_TOKEN: \\$\\{\\{ secrets\\.${target.tokenName} \\}\\}$`, 'm'),
    );
  });

  // Two things must not happen to the token once a step has it: a `${{ }}`
  // expression inside a `run:` is pasted into the program text before bash
  // parses it, and a dereference anywhere in a script puts the value on a
  // command line.
  it('hands the token to a shell only as GH_TOKEN in an env mapping', () => {
    const raw = rawJobBlock(target.id);

    const blocks = runBlocksOf(raw);
    // The control for the two absence checks: one of these scripts names the
    // secret in its refusal message, so a reader that captured nothing would
    // fail here rather than pass the loop below.
    expect(
      blocks.filter((block) => block.includes(target.tokenName)),
      'no run: block mentions the secret at all — these scripts were not captured',
    ).not.toEqual([]);

    for (const block of blocks) {
      expect(block, 'a run: block dereferences the token').not.toMatch(
        new RegExp(`\\$\\{?${target.tokenName}\\b`),
      );
      // Not named at all, not merely not dereferenced: `printenv GH_TOKEN |
      // base64` reads it with no `$`, and the encoding defeats the runner's
      // log masking. `gh` finds GH_TOKEN in its environment on its own.
      expect(block, 'a run: block names GH_TOKEN').not.toMatch(/\bGH_TOKEN\b/);
      // The secret's NAME is what the refusal and the notice report, so it may
      // appear — on an annotation line and nowhere else.
      const naming = block
        .split('\n')
        .filter((line) => new RegExp(`\\b${target.tokenName}\\b`).test(line));
      expect(
        naming.filter((line) => !/^echo ["']::(?:error|notice)::/.test(line.trim())),
        `a run: block names ${target.tokenName} outside an annotation`,
      ).toEqual([]);
      expect(block, 'a run: block pastes an expression into the program text').not.toContain('${{');
    }
  });

  // The push step reads the rendered file from a directory this job never
  // writes — it arrives as the release job's artifact. A name or a path that
  // disagrees with that upload fails only on a real tag, after the binaries are
  // already released.
  it('downloads the artifact the release job uploads, where the push step reads it', () => {
    const job = jobBlock(readWorkflow(), target.id);
    const downloads = steps(job).filter((step) =>
      /^[^\S\n]*uses: actions\/download-artifact@v\d+$/m.test(step),
    );
    expect(downloads, `${target.id} downloads no single artifact`).toHaveLength(1);

    const uploaded = /^[^\S\n]*name: (\S+)$/m.exec(manifestUploadStep());
    expect(uploaded, 'the release job uploads an artifact with no name').not.toBeNull();
    expect(downloads[0]).toMatch(new RegExp(`^[^\\S\\n]*name: ${uploaded[1]}$`, 'm'));

    const into = /^[^\S\n]*path: (\S+)$/m.exec(downloads[0]);
    expect(into, `${target.id} downloads to no named directory`).not.toBeNull();
    const push = stepNamed(job, target.pushStep);
    expect(push).toMatch(new RegExp(`^[^\\S\\n]*SOURCE_FILE: ${into[1]}/${target.source}$`, 'm'));
    expect(blockScalarText(push, 'run')).toContain(`$(cat ${into[1]}/VERSION)`);
  });
});

/**
 * Run a publish job's push script against a stubbed `gh`.
 *
 * What is executed is the branching, which is the part that cannot be read: a
 * `grep '(HTTP 404)'` swapped for `true` leaves the refusal branch textually
 * present and unreachable, so every 502 is taken for "not there yet" and the
 * file is written back with no parent blob.
 * @param {(typeof PUBLISH_JOBS)[number]} target
 * @param {{ mode: 'found' | 'missing' | 'fault', remote?: string, rejectPut?: boolean }} options
 */
function runPush(target, { mode, remote, rejectPut = false }) {
  const root = scratchDir('aka-publish-');
  const bin = join(root, 'bin');
  mkdirSync(bin);

  const manifests = join(root, 'manifests');
  mkdirSync(manifests);
  writeFileSync(join(manifests, 'VERSION'), '0.9.12\n');
  const rendered = `# rendered ${target.source} for 0.9.12\n`;
  writeFileSync(join(manifests, target.source), rendered);

  // What the contents API returns for a file that is there: base64 WRAPPED,
  // which is why the script folds the newlines out before comparing.
  const body = join(root, 'remote.json');
  const wrapped = Buffer.from(remote ?? rendered)
    .toString('base64')
    .replace(/(.{60})/g, '$1\n');
  writeFileSync(body, JSON.stringify({ sha: 'b1ob5ha', content: `${wrapped}\n` }));

  const calls = join(root, 'gh-calls');
  writeFileSync(calls, '');
  writeFileSync(
    join(bin, 'gh'),
    [
      '#!/bin/sh',
      '# A PUT carries --method as its second argument; a GET carries the path.',
      'if [ "$2" = "--method" ]; then',
      '  echo "PUT $*" >> "$GH_CALLS"',
      '  if [ "$GH_REJECT_PUT" = yes ]; then echo \'gh: Conflict (HTTP 409)\' >&2; exit 1; fi',
      '  exit 0',
      'fi',
      'case "$GH_MODE" in',
      '  found)   cat "$GH_BODY" ;;',
      "  missing) echo 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;",
      "  *)       echo 'gh: Bad gateway (HTTP 502)' >&2; exit 1 ;;",
      'esac',
      '',
    ].join('\n'),
  );
  chmodSync(join(bin, 'gh'), 0o755);

  const push = stepNamed(rawJobBlock(target.id), target.pushStep);
  const script = blockScalarText(push, 'run');
  const run = {
    cwd: root,
    encoding: 'utf8',
    env: {
      PATH: [bin, TOOL_PATH].join(delimiter),
      RUNNER_TEMP: root,
      GH_TOKEN: 'not-a-real-token',
      GH_MODE: mode,
      GH_REJECT_PUT: rejectPut ? 'yes' : 'no',
      GH_BODY: body,
      GH_CALLS: calls,
      // The step's OWN mapping, not this table's: a push step aimed at the
      // other job's repository or file is the defect, and a fixture that
      // supplied the right values itself would run a script that never does.
      TARGET_REPO: stepEnvValue(push, 'TARGET_REPO'),
      TARGET_PATH: stepEnvValue(push, 'TARGET_PATH'),
      SOURCE_FILE: stepEnvValue(push, 'SOURCE_FILE'),
    },
    timeout: 60_000,
  };

  try {
    const stdout = execFileSync(BASH, ['-c', script], run);
    return { pushed: true, status: 0, stdout, calls: readFileSync(calls, 'utf8'), rendered };
  } catch (err) {
    return {
      pushed: false,
      status: err.status,
      stdout: `${String(err.stdout ?? '')}${String(err.stderr ?? '')}`,
      calls: readFileSync(calls, 'utf8'),
      rendered,
    };
  }
}

/** The `-f content=` a PUT must carry: the rendered file, base64 and unwrapped. */
const contentField = (rendered) => `-f content=${Buffer.from(rendered).toString('base64')}`;

describe.each(PUBLISH_JOBS)('$id writes through the contents API', (target) => {
  const TOOLS = ['jq', 'base64', 'tr', 'grep', 'cat', 'head', 'sed', 'sort', 'tail'];

  it('creates the file when the target has none, with no parent blob', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls, rendered } = runPush(target, { mode: 'missing' });

    expect(pushed, `the push exited ${status}:\n${stdout}`).toBe(true);
    expect(calls, 'nothing was written').toContain('PUT ');
    expect(calls).toContain(`repos/${target.repo}/contents/${target.path}`);
    expect(calls).toContain('-f message=aka 0.9.12');
    expect(calls, 'the PUT carries something other than the rendered file').toContain(
      contentField(rendered),
    );
    expect(calls, 'a create must carry no sha — there is no blob to replace').not.toContain(
      '-f sha=',
    );
  });

  it('replaces the file it read, naming the blob it replaces', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls, rendered } = runPush(target, {
      mode: 'found',
      remote: '# an older render\n',
    });

    expect(pushed, `the push exited ${status}:\n${stdout}`).toBe(true);
    expect(calls, 'nothing was written').toContain('PUT ');
    // The blob the read returned, not merely a `sha` field: an empty or stale
    // one is refused by the API exactly like a missing one.
    expect(calls, 'an update without the current sha is refused by the API').toMatch(
      /-f sha=b1ob5ha(?:\s|$)/,
    );
    expect(calls, 'the PUT carries something other than the rendered file').toContain(
      contentField(rendered),
    );
  });

  // The write is the step's last effect, so a script that carries on past a
  // refused PUT ends on its own success line: a formula that never landed,
  // reported by a green job.
  it('fails when the write itself is refused', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, calls } = runPush(target, {
      mode: 'found',
      remote: '# an older render\n',
      rejectPut: true,
    });

    expect(calls, 'the fixture never reached the write').toContain('PUT ');
    expect(pushed, 'a refused write was reported as a published manifest').toBe(false);
    expect(status, 'the script ended some way other than a non-zero exit').toBeGreaterThan(0);
  });

  // A re-run after a transient failure must not add a commit that changes
  // nothing — which is also what makes re-running this job safe at all.
  it('writes nothing when the target already serves these bytes', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls } = runPush(target, { mode: 'found' });

    expect(pushed, `the push exited ${status}:\n${stdout}`).toBe(true);
    expect(calls, 'an identical render was written back anyway').toBe('');
    expect(stdout).toContain('nothing to commit');
  });

  // Forward only. The version is read off the versioned download URL both
  // formats carry, so these remote bodies carry one the way a real render does.
  const servingVersion = (version) =>
    `url "https://github.com/akasecurity/ai-tc/releases/download/bin-v${version}/aka-${version}-x.tar.gz"\n`;

  it('leaves a file that already serves a newer version', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls } = runPush(target, {
      mode: 'found',
      remote: servingVersion('0.10.0'),
    });

    expect(pushed, `the push exited ${status}:\n${stdout}`).toBe(true);
    expect(calls, 'a newer file was overwritten with an older one').toBe('');
    expect(stdout).toContain('0.10.0, which is newer than 0.9.12');
  });

  it.for([
    // As text 0.9.9 sorts after 0.9.12, which would read an older file as newer.
    ['an older version, compared as numbers', '0.9.9'],
    // The same version with other bytes: a renderer change, or a repair.
    ['the same version with other bytes', '0.9.12'],
  ])('replaces a file that serves %s', ([, version], ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls, rendered } = runPush(target, {
      mode: 'found',
      remote: servingVersion(version),
    });

    expect(pushed, `the push exited ${status}:\n${stdout}`).toBe(true);
    expect(calls, 'nothing was written').toContain('PUT ');
    expect(calls).toContain(contentField(rendered));
  });

  // The one that cannot be read off the text. A non-404 answer says the read
  // FAILED, not that the file is absent, and taking it for absence writes the
  // file back with no parent blob — discarding whatever the read could not see.
  it('refuses a read that failed for any reason but absence', (ctx) => {
    requireTools(ctx, TOOLS);
    const { pushed, status, stdout, calls } = runPush(target, { mode: 'fault' });

    expect(pushed, 'a failed read was taken for an absent file').toBe(false);
    expect(status, 'the script ended some way other than a non-zero exit').toBeGreaterThan(0);
    expect(stdout).toMatch(/::error::/);
    expect(calls, 'a failed read was followed by a write').toBe('');
  });
});

// An expansion inside single quotes, in the form shellcheck's SC2016 reports it:
// a parameter or command substitution, or a backtick pair. actionlint runs
// shellcheck over every `run:` block at its default severity, which includes
// this `info` rule, so one such span reddens the workflow gate on a pull request
// — and a Markdown code span written with backticks inside a single-quoted
// `printf` format is exactly that shape.
const SINGLE_QUOTED_EXPANSION = /\$[{(0-9A-Za-z_]|`[^`]+`/;

/**
 * Every line of a script carrying a single-quoted span SC2016 would report.
 *
 * Quote-aware per line: a `'` inside a double-quoted string opens nothing, and a
 * `#` that begins a word ends the code on that line. A line directly below a
 * `# shellcheck disable=` naming SC2016 is exempt, as shellcheck exempts it.
 * @param {string} script
 */
function singleQuotedExpansions(script) {
  const lines = script.split('\n');
  /** @type {string[]} */
  const found = [];
  lines.forEach((line, index) => {
    if (line.trim().startsWith('#')) return;
    if (/^#\s*shellcheck disable=.*\bSC2016\b/.test((lines[index - 1] ?? '').trim())) return;
    /** @type {string | null} */
    let quote = null;
    let start = 0;
    for (let at = 0; at < line.length; at++) {
      const char = line[at];
      if (quote === null) {
        if (char === '\\') at++;
        else if (char === '#' && (at === 0 || /\s/.test(line[at - 1]))) break;
        else if (char === "'" || char === '"') {
          quote = char;
          start = at + 1;
        }
      } else if (quote === '"') {
        if (char === '\\') at++;
        else if (char === '"') quote = null;
      } else if (char === "'") {
        if (SINGLE_QUOTED_EXPANSION.test(line.slice(start, at))) found.push(line.trim());
        quote = null;
      }
    }
  });
  return found;
}

describe('every run: block passes the workflow gate shellcheck applies', () => {
  // The control: the reader must report the shape it exists for, and must not
  // report the same text once it is double-quoted with its backticks escaped.
  it('reports a backtick pair or an expansion inside single quotes, and nothing else', () => {
    expect(singleQuotedExpansions('printf \'run `gh x` -R %s\\n\' "$R"')).toHaveLength(1);
    expect(singleQuotedExpansions("echo 'value: $HOME'")).toHaveLength(1);
    expect(singleQuotedExpansions('printf \'%s\\n\' "\\`gh x -R ${R}\\`"')).toEqual([]);
    expect(singleQuotedExpansions('echo "it\'s $HOME"')).toEqual([]);
    expect(singleQuotedExpansions("# shellcheck disable=SC2016\necho '$HOME'")).toEqual([]);
  });

  it('carries no single-quoted expansion in any run: block', () => {
    const scripts = steps(readWorkflow())
      .filter((step) => /^[^\S\n]*run: \|[^\S\n]*$/m.test(step))
      .map((step) => blockScalarText(step, 'run'));
    expect(scripts.length, 'the workflow declares no run: block').toBeGreaterThan(0);

    expect(scripts.flatMap(singleQuotedExpansions)).toEqual([]);
  });
});
