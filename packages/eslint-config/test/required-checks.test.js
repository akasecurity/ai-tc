// CONTRIBUTING.md ("Checks that gate `main`") lists the status checks branch
// protection matches on. Protection matches by NAME, so a renamed job does not
// fail — it stops being produced, protection goes on waiting for a name nothing
// emits, and the check is silently no longer required. That failure is invisible
// in a diff and invisible in a green run, which is why the table is read here
// and driven against the workflows rather than being trusted.
//
// What this cannot see is repository settings: whether each name is actually
// configured as required lives outside the tree. This pins the half that is in
// the tree — that every name in the table still belongs to a real job.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  readPackageManifest,
  rootScripts,
  workspaceLintScripts,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');

const readWorkflow = (file) => readFileSync(join(WORKFLOWS, file), 'utf8');

// A job's `name:` sits at four spaces (`jobs:` → job key at two → its keys at
// four). A step's is deeper and carries a `- `, so this matches job names only.
const JOB_NAME = /^ {4}name: (.+)$/gm;

// One `${{ matrix.<key> }}` in a job name, which is how a matrix job produces
// one check per value. Anything more elaborate is not in use and would show up
// here as an unexpanded name that matches nothing in the table.
const MATRIX_REF = /\$\{\{\s*matrix\.([a-zA-Z0-9_-]+)\s*\}\}/;

function matrixValues(source, key) {
  const inline = new RegExp(`^\\s*${key}: \\[(.+)\\]$`, 'm').exec(source);
  if (inline === null) return [];
  return inline[1].split(',').map((value) => value.trim().replace(/^['"]|['"]$/g, ''));
}

// One job's body: from its two-space key to the next two-space line, whatever
// that line is. Ending at a `#` matters as much as ending at the next job key,
// because each job here is introduced by a two-space comment block: run past it
// and a job's body absorbs the NEXT job's prose, so an assertion about what this
// job does starts answering to a paragraph describing a different one. Every
// line a job actually owns is indented four or more, so nothing inside a body
// can terminate it. Note this is the opposite choice from the `pull_request`
// reader above, which must NOT stop at a comment — there the thing being looked
// for could legitimately be written below one, inside the block.
//
// The two structural assertions are what make every ABSENCE check downstream
// non-vacuous, and they belong here rather than in each caller. A block that
// captured too little satisfies `not.toMatch(…)` for the wrong reason, and the
// checks most exposed to that are the ones with nothing positive to pair with:
// "no `if:` here" and "no cache in the no-network job" both pass on `''`. A
// truncation is not hypothetical — one stray two-space line inside a body cuts
// the macOS job from 26 lines to 4, which still carries `runs-on:` and `steps:`
// and so survives any check that only asks whether this looks like a job. What
// it does not survive is being asked for a STEP, because the cut lands above
// them. So require both: a `runs-on:` (this is a job) and at least one step
// list item (the body reached its end).
//
// COMMENT LINES ARE DROPPED, and that is load-bearing rather than tidying. Every
// check below matches a pattern against this text, and a job's own comments
// describe the very flags they sit next to — `# --continue: report every
// package's failures…` sits one line above the `--continue` it explains. So a
// reader that keeps them cannot tell a flag from a sentence about a flag, and
// each of these passes on a job whose real step was deleted: measured, all three
// of the Windows leg's structural checks stayed green with the flag, the filter
// and the whole cache step removed and only the prose left behind. That is the
// exact failure mode this file exists to prevent, one level up.
//
// A line whose first non-space character is `#` is a YAML comment here. The one
// shape that would be misread is a `#` inside a `run:` block scalar, where it is
// command text rather than a comment.
//
// That is safe because of WHERE this is pointed, not because the repo avoids the
// shape: every caller passes `ci.yml`, which carries no `#`-leading line inside
// any `run:` block. Four other workflows do — `dependabot-major-guard.yml` and
// the three `release-plugin-*.yml` — so pointing `jobBlock` at one of those
// makes this sentence false. It stays harmless while those lines are shell
// comments, since dropping them changes no flag matched below; it stops being
// harmless the first time a check wants to see something a `run:` block states
// on a `#`-leading line.
function jobBlock(source, key) {
  // Escaped even though GitHub constrains job ids to [A-Za-z_][A-Za-z0-9_-]*,
  // where nothing is a metacharacter: the cost is one call, and a caller that
  // ever passes a step name instead would otherwise get `.` as a wildcard.
  const pattern = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const block = new RegExp(
    `^ {2}${pattern}:[^\\S\\n]*$([\\s\\S]*?)(?=^ {2}\\S|\\s*$(?![\\s\\S]))`,
    'm',
  ).exec(source);
  expect(block, `no job \`${key}\` in the workflow`).not.toBeNull();
  const body = block[1]
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');
  expect(body, `\`${key}\` captured no runs-on — not a job body`).toMatch(/^ {4}runs-on: /m);
  expect(body, `\`${key}\` captured no steps — the body was cut short`).toMatch(/^ {6}- /m);
  return body;
}

// The windows-lint step, which must be `pnpm lint` and nothing else. The
// boundary is `(?![\w:])` rather than `\b` because `:` is a NON-word character,
// so `pnpm lint\b` also matches `pnpm lint:root` — and that is not a hypothetical
// spelling, it is a script this repo really has. Swapping the step to it drops
// `turbo run lint` (all twenty packages) and `check:portability`, leaving only
// the repo-root pass, while every assertion below goes on passing. The negative
// class deliberately excludes a SPACE, so an argument appended after the script
// name still matches: that is what lets this double as the positive control for
// the absence checks, which is the property the comments below turn on.
const LINT_STEP = /run: pnpm lint(?![\w:])/;

// Every Turbo cache key a job declares — the `key:` and each line under
// `restore-keys:`, which are bare values rather than `key: `-prefixed.
// `[^\S\n]+` rather than `\s+`: this is one line's indentation, and `\s` would
// let the anchor run back across blank lines.
function turboCacheKeys(block) {
  return [...block.matchAll(/^[^\S\n]+(?:key: )?(turbo-.+)$/gm)].map(([, key]) => key);
}

/**
 * Every `--filter=<name>` a job's run steps pass to turbo. Comment lines are
 * already gone by the time a block reaches here (see jobBlock), which is what
 * stops a filter that was moved into a comment reading as one that still runs.
 */
const turboFilters = (block) => [...block.matchAll(/--filter=(\S+)/g)].map(([, name]) => name);

/**
 * Every workspace package npm actually publishes — `private` absent or false.
 * Derived from pnpm-workspace.yaml and the manifests themselves rather than
 * listed, because a list is exactly what let the CLI and the plugin sit outside
 * the Windows job while its name claimed the shipped surface: a fifth artifact
 * added tomorrow would not be on it either.
 */
const publishedPackageNames = () =>
  workspacePackageDirs()
    .map((dir) => readPackageManifest(dir))
    .filter((pkg) => pkg.private !== true && typeof pkg.name === 'string')
    .map((pkg) => pkg.name)
    .sort();

// Every check name a workflow can emit, with matrix jobs expanded to the names
// GitHub actually reports.
function checkNames(file) {
  const source = readWorkflow(file);
  const names = [];
  for (const [, rawName] of source.matchAll(JOB_NAME)) {
    const name = rawName.trim();
    const ref = MATRIX_REF.exec(name);
    if (ref === null) {
      names.push(name);
      continue;
    }
    for (const value of matrixValues(source, ref[1])) {
      names.push(name.replace(MATRIX_REF, value));
    }
  }
  return names;
}

// The table itself: | `Check name` | `workflow.yml` |
function requiredChecks() {
  const contributing = readFileSync(join(REPO_ROOT, 'CONTRIBUTING.md'), 'utf8');
  const section = /## Pull requests[\s\S]*?### Checks that gate `main`([\s\S]*?)```bash/.exec(
    contributing,
  );
  expect(section).not.toBeNull();
  return [...section[1].matchAll(/^\| `([^`]+)`\s*\| `([^`]+)`\s*\|$/gm)].map(
    ([, check, file]) => ({
      check,
      file,
    }),
  );
}

describe('the required-check table in CONTRIBUTING.md', () => {
  const rows = requiredChecks();

  // A table that parsed to nothing would satisfy every per-row assertion below
  // without checking anything, so pin the count first. The five CI jobs, the
  // audit, and CodeQL's two matrix legs.
  it('parses, and covers every gate the table is supposed to list', () => {
    expect(rows).toHaveLength(8);
    expect(rows.map((row) => row.file)).toEqual(
      expect.arrayContaining(['ci.yml', 'audit.yml', 'codeql.yml']),
    );
  });

  it.each(rows)('$check is a real job in $file', ({ check, file }) => {
    expect(checkNames(file)).toContain(check);
  });

  // The matrix expander is load-bearing for the two CodeQL rows: without it
  // they would read as the literal `CodeQL (${{ matrix.language }})` and match
  // nothing. Pin that it expands rather than trusting the rows above, which
  // would also pass if the table itself drifted to the unexpanded spelling.
  it('expands a matrix job into the names GitHub reports', () => {
    const names = checkNames('codeql.yml');
    expect(names).toContain('CodeQL (javascript-typescript)');
    expect(names).toContain('CodeQL (actions)');
    expect(names.some((name) => name.includes('matrix.'))).toBe(false);
  });

  // The audit workflow's second job reports a check too, and it is deliberately
  // NOT required — it only ever runs on the schedule, so requiring it would
  // block every PR on a check that is permanently skipped there.
  it('does not require the scheduled advisory-reporting job', () => {
    expect(checkNames('audit.yml')).toContain('File advisory issue (scheduled runs)');
    expect(rows.map((row) => row.check)).not.toContain('File advisory issue (scheduled runs)');
  });
});

describe('the workflows behind those checks', () => {
  // `Dependency audit` and the CodeQL legs are only "on every PR" if neither
  // workflow filters `pull_request` by base branch. A `branches:` filter there
  // excludes a stacked PR entirely — no run, no check — and for a required
  // check that means a PR that can never satisfy it.
  // The block ends at the next sibling KEY, and a `#` comment is not one — an
  // end-of-block test that stopped at the first two-space non-space character
  // would end at a comment line instead, so a `branches:` filter written below
  // one would sit outside the captured block and be missed.
  it.each(['audit.yml', 'codeql.yml'])('%s runs on every PR, whatever its base', (file) => {
    const source = readWorkflow(file);
    const trigger = /^ {2}pull_request:[^\S\n]*$([\s\S]*?)^ {2}[^\s#]/m.exec(source);
    expect(trigger).not.toBeNull();
    expect(trigger[1]).not.toMatch(/^\s*branches:/m);
  });

  it('both run daily or weekly as well as on PRs', () => {
    expect(readWorkflow('audit.yml')).toMatch(/^\s*- cron: '[^']+'$/m);
    expect(readWorkflow('codeql.yml')).toMatch(/^\s*- cron: '[^']+'$/m);
  });

  // Code scanning cannot upload results without it, so the analysis would run
  // and report nothing.
  it('codeql.yml grants security-events: write', () => {
    expect(readWorkflow('codeql.yml')).toMatch(/^\s*security-events: write$/m);
  });
});

// The macOS leg is the only platform job whose value is entirely in what it does
// NOT restrict. Its name promises the full suite, and nothing about a filtered
// run looks wrong in a diff — the Windows leg is filtered on purpose, so a
// filter copied here reads like consistency. These pin the promise instead.
describe('the macOS leg', () => {
  // Read here, but BLOCKED here too: jobBlock asserts, and an assertion in a
  // describe body is a collection error rather than a test failure — vitest
  // reports the file as `(0 test)` and every other suite in it stops running,
  // so deleting the macOS job would also silence the CodeQL, audit and
  // gate-table rows above. Each `it` resolves its own block instead.
  const ci = readWorkflow('ci.yml');

  it('runs on a macOS runner', () => {
    expect(jobBlock(ci, 'macos')).toMatch(/^ {4}runs-on: macos-latest$/m);
  });

  // Two darwin-only fault-injection tests guard on `process.platform !== 'darwin'`
  // with an early RETURN, so off darwin they report as passes without running.
  // A --filter that drops `persistence` or `cli` therefore does not merely
  // narrow this job — it puts those two cases straight back to green-and-unrun,
  // which is the state this leg exists to end.
  it('runs the whole workspace rather than a filtered subset', () => {
    const block = jobBlock(ci, 'macos');
    expect(block).toMatch(/turbo run test/);
    expect(block).not.toMatch(/--filter/);
  });

  // --continue is what makes a first macOS run worth one triage pass instead of
  // several: without it turbo bails at the first red package and the rest of the
  // platform's failures stay hidden until that one is fixed. Nothing else here
  // would notice its removal — `turbo run test` still matches.
  it('reports every package rather than bailing at the first failure', () => {
    expect(jobBlock(ci, 'macos')).toMatch(/turbo run test\b.*--continue/);
  });

  it('restores a Turbo cache', () => {
    const block = jobBlock(ci, 'macos');
    expect(block).toMatch(/uses: actions\/cache@/);
    expect(block).toMatch(/path: \.turbo\/cache$/m);
  });

  // A job-level `if:` is the obvious lever for anyone trimming macOS runner
  // minutes — draft PRs, a label gate, push-only. It is also the one lever that
  // cannot be applied here, and not merely because it would narrow the promise:
  // GitHub reports a skipped job as PENDING for a required check, so a condition
  // that makes this leg skip does not save a PR the wait, it blocks the merge
  // outright and with nothing red to point at. Narrow the work inside the job
  // instead, never whether the job runs.
  //
  // Absence-only, so its positive control is jobBlock's own structural pair —
  // without those this passes on a body cut short above its steps.
  it('carries no condition that could skip it on a PR', () => {
    expect(jobBlock(ci, 'macos')).not.toMatch(/^ {4}if:/m);
  });
});

// The two Windows legs. Between them they are the only place three things are
// ever executed on this platform, and each is invisible in a diff once dropped:
// every package npm publishes, the guard package's own path handling, and the
// glob expansion every `lint` script depends on.
//
// The shipped-surface leg is the mirror image of the macOS one: it is filtered ON
// PURPOSE, so nothing about a narrow filter looks wrong in a diff — which is how
// it spent its whole life excluding `@akasecurity/cli` and the plugins while its
// own name promised the shipped surface and its own comment named those very
// packages as the reason it exists. The filter is where its promise lives, so
// that is what these pin.
describe('the Windows legs', () => {
  // Read here, but BLOCKED inside each `it` — jobBlock asserts, and an assertion
  // in a describe body is a collection error that reports the whole FILE as
  // `(0 test)`, silently taking the gate-table rows with it. Reading the file is
  // safe out here; resolving a block is not.
  const ci = readWorkflow('ci.yml');

  it('runs the shipped-surface tests on a Windows runner', () => {
    expect(jobBlock(ci, 'windows')).toMatch(/^ {4}runs-on: windows-latest$/m);
  });

  // THE assertion this job exists for. Derived from the workspace rather than
  // listed, so a fifth published artifact is caught the day it lands; the
  // count check first is what stops a broken derivation satisfying the loop
  // with an empty set.
  it('runs every package npm publishes', () => {
    const published = publishedPackageNames();
    // Positive control on the DERIVATION, not a second copy of the list: a
    // manifest reader that broke and returned nothing — or everything — would
    // otherwise satisfy `arrayContaining` and this check would pass forever
    // while the filter list rotted. `cli` is the package the job's own comment
    // names, and `persistence` is private and bundled, so one must be in the
    // derived set and the other must not. A length floor alone cannot separate
    // those two failures.
    expect(published).toContain('@akasecurity/cli');
    expect(published).not.toContain('@akasecurity/persistence');
    expect(turboFilters(jobBlock(ci, 'windows'))).toEqual(expect.arrayContaining(published));
  });

  // @akasecurity/eslint-config is the one filter entry that ships nothing —
  // `private: true`, bundled by no artifact — so it is the first thing anyone
  // trimming this list back to "the shipped surface" would strike, and the job's
  // NAME invites exactly that. It is also the only place the guard's own
  // Windows path handling ever runs: globSync yields native separators while
  // `git ls-files` yields posix, and the two are compared against each other
  // throughout effective-config.test.js. Drop this entry and those normalizations
  // go back to being a hypothesis no runner checks, with nothing red to show it.
  //
  // Not covered by the published-package check above, and cannot be: that set is
  // derived from `private !== true`, which excludes this package by construction.
  it('tests the enforcement package, not just the shipped surface', () => {
    const block = jobBlock(ci, 'windows');
    expect(block).toMatch(/turbo run test/);
    // `(?![\w-])` rather than `\b`: a hyphen is a non-word character, so `\b`
    // would also accept `--filter=@akasecurity/eslint-config-legacy`, i.e. a
    // rename or split that repoints the filter at a sibling and takes this
    // package's Windows coverage away while the test stays green.
    expect(block).toMatch(/--filter=@akasecurity\/eslint-config(?![\w-])/);
  });

  // A filter is only a filter while there is something to filter. `turbo run
  // test` with no --filter at all would satisfy the containment check above by
  // running everything, which is a different job with a different cost — and it
  // would make the assertion above unfalsifiable from then on.
  it('is a filtered run, which is what makes the filter list load-bearing', () => {
    const block = jobBlock(ci, 'windows');
    expect(block).toMatch(/turbo run test/);
    expect(turboFilters(block).length).toBeGreaterThan(0);
  });

  // Without it turbo bails at the first red package, so a platform-specific
  // failure in an early package hides every later one — and on this leg the
  // whole point is seeing the platform's failures in one triage pass.
  it('reports every package rather than bailing at the first failure', () => {
    expect(jobBlock(ci, 'windows')).toMatch(/--continue/);
  });

  it('restores a Turbo cache', () => {
    const block = jobBlock(ci, 'windows');
    expect(block).toMatch(/uses: actions\/cache@/);
    expect(block).toMatch(/path: \.turbo\/cache$/m);
  });

  it('runs lint on a Windows runner', () => {
    expect(jobBlock(ci, 'windows-lint')).toMatch(/^ {4}runs-on: windows-latest$/m);
  });

  // `pnpm lint`, not `turbo run lint`: the root script chains `lint:root` after
  // it, which is the only pass covering the repo-root files that belong to no
  // package. Going to turbo directly drops that half while still reading as a
  // lint pass.
  it('runs the root lint script, so the repo-root pass runs too', () => {
    expect(jobBlock(ci, 'windows-lint')).toMatch(LINT_STEP);
  });

  // Unfiltered is the whole point: every lint script in the workspace targets
  // `*.config.*`, so a filter narrows what expansion is observed while leaving a
  // green check that reads as covering all of it. Absence-only, so it is paired
  // with the positive control above — without a `pnpm lint` in the same body
  // this passes on a block that captured no run step at all.
  //
  // That control stops at a boundary rather than end-of-line, and the difference
  // is the whole value of the pair. Anchored with `$`, appending `--filter=…` to
  // the step breaks the CONTROL, so this test goes red for the wrong reason and
  // its own assertion — the one naming the property — is never reached. The
  // absence check has to be the thing that fires on the mutation it describes, or
  // it is unproven however green the suite is. See LINT_STEP for why that
  // boundary is not `\b`.
  it('lints the whole workspace rather than a filtered subset', () => {
    const block = jobBlock(ci, 'windows-lint');
    expect(block).toMatch(LINT_STEP);
    expect(block).not.toMatch(/--filter/);
  });

  // Same reasoning as the macOS leg: a job-level `if:` does not save a PR the
  // wait, because GitHub reports a skipped job as PENDING for a required check.
  it.each(['windows', 'windows-lint'])('%s carries no condition that could skip it', (job) => {
    expect(jobBlock(ci, job)).not.toMatch(/^ {4}if:/m);
  });

  // The windows-lint job's whole justification is that a `lint` script carries a
  // glob whose expansion is decided by the platform. That premise is a claim
  // about the tree, so derive it rather than asserting it in a comment: a package
  // whose lint script drops `*.config.*` takes its root config files out of every
  // lint pass on every platform, and this job would stay green throughout —
  // twenty other scripts still expand, so nothing here reddens.
  //
  // The count is pinned first for the usual reason: an empty list satisfies a
  // `for` loop over it without checking anything. It is a floor AND a ceiling, so
  // a package added without a lint script is caught by the same assertion.
  it('every lint script carries the glob this job exists to observe', () => {
    const scripts = workspaceLintScripts();
    expect(scripts).toHaveLength(21);
    for (const { dir, lintScript } of scripts) {
      expect(lintScript, `${dir} declares no lint script`).not.toBe('');
      expect(lintScript, `${dir}'s lint script targets no *.config.* glob`).toContain('*.config.*');
    }
    // And the repo-root pass, which is the twenty-first invocation rather than a
    // twenty-first package — it is the only one covering files no package owns.
    expect(rootScripts()['lint:root']).toContain('*.config.*');
  });
});

// The installer trust chain is the one shipped surface whose ENTIRE mechanism is
// two files ESLint does not lint and tsc does not read, so nothing about them
// moves a hash or fails a build. What executes them is the suite in
// tools/installer, and what runs that suite is these two wirings — each one line
// long, each invisible in a diff once removed, and each restoring the exact hole
// the suite was written to close: a shipped security control that no runner ever
// runs. So they are pinned rather than trusted.
//
// They cover different halves and neither substitutes for the other. `ci.yml`
// has no path filter, so it runs the suite against a STUB archive on every PR —
// that is what makes an installer-only PR exercised at all, and on the Windows
// leg it is the only thing that reaches install.ps1's junction and user-PATH
// flow. `build-binaries.yml` is the only place a REAL archive meets the real
// installer, and it is path-filtered, so an installer-only PR reaches it only
// because `tools/installer/**` is listed.
describe('the installer trust chain is wired into CI', () => {
  const ci = readWorkflow('ci.yml');
  const binaries = readWorkflow('build-binaries.yml');

  // The half of this that is an ABSENCE, and so the half nothing would otherwise
  // notice. build-binaries.yml reaches an installer-only PR because it now lists
  // the path; ci.yml reaches one because it filters no path at all. The second is
  // a property of what is NOT written, so adding a `paths:` filter here — the
  // ordinary way to make a workflow cheaper — would take the whole stub tier away
  // on every platform at once, leaving the entry above pointing at a job that
  // never starts.
  it('runs on an installer-only PR at all, because it filters no path', () => {
    // Same block shape as the audit/codeql trigger check above, and stopping at
    // a sibling KEY rather than any two-space token for the same reason: a
    // `paths:` written under a comment line must still land inside the block.
    const trigger = /^ {2}pull_request:[^\S\n]*$([\s\S]*?)^ {2}[^\s#]/m.exec(ci);
    expect(trigger, 'ci.yml has no parseable pull_request trigger').not.toBeNull();
    expect(trigger[1]).not.toMatch(/^\s*paths(?:-ignore)?:/m);
  });

  // `(?![\w-])` for the reason the eslint-config filter above uses it: a hyphen
  // is a non-word character, so `\b` would also accept a rename that repointed
  // the filter at a sibling and took install.ps1's coverage away while staying
  // green.
  it('runs the installer suite on the Windows leg, the only one that reaches install.ps1 whole', () => {
    expect(turboFilters(jobBlock(ci, 'windows'))).toContain('@akasecurity/installer');
    expect(jobBlock(ci, 'windows')).toMatch(/--filter=@akasecurity\/installer(?![\w-])/);
  });

  it('builds a binary when only the installer changed', () => {
    // Read off the `paths:` list rather than the whole file, so the entry cannot
    // be satisfied by the word appearing in a comment or a step.
    const paths = /^on:$[\s\S]*?^ {4}paths:$([\s\S]*?)^\S/m.exec(binaries)?.[1] ?? '';
    expect(paths, 'build-binaries.yml has no parseable pull_request paths list').toMatch(
      /^ {6}- '/m,
    );
    expect(paths).toMatch(/^ {6}- 'tools\/installer\/\*\*'$/m);
  });

  it('drives the real archive through the real installer after building it', () => {
    const block = jobBlock(binaries, 'build');
    // The env var is what switches the suite off its stub fixture and onto the
    // artifact `archive:sea` just wrote; without it the step still passes, having
    // skipped the only case that touches a real binary.
    expect(block).toMatch(/AKA_INSTALLER_REAL_DIST:/);
    expect(block).toMatch(/pnpm --filter @akasecurity\/installer test/);
    // After archive:sea, or there is nothing for it to find. Both indices are
    // asserted FOUND first: `indexOf` returns -1 for a string that is not there,
    // and -1 is less than every real index, so a bare `toBeLessThan` would go on
    // passing after the archive:sea step was deleted — the one edit this
    // ordering check exists to catch.
    const archived = block.indexOf('archive:sea');
    const verified = block.indexOf('AKA_INSTALLER_REAL_DIST');
    expect(archived, 'build-binaries.yml no longer runs archive:sea').toBeGreaterThanOrEqual(0);
    expect(
      verified,
      'build-binaries.yml no longer sets AKA_INSTALLER_REAL_DIST',
    ).toBeGreaterThanOrEqual(0);
    expect(archived).toBeLessThan(verified);
  });

  // install.ps1's happy path writes HKCU's `Path`, so it is opt-in: the cases
  // skip unless AKA_INSTALLER_ALLOW_USER_PATH=1, which keeps a contributor's
  // workstation out of it. That makes the variable the ONLY thing standing
  // between CI and a green run in which the ps1 happy path never executed —
  // exactly the state this whole package was written to end. Three separate
  // one-line edits can reach that state, so all three are pinned.
  it('grants the ps1 happy path its user-PATH opt-in on both Windows runners', () => {
    expect(jobBlock(ci, 'windows')).toMatch(/AKA_INSTALLER_ALLOW_USER_PATH: *'1'/);
    expect(jobBlock(binaries, 'build')).toMatch(/AKA_INSTALLER_ALLOW_USER_PATH: *'1'/);
  });

  it('declares that opt-in to turbo, so setting it cannot replay a cached skip', () => {
    // ci.yml reaches the suite through `turbo run test`, and turbo hashes only
    // the env it is told about. Undeclared, a run WITH the variable hash-matches
    // one without it and replays a green in which the case skipped — the same
    // trap build-binaries.yml routes around by not using turbo at all. Read off
    // the `test` task's own `env`, not the file, so the entry cannot be satisfied
    // by the name appearing under some other task.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const testTask = /^ {4}"test": \{$([\s\S]*?)^ {4}\},$/m.exec(turbo)?.[1] ?? '';
    expect(testTask, 'turbo.json has no parseable `test` task').not.toBe('');
    expect(testTask).toMatch(/"env": *\[[^\]]*"AKA_INSTALLER_ALLOW_USER_PATH"/);
  });
});

// Turbo's task hash covers file contents, dependencies and env — not the
// platform. Three jobs now restore .turbo/cache on three different OSes, so a
// key that did not separate them would let macOS or Windows restore Linux's
// entry, hash-match, and replay Linux's green `test` tasks: a platform leg
// reporting success having executed nothing. `runner.os` leading every key and
// restore-key is the whole of what prevents it, and it is one edit from being
// dropped. It matters most on the Windows leg, which is the newest to take a
// cache and the one whose packages differ most by platform.
describe('the Turbo caches in ci.yml', () => {
  const ci = readWorkflow('ci.yml');

  it.each(['ci', 'macos', 'windows'])('%s keys its cache per platform', (job) => {
    const keys = turboCacheKeys(jobBlock(ci, job));
    // The `key:` plus two restore-keys. Pinned so a key added without the
    // prefix cannot hide behind a loop that happens to see none.
    expect(keys).toHaveLength(3);
    for (const key of keys) {
      expect(key.startsWith('turbo-${{ runner.os }}-')).toBe(true);
    }
  });

  // The inverse, and the reason the two cached jobs are named rather than
  // discovered: the no-network job forgoes the cache deliberately, because a
  // restore-key falling back to an earlier commit would let turbo replay a
  // `test` task that never ran under the egress block. With caches now visibly
  // the norm here, adding one there looks like fixing an oversight.
  //
  // The absence here is the whole assertion and the thing it looks for is the
  // thing that must not be there, so it has no natural positive control of its
  // own. It leans on jobBlock's structural pair, plus the egress step below —
  // which is both the job's last step and the reason it exists, so a body that
  // reaches it reached the end.
  it('leaves the no-network job uncached', () => {
    const block = jobBlock(ci, 'no-network');
    expect(block).toMatch(/no-network-test\.sh/);
    expect(block).not.toMatch(/uses: actions\/cache@/);
  });

  // And the Windows lint leg, for the same reason one step further out. What it
  // exists to observe is who expands `*.config.*` on this platform — a property
  // of the runner image, the shell and the Node build, none of which turbo
  // hashes. So a restored cache is not merely stale here, it is the failure:
  // turbo replays a green `lint` task that expanded no glob on this runner at
  // all, and the check reports success having observed nothing. `runner.os` in
  // the key does not help — the replay it would license is a WINDOWS entry from
  // an earlier commit, which is exactly the run being skipped.
  //
  // Paired with the lint step for the same reason as above: the assertion is an
  // absence, and an absence passes on a body that captured nothing.
  it('leaves the Windows lint job uncached', () => {
    const block = jobBlock(ci, 'windows-lint');
    expect(block).toMatch(LINT_STEP);
    expect(block).not.toMatch(/uses: actions\/cache@/);
  });
});
