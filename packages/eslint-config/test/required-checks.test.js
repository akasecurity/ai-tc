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

import { readFileSync, readdirSync } from 'node:fs';
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

// Memoised per path: every workflow here is read by several assertions and
// CONTRIBUTING.md by several more, and all of them want the same bytes within a
// run. The cache is keyed on the absolute path so the two readers cannot collide.
const fileCache = new Map();
const readText = (path) => {
  if (!fileCache.has(path)) fileCache.set(path, readFileSync(path, 'utf8'));
  return fileCache.get(path);
};

const readWorkflow = (file) => readText(join(WORKFLOWS, file));

// A line whose first non-space character is `#` is a YAML comment. Dropping them
// is load-bearing rather than tidying — see jobBlock and triggerBlock, each of
// which matches patterns against text whose own comments name the very thing
// being looked for. Shared by all three block readers so they cannot drift into
// disagreeing about what a comment is.
const dropComments = (text) =>
  text
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');

/**
 * A top-level block: a column-0 `key:` through to the next column-0 key, or to
 * the end of the file. Comments are dropped, and `control` is a pattern the body
 * must match — the positive control, without which every absence check below it
 * passes on a block that captured nothing.
 *
 * The end-of-input alternative matters because these are read from arbitrary
 * workflows: a `concurrency:` block that happens to be the last top-level key in
 * its file would otherwise report as absent rather than being read.
 */
function topLevelBlock(file, key, control) {
  const block = new RegExp(`^${key}:[^\\S\\n]*$([\\s\\S]*?)(?=^\\S|\\s*$(?![\\s\\S]))`, 'm').exec(
    readWorkflow(file),
  );
  expect(block, `${file} has no \`${key}:\` block`).not.toBeNull();
  const body = dropComments(block[1]);
  expect(body, `${file}: the \`${key}:\` block captured nothing`).toMatch(control);
  return body;
}

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
  const body = dropComments(block[1]);
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

// Any spelling of the cache action: the combined one and both sub-actions. The
// absence checks below need all three, and that is not a stylistic preference —
// after the restore/save split no cached job spells the bare `actions/cache@` at
// all, so a guard still looking only for that would go on passing while a cache
// was added to a job whose whole point is not having one. An omitted alternative
// in an absence guard is invisible rather than noisy: nothing reports the
// candidate it failed to match.
const ANY_CACHE_ACTION = /uses: actions\/cache(?:\/(?:restore|save))?@/;

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

const readContributing = () => readText(join(REPO_ROOT, 'CONTRIBUTING.md'));

// The table itself: | `Check name` | `workflow.yml` | <mark> |. Sliced to its own
// section so a table further down the file cannot contribute rows — the
// branch-freshness section below carries one, and its rows are not two backticked
// cells, but the slice is what makes that a fact about this reader rather than
// about that table.
//
// The third cell is the ENFORCED column: whether branch protection actually
// requires the check today. That is repository state rather than anything this
// tree can set, so nothing here asserts it is ✅ — `required-checks.yml` reads the
// live set daily and fails on drift in either direction. What this file keeps
// true is the half that IS in the tree: that every name still belongs to a real
// job, and that the column parses at all.
//
// Asserts NOTHING, deliberately: a caller builds an `it.each` list from this in a
// `describe` body, and an assertion there is a collection error rather than a
// test failure — vitest reports the whole FILE as `(0 test)` and every suite in
// it stops running. A parse that found nothing returns null, and the callers that
// can afford to assert do so inside an `it`.
const ENFORCED_MARKS = ['✅', '⛔'];

function requiredCheckRows() {
  const section = /## Pull requests[\s\S]*?### Checks that gate `main`([\s\S]*?)```bash/.exec(
    readContributing(),
  );
  if (section === null) return null;
  const rows = [...section[1].matchAll(/^\| `([^`]+)`\s*\| `([^`]+)`\s*\| *(\S+) *\|$/gm)].map(
    ([, check, file, enforced]) => ({
      check,
      file,
      enforced,
    }),
  );
  // The same completeness rule `parseGateTable` enforces, because this is a
  // SECOND reader of one document and the two must not disagree about how many
  // rows it has. Without it the pair diverges in the permissive direction: add
  // a ninth row whose Enforced cell does not parse and the gate refuses the
  // whole table (9 row-like, 8 parsed) while this file yields 8, satisfies its
  // `toHaveLength(8)` pin, and stays green — measured at 111 passed. The count
  // pin catches a REFORMATTED row and cannot catch an ADDED one.
  //
  // Duplicated rather than imported: `@akasecurity/required-checks-gate`
  // devDepends on this package, so taking the reverse edge makes turbo report
  // `x Cyclic dependency detected`. The guard travels with the copy instead.
  //
  // REPORTED, not asserted here. Collapsing a short count to `null` made
  // `requiredChecks()` throw in a describe body, which vitest reports as a
  // collection error — `Test Files 1 failed` with `Tests no tests`, taking
  // every other suite in this file down and reading as green to anything
  // grepping for a failed test. The count rides along and one named `it`
  // asserts it.
  rows.rowLike = section[1].split('\n').filter((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('|') || !trimmed.endsWith('|')) return false;
    if (/^[|\-: ]+$/.test(trimmed)) return false;
    return !trimmed.startsWith('| Check');
  }).length;
  return rows;
}

function requiredChecks() {
  const rows = requiredCheckRows();
  expect(rows).not.toBeNull();
  return rows;
}

// A workflow's `on:` block. The positive control is that the block captured a
// trigger AT ALL — a two-space key — rather than any particular one: this backs
// the merge_group check, and pinning `pull_request` here would fail a workflow
// triggered by push and merge_group only, which is a valid shape once a queue is
// what gates. Which workflows must carry which trigger is decided by the callers.
const triggerBlock = (file) => topLevelBlock(file, 'on', /^ {2}\w+:/m);

// A workflow's `concurrency:` block. `group:` is the positive control: every
// check below reads one line out of this block, and all of them pass on a block
// that captured nothing.
const concurrencyBlock = (file) => topLevelBlock(file, 'concurrency', /^ {2}group: /m);

/**
 * The workflows that GATE a change: those that run both on `pull_request` and on
 * a push to `main`. Derived from the workflows themselves rather than from the
 * required-check table, because the table is documented (in the section it is
 * read from) as listing more checks than are actually required — so it is
 * neither the tabled set nor the enforced set, and a gating workflow missing
 * from it inherits none of the properties below. `internal-path-guard.yml` was
 * exactly that: absent from the table, and the one workflow whose being skipped
 * is a disclosure rather than a missing verdict.
 *
 * Running on BOTH events is what makes a workflow a gate, and is what excludes
 * `build-binaries.yml` — PR-only, path-filtered, and not something a merge waits
 * on. An empty list is the vacuity risk (`it.each([])` registers no tests and
 * reports nothing), so a shared `it` asserts the contents below.
 */
function gatingWorkflows() {
  return readdirSync(WORKFLOWS)
    .filter((file) => file.endsWith('.yml') || file.endsWith('.yaml'))
    .filter((file) => {
      const on = dropComments(
        /^on:[^\S\n]*$([\s\S]*?)(?=^\S|\s*$(?![\s\S]))/m.exec(readWorkflow(file))?.[1] ?? '',
      );
      // The end alternative is `$(?![\s\S])` — true end of input — and NOT a bare
      // `$`, which under /m matches the end of the FIRST line and stops the lazy
      // quantifier at once, capturing nothing. Measured: every workflow read as
      // having no `push:` branches, so the derived set came back empty and only
      // the non-vacuity control below caught it.
      const push = /^ {2}push:[^\S\n]*$([\s\S]*?)(?=^ {2}\S|$(?![\s\S]))/m.exec(on);
      return /^ {2}pull_request:/m.test(on) && /branches:.*\bmain\b/.test(push?.[1] ?? '');
    })
    .sort();
}

// The workflows behind the required checks, deduped from the table. Every one of
// them must also be a gating workflow — a required check that does not run on
// both events cannot be satisfied on a PR or cannot be re-verified on main.
const requiredWorkflows = () => [...new Set((requiredCheckRows() ?? []).map((row) => row.file))];

// The decision recorded in CONTRIBUTING.md's "Branch freshness" section. Returns
// what it found rather than asserting, for the `describe`-body reason above.
// Lower-cased because the prose two paragraphs above the record spells the
// alternative "Require branches to be up to date", and a maintainer switching the
// decision will copy that spelling; a case-sensitive lookup would then fail with
// a message about an unknown mechanism rather than about the thing they changed.
//
// `in use` and `chosen` are both accepted, and the line is NOT anchored at its
// end. A mechanism that is recorded but not yet switched on has to say so on the
// same line — the bolded record is where a reader stops, so a caveat four
// paragraphs down is one they never reach — and that trailing text is exactly
// what an end-anchored pattern rejects. Dropping `$` is therefore half the
// widening rather than a tidy-up: keeping it while adding the alternation parses
// `Mechanism chosen: …` only while nothing follows the bold, which is the one
// case the wording exists to cover.
function branchFreshness() {
  const contributing = readContributing();
  const mechanism = /^\*\*Mechanism (?:in use|chosen): ([^.*]+)\.\*\*/m.exec(contributing);
  return {
    documented: /^### Branch freshness$/m.test(contributing),
    mechanism: mechanism === null ? null : mechanism[1].trim().toLowerCase(),
  };
}

// The two mechanisms that close the stale-base hole. Only the queue reaches the
// workflows — it is the one that needs an event they do not otherwise receive —
// so recording the other one obliges this tree to carry nothing, and the suite
// below pins that the recorded one is the queue rather than carrying a flag whose
// false branch nothing can reach.
const MECHANISMS = ['merge queue', 'require branches to be up to date'];
const MECHANISM_NEEDING_MERGE_GROUP = 'merge queue';

describe('the required-check table in CONTRIBUTING.md', () => {
  const rows = requiredChecks();

  // A table that parsed to nothing would satisfy every per-row assertion below
  // without checking anything, so pin the count first. The five CI jobs, the
  // audit, and CodeQL's two matrix legs.
  it('parses, and covers every gate the table is supposed to list', () => {
    expect(rows).toHaveLength(8);
    // Every line that LOOKS like a row parsed as one. The length pin above
    // catches a REFORMATTED row (8 become 7) and cannot catch an ADDED one: a
    // ninth row whose Enforced cell does not parse leaves 8 here while
    // `parseGateTable` refuses the table outright, so the gate goes red daily
    // and this file stays green. Measured at 111 passed before this line.
    expect(rows).toHaveLength(rows.rowLike);
    expect(rows.map((row) => row.file)).toEqual(
      expect.arrayContaining(['ci.yml', 'audit.yml', 'codeql.yml']),
    );
  });

  it.each(rows)('$check is a real job in $file', ({ check, file }) => {
    expect(checkNames(file)).toContain(check);
  });

  // The Enforced column is what `required-checks.yml` compares the live set
  // against, and that gate reads an unrecognised mark as a configuration error
  // rather than as `false` — so a cell holding anything else fails the daily job
  // rather than silently downgrading the row. Catch it here, in the PR that
  // wrote it, instead of tomorrow morning.
  it.each(rows)('$check records an enforced mark this repo recognises', ({ enforced }) => {
    expect(ENFORCED_MARKS).toContain(enforced);
  });

  // The column has to be able to say both things. A table that had drifted to
  // all-✅ or all-⛔ would satisfy every per-row check above while describing a
  // state nobody measured — and all-✅ in particular is the shape that reads as
  // "everything gates" while six checks block nothing.
  it('records both enforced and not-enforced checks, so the column is load-bearing', () => {
    const marks = new Set(rows.map((row) => row.enforced));
    expect([...marks].sort()).toEqual([...ENFORCED_MARKS].sort());
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
  // NOT required — it runs only on the schedule and on a push to main, so
  // requiring it would block every PR on a check that is permanently skipped
  // there.
  // The alert-count job reports a check too, and it is deliberately NOT
  // required for the same reason: it runs only on its own schedule, so on a PR
  // it is SKIPPED — and GitHub reports a skipped required check as pending, so
  // requiring it would block every PR for ever on a check that never reports.
  it('does not require the CodeQL alert-count job', () => {
    expect(checkNames('codeql-alerts.yml')).toContain('Open alerts match the baseline');
    expect(requiredChecks().map((row) => row.check)).not.toContain(
      'Open alerts match the baseline',
    );
  });

  it('does not require the unattended advisory-reporting job', () => {
    expect(checkNames('audit.yml')).toContain('File advisory issue (unattended runs)');
    expect(rows.map((row) => row.check)).not.toContain('File advisory issue (unattended runs)');
  });

  // The job's NAME is the claim; its `if:` is what decides. They drifted apart
  // once already — the name said "scheduled runs" while a main-push failure was
  // the case nobody was watching, and the branch that ships stayed red for up
  // to a day with no issue filed. Pin both halves so the next widening has to
  // say so in the name too.
  it('files an advisory issue for a push to main as well as for the schedule', () => {
    const block = jobBlock(readWorkflow('audit.yml'), 'report');
    expect(block).toMatch(/github\.event_name == 'schedule'/);
    expect(block).toMatch(/github\.event_name == 'push'/);
    expect(block).toMatch(/github\.ref == 'refs\/heads\/main'/);
    // And still not on a PR, where the red check is already the signal in front
    // of the one person who can act on it. Without this the case above is
    // satisfied by an `if:` that fires on everything.
    expect(block).toMatch(/needs\.audit\.result == 'failure'/);
    expect(block).not.toMatch(/event_name == 'pull_request'/);
  });
});

// The Enforced column above is a claim about repository state, and the only
// thing that can keep it true is something that reads that state. This pins the
// wiring — that the workflow exists, runs unattended, and drives the gate — since
// every one of those can be removed leaving a table that still reads as audited.
describe('the job that holds the enforced column against reality', () => {
  const workflow = () => readWorkflow('required-checks.yml');

  it('runs the gate rather than restating the table in YAML', () => {
    expect(workflow()).toMatch(/node tools\/required-checks-gate\/src\/check-required\.ts/);
  });

  // Scheduled, because its answer has nothing to do with any PR's diff: it reads
  // live settings, so as a PR check it would fail for a change somebody else
  // made — which is a check people re-run rather than read.
  it('runs on a schedule, so nothing has to remember to ask', () => {
    expect(triggerBlock('required-checks.yml')).toMatch(/^ {4}- cron: '[^']+'$/m);
  });

  // And on a push touching the record itself, so a PR that flips a row learns
  // within minutes of merging whether it told the truth. Without this the
  // feedback on an edit to the column arrives the next morning, by which time
  // it reads as an unrelated failure.
  it('also runs when the record or the reader changes', () => {
    const trigger = triggerBlock('required-checks.yml');
    expect(trigger).toMatch(/^ {6}- 'CONTRIBUTING\.md'$/m);
    expect(trigger).toMatch(/^ {6}- 'tools\/required-checks-gate\/\*\*'$/m);
  });

  // It reads the table it is checking, so it must not also be IN it: requiring
  // it would put a live GitHub query on the critical path of every merge, and
  // its red means a settings drift nobody's PR caused.
  it('is not itself one of the checks it gates on', () => {
    expect(requiredChecks().map((row) => row.file)).not.toContain('required-checks.yml');
  });
});

// The two scheduled repository-state gates. Both read state that only settles
// AFTER something else finishes, and both were got wrong once in review.
describe('the scheduled repository-state gates', () => {
  // A `push` trigger here reads the Security tab as it stood BEFORE the merge:
  // an alert closes only when a later analysis stops reporting it, and
  // codeql.yml takes ~2m20s on a main push while this job starts in seconds. It
  // had one, and the effect was systematic — do what the gate's own failure text
  // says (fix one alert, lower the baseline in the same commit) and the push run
  // calls the lowered baseline a RISE and prints "Do not raise the baseline" at
  // the commit that correctly lowered it.
  it('codeql-alerts.yml has no push trigger, so it never reads a pre-merge count', () => {
    const trigger = triggerBlock('codeql-alerts.yml');
    expect(trigger).toMatch(/^ {2}schedule:/m);
    expect(trigger).not.toMatch(/^ {2}push:/m);
  });

  // Specifying `permissions` at all sets every unlisted scope to `none`, and
  // this job's whole purpose is two GraphQL reads that cross TWO surfaces:
  // `repository.pullRequests` needs `pull-requests`, and the `statusCheckRollup`
  // CheckRun nodes it selects need `checks`. Missing either is a daily red that
  // says "could not read the required-check state" and nothing about the repo.
  it.each(['pull-requests', 'checks'])(
    'required-checks.yml grants %s: read, which its queries cross',
    (scope) => {
      expect(jobBlock(readWorkflow('required-checks.yml'), 'required-checks')).toMatch(
        new RegExp(`^ {6}${scope}: read$`, 'm'),
      );
    },
  );
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

  // Retargeting a PR's base fires ONLY `edited`. `ci.yml` needs that type to
  // avoid a permanent deadlock, because its `branches: [main]` filter means a
  // stacked PR matches no event until it is retargeted. `codeql.yml` has no
  // such filter, so the deadlock is unreachable there — but the retarget still
  // changes the MERGE COMMIT, so an analysis that does not re-run describes a
  // tree nobody will merge while reporting green. Both workflows carry the type
  // for those two different reasons; pin both, since the second is the one a
  // reader is likeliest to trim as redundant.
  it.each(['ci.yml', 'codeql.yml'])('%s re-runs when a PR is retargeted', (file) => {
    const trigger = /^ {2}pull_request:[^\S\n]*$([\s\S]*?)(?=^ {2}[^\s#])/m.exec(
      dropComments(readWorkflow(file)),
    );
    expect(trigger, `${file} has no pull_request trigger block`).not.toBeNull();
    expect(trigger[1]).toMatch(/types:\s*\[[^\]]*\bedited\b[^\]]*\]/);
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

// A workflow declaring no `permissions:` anywhere takes the repository's DEFAULT
// token scope. That default is a repository setting — invisible to anyone reading
// this tree, and widenable for every workflow at once by an admin who never
// touches a file here. So the scope such a workflow runs with is not a property
// of the workflow at all, which is why CodeQL's `actions/missing-workflow-
// permissions` flags it and why it is worth deriving rather than pinning to the
// one file that was missing it. `build-binaries.yml` was that file, and it is the
// only reason this check exists — but a pin on that name would go green the
// moment it was fixed and say nothing about the fourteenth workflow.
describe('every workflow declares its token scope', () => {
  // Top-level OR every job — the same disjunction the CodeQL rule uses. Four
  // release workflows take the second form (each job narrows its own scope, one
  // of them to `id-token: write` for provenance), so requiring the top-level form
  // outright would fail them for being MORE precise than the rule asks.
  // BOTH extensions: GitHub honours `.yaml` exactly as it honours `.yml`, so a
  // workflow named that way would escape this guard entirely — and the
  // non-vacuity check below counts files, so it cannot see one that was never
  // enumerated. The claim this describe makes is about EVERY workflow.
  const isWorkflow = (file) => file.endsWith('.yml') || file.endsWith('.yaml');
  const workflowFiles = () => readdirSync(WORKFLOWS).filter(isWorkflow);

  // Job keys sit at two spaces inside `jobs:`; their own keys sit at four, and a
  // step's at six with a `- `. Comments are dropped first, or a `#` line inside a
  // `run:` block reads as a job key.
  const jobKeys = (file) =>
    [...dropComments(topLevelBlock(file, 'jobs', /^ {2}\S/m)).matchAll(/^ {2}([\w-]+):/gm)].map(
      ([, key]) => key,
    );

  // Non-vacuity, and it has to name a file rather than assert a count: an empty
  // enumeration satisfies `it.each` by registering no tests at all, and vitest
  // reports that as a pass. `build-binaries.yml` is the file this check was
  // written for, so a reader that stopped finding it would be reporting on
  // nothing while looking green.
  it('enumerates the workflow files, so the per-file cases below are not vacuous', () => {
    expect(workflowFiles()).toContain('build-binaries.yml');
    expect(workflowFiles().length).toBeGreaterThan(10);
  });

  it.each(workflowFiles())('%s narrows the default token scope', (file) => {
    const source = dropComments(readWorkflow(file));
    if (/^permissions:/m.test(source)) return;
    // No top-level block, so every job must carry one of its own. Assert the job
    // list is non-empty first: a workflow whose jobs failed to parse would
    // otherwise satisfy `every` on an empty array — the vacuous pass this whole
    // describe exists to avoid, reached one level down.
    const keys = jobKeys(file);
    expect(keys.length, `${file}: no jobs parsed, so the per-job check is vacuous`).toBeGreaterThan(
      0,
    );
    for (const key of keys) {
      expect(
        jobBlock(readWorkflow(file), key),
        `${file}: job \`${key}\` declares no permissions`,
      ).toMatch(/^ {4}permissions:/m);
    }
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
    expect(block).toMatch(/uses: actions\/cache\/restore@/);
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

  // The second entry the derived check above cannot reach, and pinned for the
  // same reason: `private: true` puts it outside the `private !== true` rule by
  // construction, so a bare filter line could be removed with nothing going red
  // — which is exactly what the `private !== true` rule deliberately will not
  // protect.
  //
  // What it buys is narrow and has no substitute. `plugins/browser-extension/
  // test/native-host/scan-worker-bundle.e2e.test.ts` is the only place
  // `resolveWorkerUrl()` runs from the built NATIVE HOST, and that resolver is
  // `fileURLToPath` over a bundled script's own URL — the one thing in the
  // isolated-scan path that can differ on Windows and nowhere else. A miss
  // returns undefined, the host keeps serving, and every pulled and custom
  // regex rule is dropped on that machine with nothing failing loudly.
  //
  // The sibling property — that the Windows INSTALL of the native host works —
  // is covered by `cli`'s extension suite and is not this. Installing the host
  // is not the same as the host resolving its worker at runtime, so neither
  // check stands in for the other.
  it('tests the native-messaging host, which is private but ships inside the CLI', () => {
    const block = jobBlock(ci, 'windows');
    expect(block).toMatch(/turbo run test/);
    expect(block).toMatch(/--filter=@akasecurity\/plugin-browser-extension(?![\w-])/);
  });

  // The pin above is a filter entry, and a filter entry only buys a Windows run
  // of the case that matters while that case EXISTS. The three older cases in
  // that file check the worker is emitted, that its name is a literal in the
  // bundle, and that it runs when this suite starts it directly — none of which
  // drives the resolver as the shipped bundle inlines it, and all of which
  // would go on passing on Windows while the property the leg was widened for
  // went unexercised. So pin the case by name too: deleting it is then a red
  // test rather than a silently narrower leg.
  it('drives the built host, not only the worker started by the suite itself', () => {
    const suite = readFileSync(
      join(
        REPO_ROOT,
        'plugins',
        'browser-extension',
        'test',
        'native-host',
        'scan-worker-bundle.e2e.test.ts',
      ),
      'utf8',
    );
    expect(suite).toContain('is found by the built host’s own resolver');
    // The positive control on the pin: it is a spawn OF the built host script,
    // not another Worker the suite constructs. Without this the assertion above
    // is satisfied by a case renamed to match and rewritten to do anything.
    expect(suite).toMatch(/spawnSync\(process\.execPath, \[join\(HOST_DIR, HOST_SCRIPT\)\]/);
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
    expect(block).toMatch(/uses: actions\/cache\/restore@/);
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

  // Unfiltered AND unbounded is what this leg cannot be. `pnpm lint` fans
  // `turbo run lint` across every package, and each package task runs its own
  // ESLint. Windows answers a process storm of that size with
  // STATUS_DLL_INIT_FAILED (0xC0000142, exit 3221225794): the child never starts,
  // so there is no lint output to read and the package that dies moves between
  // runs, which is what distinguishes it from a real violation. Every
  // `turbo run test` invocation in this file is bounded for the same reason; this
  // leg was the one that never got it.
  //
  // Peak parallelism is turbo's concurrency and nothing else — a package making
  // two ESLint passes chains them with `&&`, so they are sequential and add
  // nothing to the peak. That is what makes the env var the whole lever, and it
  // is why this asserts a bound rather than counting passes.
  //
  // The bound is asserted through `env:` rather than a flag on the step, and that
  // is forced rather than chosen: the two assertions above pin the step as exactly
  // `pnpm lint`, because going to turbo directly drops `lint:root` and
  // `check:portability`. `TURBO_CONCURRENCY` is turbo's own spelling of the flag —
  // verified against the pinned turbo, where an invalid value fails with the same
  // `--concurrency` parse error the flag produces, which an unread variable could
  // not do.
  //
  // Paired with the positive control for the reason the filter check is: a block
  // that captured nothing satisfies an absence, and it would satisfy a bare
  // presence check here too if the value were never read. So read the value and
  // require it to be a small positive integer — `TURBO_CONCURRENCY: 0` is refused
  // by turbo at startup, and a large one is the unbounded case wearing a number.
  it('bounds how many packages lint at once', () => {
    const block = jobBlock(ci, 'windows-lint');
    expect(block).toMatch(LINT_STEP);
    const bound = /^ {6}TURBO_CONCURRENCY: (\d+)$/m.exec(block);
    expect(bound, 'the Windows lint job declares no TURBO_CONCURRENCY bound').not.toBeNull();
    expect(Number(bound[1])).toBeGreaterThan(0);
    expect(Number(bound[1])).toBeLessThanOrEqual(4);
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
  // twenty-one other scripts still expand, so nothing here reddens.
  //
  // The count is pinned first for the usual reason: an empty list satisfies a
  // `for` loop over it without checking anything. It is a floor AND a ceiling, so
  // a package added without a lint script is caught by the same assertion.
  //
  // It is also the one number here that two branches can both raise to the SAME
  // value for different reasons and merge clean: one adding a package and one
  // adding another both write 21, git sees identical text, and the merged truth
  // is 22. Re-derive it after a merge rather than trusting that it merged.
  it('every lint script carries the glob this job exists to observe', () => {
    const scripts = workspaceLintScripts();
    expect(scripts).toHaveLength(24);
    for (const { dir, lintScript } of scripts) {
      expect(lintScript, `${dir} declares no lint script`).not.toBe('');
      expect(lintScript, `${dir}'s lint script targets no *.config.* glob`).toContain('*.config.*');
    }
    // And the repo-root pass, which is the twenty-third invocation rather than a
    // twenty-third package — it is the only one covering files no package owns.
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

  // The host variables the Windows installer cases need, which turbo's `strict`
  // env mode does NOT pass by default. These are `passThroughEnv` rather than
  // `env` on purpose: they describe the RUNNER, so hashing one would fork the
  // cache per machine while saying nothing about the inputs.
  //
  // Pinned as a set because the two halves fail differently and only one of them
  // says so. Dropping PROCESSOR_ARCHITECTURE is caught at the spawn by
  // `assertHostArchitecture`, which names the variable and this very field.
  // Dropping a system variable is caught by nothing: Windows PowerShell loses
  // the module path it derives from %SystemRoot%, `Compress-Archive` never
  // autoloads, and the case spends its whole timeout before failing as a
  // 120-second hang that names no variable at all.
  it.each([
    'PROCESSOR_ARCHITECTURE',
    'SystemRoot',
    'windir',
    'ComSpec',
    'SystemDrive',
    'LOCALAPPDATA',
  ])('passes %s through to the Windows test child', (name) => {
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const testTask = /^ {4}"test": \{$([\s\S]*?)^ {4}\},$/m.exec(turbo)?.[1] ?? '';
    expect(testTask, 'turbo.json has no parseable `test` task').not.toBe('');
    const passThrough = /"passThroughEnv": *\[([\s\S]*?)\]/.exec(testTask)?.[1] ?? '';
    expect(passThrough, 'the `test` task declares no `passThroughEnv`').not.toBe('');
    expect(passThrough).toContain(`"${name}"`);
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
    // The restore `key:`, its two restore-keys, and the save `key:`. Pinned so a
    // key added without the prefix cannot hide behind a loop that happens to see
    // none.
    expect(keys).toHaveLength(4);
    for (const key of keys) {
      expect(key.startsWith('turbo-${{ runner.os }}-')).toBe(true);
    }
    // Restore and save must name the SAME key, or the run uploads its cache
    // under a key no later run ever looks up — which reads as caching and
    // caches nothing. Positional because the length above is pinned: the
    // restore step's `key:` comes first and the save step's last.
    const [restoreKey, , , saveKey] = keys;
    expect(saveKey).toBe(restoreKey);
  });

  // The combined `actions/cache` saves in a post step that GitHub skips once an
  // earlier step has failed, so under it a leg that goes RED saves nothing, and
  // the next run finds no entry for its own lockfile lineage, falls back to an
  // older one and misses on every task. That is a loop rather than a one-off:
  // the cold run is slower, a slower run is likelier to time out, and a
  // timed-out run saves nothing again. Windows sat in it at 0 of 36 cached
  // tasks while the two green legs cached normally — the leg that needed a warm
  // cache most was the one structurally guaranteed not to get one.
  //
  // Three things break the loop and all three are pinned, because any one of
  // them alone restores it silently: the combined action must be GONE (it is
  // the trap), a save step must exist, and its `if:` must not fall back to the
  // default `success()` — which is precisely what skips it on a red job.
  it.each(['ci', 'macos', 'windows'])('%s saves its cache even when the job fails', (job) => {
    const block = jobBlock(ci, job);
    expect(block).toMatch(/uses: actions\/cache\/restore@/);
    expect(block).not.toMatch(/uses: actions\/cache@/);

    const save = /- name: Save Turbo cache\n([\s\S]*?)uses: actions\/cache\/save@/.exec(block);
    expect(save, `\`${job}\` has no Save Turbo cache step`).not.toBeNull();
    expect(save[1]).toMatch(/if: \$\{\{ !cancelled\(\)/);
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
    expect(block).not.toMatch(ANY_CACHE_ACTION);
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
    expect(block).not.toMatch(ANY_CACHE_ACTION);
  });
});

// A `pull_request` check runs against a merge commit GitHub built when the branch
// was last pushed, and never rebuilds as `main` moves. Several guards in this
// repository derive their expectations from the tree at run time, so two branches
// can each be green against a tree the other has already changed, and the first
// run that sees both is the post-merge run on `main`. CONTRIBUTING.md's "Branch
// freshness" section records which repository setting closes that; these suites
// hold the half of it that lives in the tree.
//
// Neither property below can be seen in a diff. A missing `merge_group` trigger
// looks like every workflow that predates the queue, and a concurrency group is
// one line nobody re-reads.
describe('the gating workflows can run in a merge queue', () => {
  const workflows = gatingWorkflows();

  // `it.each([])` registers no tests and reports nothing, so a derivation that
  // stopped matching would empty every loop below while leaving the run green.
  // The four are named rather than counted: a floor also clears on junk, and the
  // two exclusions are as load-bearing as the inclusions — `build-binaries.yml`
  // runs on PRs but gates nothing, and requiring a queue build of four binaries
  // per entry would be a real cost added by a guard nobody asked for.
  it('derives the gating workflows, so the loops below are not vacuous', () => {
    expect(workflows).toEqual(['audit.yml', 'ci.yml', 'codeql.yml', 'internal-path-guard.yml']);
  });

  // Every workflow behind a required check has to be one of them, or the table
  // names a check that cannot gate a PR in the first place.
  it('covers every workflow behind a required check', () => {
    expect(workflows).toEqual(expect.arrayContaining(requiredWorkflows()));
  });

  // THE assertion this suite exists for. A merge queue reaches a workflow through
  // `merge_group` and no other event, so a gating check missing it does not go
  // red in the queue — it never reports, and the entry waits on it indefinitely.
  // That failure arrives the day the queue is switched on, in a workflow whose
  // last change may be months old, which is why it is pinned before then.
  it.each(workflows)('%s triggers on merge_group', (file) => {
    expect(triggerBlock(file), `${file} would never report in a merge queue`).toMatch(
      /^ {2}merge_group:/m,
    );
  });
});

describe('the concurrency groups of the gating workflows', () => {
  const workflows = gatingWorkflows();

  // A push to `main` and a merge-queue entry are each the only run their commit
  // will ever get. Cancelling one does not save a re-run, it leaves that commit
  // with no verdict — and the next red run then carries a SHA whose own change
  // was not the cause, which is how an innocent commit gets implicated.
  //
  // The expression is pinned WHOLE rather than by the substring it contains. A
  // substring test passes on its own inversion: `!(github.event_name ==
  // 'pull_request')` and `… || true` both contain the condition and both restore
  // the defect, the first by cancelling exactly the runs that must never be
  // cancelled. Measured — both matched the substring form this replaced.
  it.each(workflows)('%s cancels a superseded PR run and nothing else', (file) => {
    expect(
      concurrencyBlock(file),
      `${file} does not condition cancelling on the event being a pull_request`,
    ).toMatch(/^ {2}cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}$/m);
  });

  // The other half, and the one that reads as already fixed once cancelling is
  // conditioned. It is not: with the group still keyed on the ref, every push to
  // `main` shares `refs/heads/main`, and a group that does not cancel QUEUES
  // instead — so the second merge waits out the first run in full rather than
  // losing it. Keying non-PR events by SHA is what gives each merged commit a
  // group of its own, and nothing above would notice its removal.
  //
  // Pinned as the whole ternary for the same reason: a bare `github.sha` test
  // passes on the swap that keys PRs by sha and main by ref, which reintroduces
  // this defect AND silently drops the PR-supersede saving the block opens with.
  it.each(workflows)('%s gives a non-PR run a group of its own', (file) => {
    expect(
      concurrencyBlock(file),
      `${file}'s group does not key non-PR events by SHA, so main runs queue behind each other`,
    ).toMatch(/^ {2}group:.*github\.event_name == 'pull_request' && github\.ref \|\| github\.sha/m);
  });

  // The event name separates a merge_group run from the push that follows it:
  // the queue advances `main` to the merge-group commit, so those two events
  // carry the same SHA and would otherwise share a group.
  it.each(workflows)('%s keys its group on the event as well', (file) => {
    expect(concurrencyBlock(file)).toMatch(/^ {2}group:.*\$\{\{ github\.event_name \}\}/m);
  });
});

describe('the branch-freshness decision in CONTRIBUTING.md', () => {
  const { documented, mechanism } = branchFreshness();

  it('is recorded where a contributor reading about branch protection will find it', () => {
    expect(documented, 'CONTRIBUTING.md carries no `### Branch freshness` section').toBe(true);
    expect(
      mechanism,
      'CONTRIBUTING.md carries no `**Mechanism in use/chosen: …**` line',
    ).not.toBeNull();
    expect(MECHANISMS, `"${mechanism}" is not one of the mechanisms`).toContain(mechanism);
  });

  // The record is driven against the tree rather than merely being present. A
  // note reading "merge queue" beside workflows no queue can run is worse than no
  // note at all, because the next person reads it as settled and stops looking.
  //
  // Pinning that the recorded mechanism is the one WITH a tree obligation is what
  // keeps this non-vacuous: the alternative setting obliges the tree to carry
  // nothing, so a decision changed to it would leave the loop below asserting
  // over an empty requirement while staying green. Changing the decision means
  // editing this test — which is the deliberate act the record exists to force.
  it('is the mechanism the workflows are actually wired for', () => {
    expect(
      mechanism,
      `"${mechanism}" obliges this tree to carry nothing, so the check below would assert nothing`,
    ).toBe(MECHANISM_NEEDING_MERGE_GROUP);
    for (const file of gatingWorkflows()) {
      expect(triggerBlock(file), `${file} cannot run in the recorded mechanism`).toMatch(
        /^ {2}merge_group:/m,
      );
    }
  });
});

// A step that shells a root script fans turbo at its DEFAULT of 10 unless
// something bounds it, and the bound cannot be a flag on the step: `pnpm lint --
// --concurrency=4` appends to the end of a `&&` chain, landing on
// `check:portability` rather than on turbo. The job-level environment is the only
// lever that reaches every fan in a job at once.
//
// Derived rather than listed. The Windows lint leg was bounded on its own after a
// real 0xC0000142, and the file-wide claim written beside it was wrong — the Linux
// job fanned unbounded three separate times and nobody noticed, because nothing
// asked. Naming the two jobs here would repeat that: the property is "a job that
// fans turbo unbounded declares a bound", and a third job added tomorrow is
// covered by it on the day it lands.
describe('the turbo fans in ci.yml are bounded', () => {
  const ci = readWorkflow('ci.yml');

  // Which root scripts expand to a `turbo run` carrying no `--concurrency` of its
  // own. Read from the manifest rather than listed, so a script that grows or
  // loses a bound is reflected here without an edit.
  const unboundedScripts = Object.entries(rootScripts())
    .filter(([, cmd]) => /\bturbo run\b/.test(cmd) && !/--concurrency/.test(cmd))
    .map(([name]) => name);

  // Scope is computed OUT here rather than branched on inside the test body. A
  // body that returns before asserting reports as a pass, so looping over every
  // job and returning early for the ones out of scope would have three of the five
  // claiming a check the run never made — the shape this repo requires a
  // `ctx.skip` for, and `it.each` passes no context to skip with. Deriving the
  // in-scope set instead means every registered case asserts, and the set itself
  // is what the vacuity test pins.
  //
  // This reader does NOT assert, deliberately: it runs in the `describe` body, and
  // an assertion there is a collection error that reports the whole FILE as
  // `(0 test)`. Each `it` re-resolves its block through `jobBlock`, which does
  // assert, where a failure is a test failure.
  const jobNames = [...ci.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)]
    .map(([, name]) => name)
    .filter((name) => name !== 'push');

  // `pnpm <script>` as the WHOLE command — `pnpm turbo run test --concurrency=2`
  // is a direct call carrying its own flag, and `pnpm lint:root` is a different
  // script that fans nothing, so the boundary excludes `:` and `-`.
  const fansOf = (block) =>
    unboundedScripts.filter((s) => new RegExp(`run: pnpm ${s}(?![\\w:-])`).test(block));

  const jobsWithFans = jobNames.filter((job) => {
    const raw = new RegExp(
      `^ {2}${job}:[^\\S\\n]*$([\\s\\S]*?)(?=^ {2}\\S|\\s*$(?![\\s\\S]))`,
      'm',
    ).exec(ci)?.[1];
    return raw !== undefined && fansOf(dropComments(raw)).length > 0;
  });

  // Pins the derivation from both ends. The scripts must include the three that
  // really are unbounded, and the in-scope jobs must be exactly the two that run
  // them — an EXACT set, because a floor would stay green if the scoping regex
  // quietly stopped matching a job, which is the failure that empties the loop.
  it('derives the scripts and jobs to check, so the loop below is not vacuous', () => {
    expect(unboundedScripts).toEqual(expect.arrayContaining(['lint', 'typecheck', 'build']));
    expect(jobsWithFans).toEqual(['ci', 'windows-lint']);
  });

  // The property, over jobs that are all genuinely in scope. `jobBlock` strips
  // comments first, so a bound that has been commented out reads as absent —
  // which is the point.
  it.each(jobsWithFans)('%s bounds every turbo fan it runs', (job) => {
    const block = jobBlock(ci, job);
    const fans = fansOf(block);
    expect(
      fans.length,
      `${job} was selected as fanning turbo but runs none of the scripts`,
    ).toBeGreaterThan(0);
    const bound = /^ {6}TURBO_CONCURRENCY: (\d+)$/m.exec(block);
    expect(
      bound,
      `${job} runs ${fans.map((f) => `\`pnpm ${f}\``).join(', ')} but declares no TURBO_CONCURRENCY`,
    ).not.toBeNull();
    expect(Number(bound[1]), `${job}'s bound must be a positive integer`).toBeGreaterThan(0);
    expect(Number(bound[1]), `${job}'s bound is high enough to be no bound`).toBeLessThanOrEqual(8);
  });
});
