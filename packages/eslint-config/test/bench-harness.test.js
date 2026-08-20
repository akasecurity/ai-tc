// The benchmark harness has two failure modes, and both are SILENT GREENS.
//
// 1. It measures nothing. `turbo run bench` skips a package with no `bench`
//    script without a word, so a package that grows a bench/ directory and no
//    script contributes zero benchmarks to a nightly job that goes on reporting
//    success. Nothing in the output distinguishes "ran and was fast" from "never
//    ran" — which is the same shape as the cached-green hazard the rest of this
//    package exists for, arriving through a missing script instead of a stale
//    hash.
//
// 2. It starts gating. The one rule this harness has is that nothing gates a PR
//    on wall-clock: hosted runners vary by a large factor on neighbour load
//    alone, this repository has retuned three timing assertions for exactly
//    that, and a check that fails for reasons unrelated to the diff is a check
//    people learn to re-run until green. Adding `pull_request:` to bench.yml is
//    one line, reads as an improvement in review, and quietly converts a trend
//    recorder into a flake source.
//
// Neither is visible in a diff and neither turns anything red, so both are
// asserted here. This package rather than a per-package suite for the reason its
// siblings give: only this task's turbo `inputs` hash the whole workspace, so a
// bench/ directory appearing in `plugins/` is seen here and would replay a
// cached pass anywhere else. bench.yml is named in those inputs for the same
// reason ci.yml is.

import { existsSync, readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

import { describe, expect, it } from 'vitest';

import { cardinalFor, countWordIn, readConventions, sectionOf } from './helpers/claude-md.js';

import {
  lintableTrackedFiles,
  readPackageManifest,
  REPO_ROOT,
  rootScripts,
  trackedFiles,
  workspacePackageDirs,
} from './helpers/lint-invocations.js';

const WORKFLOW_REL = '.github/workflows/bench.yml';

/** The conventions section this suite is named by, and the sentence that counts it. */
const BENCH_HEADING = '### Benchmarks are a trend, never a gate';
const PROPERTY_COUNT_SENTENCE = /\b(\w+) properties are load-bearing, and each is enforced by\b/g;
const WORKFLOW = join(REPO_ROOT, WORKFLOW_REL);

/** The directory a package keeps benchmarks in, and the basename vitest collects. */
const BENCH_DIR = 'bench';
const BENCH_FILE = /\.bench\.[cm]?[jt]sx?$/;

/**
 * How a file announces a comment, by extension — and so which files this scan
 * can read at all.
 *
 * Split by KIND rather than run through one marker set, because the sets
 * genuinely differ: `#` opens a comment in YAML and opens a private field in
 * TypeScript. One combined pattern reads `#cache = new Map()` as prose and scans
 * a line of code as if it were a claim.
 *
 * Every extension here must also be in this task's turbo `inputs` (see
 * turbo.json), or editing one of these files moves no hash and turbo replays a
 * cached green at the moment this guard exists to fire.
 */
const PROSE_KINDS = [
  { ext: /\.md$/, kind: 'markdown' },
  { ext: /\.ya?ml$/, kind: 'hash' },
  { ext: /\.([cm]?[jt]sx?|json)$/, kind: 'slash' },
];

/** The comment kind for `file`, or undefined for a file this scan cannot read. */
const proseKindOf = (file) => PROSE_KINDS.find((k) => k.ext.test(file))?.kind;

/**
 * Ways of saying that a human is the only thing that runs the benchmarks.
 *
 * Shapes rather than exact wording, so a reworded claim is still caught; a form
 * that slips past belongs here. Deliberately NARROWER than the denials used
 * against turbo.json's own comment: that list is already scoped to the one block
 * above the `bench` task, so it can afford a phrase as generic as "does not
 * exist". Tree-wide, that same phrase reads an unrelated sentence in
 * shared-test-inputs.test.js — "a requirement that does not exist", in a block
 * that happens to name a .bench.ts path — as a claim about the harness. A guard
 * that reports a file with nothing wrong in it is spent faster than one that
 * misses a case.
 */
const MANUAL_ONLY = [
  /\brun by hand\b/i,
  /\brun manually\b/i,
  /\bno workflow\b/i,
  /\bnothing (?:invokes|runs)\b/i,
];

/** Ways of acknowledging the unattended run, so a claim naming both is honest. */
const ACKNOWLEDGES_SCHEDULE = [/\bnightly\b/i, /bench\.yml/];

/**
 * Whether `block` claims a human is the only thing that runs the benchmarks.
 *
 * One predicate, used by the tree scan and by the control case that proves the
 * scan can still see anything. Two copies would be free to disagree, and the
 * copy that quietly stopped matching is the tree one — which reports a clean
 * tree either way.
 */
const deniesSchedule = (block) =>
  MANUAL_ONLY.some((r) => r.test(block)) && !ACKNOWLEDGES_SCHEDULE.some((r) => r.test(block));

/** A markdown line that begins a new item or section, and so a new block. */
const MARKDOWN_BLOCK_START = /^ {0,3}(?:[-*+] |\d+[.)] |#{1,6} )/;

/**
 * Every contiguous run of prose in `text`, as `{ line, block }` — a comment run
 * in code, a paragraph in markdown.
 *
 * The BLOCK rather than the line is the unit, because the two halves of the
 * claim are routinely sentences apart: in the case that motivated this, the
 * reference to `bench/project-files.bench.ts` and the manual-only phrase sat on
 * different lines of one comment, and a line reader sees neither half as a claim
 * about anything.
 *
 * Note that a specimen of the bad phrasing, quoted anywhere in the tree, is a
 * real match rather than a false one — this guard cannot tell a quotation from a
 * claim. Describe the shape rather than quoting it, or name the workflow in the
 * same block, which is what every honest mention of it does anyway.
 */
function proseBlocks(text, kind) {
  const isProse = (line) =>
    kind === 'markdown'
      ? line.trim() !== ''
      : kind === 'hash'
        ? /^\s*#/.test(line)
        : /^\s*(\/\/|\/\*|\*)/.test(line);

  const lines = text.split('\n');
  const blocks = [];
  let start = null;
  const flush = (end) => {
    if (start !== null) blocks.push({ line: start + 1, block: lines.slice(start, end).join('\n') });
    start = null;
  };
  lines.forEach((line, i) => {
    if (!isProse(line)) {
      flush(i);
      return;
    }
    // A markdown list runs without blank lines between its items, so a blank-line
    // split alone makes a whole list ONE block — and one item saying `nightly`
    // then exempts a stale claim in every other item. That is not hypothetical:
    // this document's own six-property list is 27 lines and already names the
    // nightly, so a manual-only claim added to any bullet in it went unreported.
    // Headings bound a block for the same reason.
    if (kind === 'markdown' && start !== null && MARKDOWN_BLOCK_START.test(line)) flush(i);
    start ??= i;
  });
  flush(lines.length);
  return blocks;
}

/**
 * Every workspace package, with what it holds and what it declares.
 *
 * Both halves are DERIVED — the files from the tracked tree, the scripts from
 * the real manifests — because the failure this guards against is a package
 * nobody remembered to add to a list.
 */
function benchPackages() {
  const tracked = lintableTrackedFiles();
  return workspacePackageDirs()
    .map((dir) => {
      const prefix = `${dir}/${BENCH_DIR}/`;
      const benchFiles = tracked.filter(
        (f) => f.startsWith(prefix) && BENCH_FILE.test(posix.basename(f)),
      );
      const manifest = readPackageManifest(dir);
      return {
        dir: dir,
        name: manifest.name,
        benchFiles,
        benchScript: manifest.scripts?.bench ?? '',
        lintScript: manifest.scripts?.lint ?? '',
        tsconfig: join(REPO_ROOT, dir, 'tsconfig.json'),
      };
    })
    .filter((p) => p.benchFiles.length > 0 || p.benchScript !== '');
}

const PACKAGES = benchPackages();

/**
 * One `git ls-files` walk for this file. `benchPackages()` already asked for it
 * through `lintableTrackedFiles()`, and a second call spawns git again for an
 * answer that cannot have changed mid-run.
 */
const TRACKED = trackedFiles();

describe('the benchmark harness', () => {
  it('is wired somewhere at all', () => {
    // Every assertion below is a filter over PACKAGES, so an empty PACKAGES
    // satisfies all of them by describing a workspace with no harness in it.
    // This is the case that goes red for that.
    expect(PACKAGES.length).toBeGreaterThan(0);
    expect(PACKAGES.some((p) => p.benchFiles.length > 0)).toBe(true);
  });

  it('gives every package that holds benchmarks a `bench` script', () => {
    // The silent skip. turbo runs a task only where a script declares it, and
    // says nothing about a package that declares none — so these benchmarks
    // would exist in the tree, be lint-checked and typechecked, and never once
    // be executed by the nightly job.
    const unwired = PACKAGES.filter((p) => p.benchFiles.length > 0 && p.benchScript === '').map(
      (p) => `${p.name} (${p.dir}/${BENCH_DIR} holds benchmarks, no \`bench\` script)`,
    );
    expect(
      unwired,
      'turbo run bench SKIPS a package with no `bench` script, silently and with a zero exit. ' +
        `Add one — see packages/persistence/package.json:\n  ${unwired.join('\n  ')}`,
    ).toEqual([]);
  });

  it('gives every package with a `bench` script something to benchmark', () => {
    // The mirror image, and it fails loudly rather than silently — `vitest
    // bench` exits 1 with "No benchmark files found" — which is precisely why
    // it belongs here: a `bench` script added to a package in anticipation
    // turns the whole nightly job red until the files arrive.
    const empty = PACKAGES.filter((p) => p.benchScript !== '' && p.benchFiles.length === 0).map(
      (p) => `${p.name} (declares \`bench\`, holds no *.bench.ts under ${p.dir}/${BENCH_DIR})`,
    );
    expect(
      empty,
      `vitest bench exits 1 on a package with no benchmark files:\n  ${empty.join('\n  ')}`,
    ).toEqual([]);
  });

  it('writes results where the workflow collects them', () => {
    // The artifact upload globs `**/bench-results.json`. A script writing
    // somewhere else produces a run that measures everything and uploads
    // nothing, which reads in the Actions UI exactly like a run that measured
    // nothing.
    const workflow = readFileSync(WORKFLOW, 'utf8');
    const collected = /path:\s*'?\*\*\/([\w.-]+)'?/.exec(workflow);
    expect(collected, `${WORKFLOW_REL} declares no artifact path`).not.toBeNull();

    const wrong = PACKAGES.filter(
      (p) => p.benchScript !== '' && !p.benchScript.includes(collected[1]),
    ).map((p) => `${p.name} (\`bench\` writes no ${collected[1]}: ${p.benchScript})`);
    expect(wrong).toEqual([]);
  });

  it('never caches a benchmark result', () => {
    // The most load-bearing line in the whole harness, and the one with no other
    // guard on it. Every other turbo task derives its output from its inputs, so
    // replaying one is sound. A benchmark returns a MEASUREMENT, and the machine
    // it ran on — its load, its CPU, its disk — is in none of the hashes. A
    // cache hit would hand the trend another runner's number, taken at another
    // moment, and label it this run's. It is the one stale green that cannot be
    // spotted by reading the result, because the result looks exactly right.
    //
    // Read as text with a scoped regex rather than parsed: turbo.json is JSONC
    // and carries comments throughout, which is also how the rest of this
    // package reads it.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const task = /"bench"\s*:\s*\{([\s\S]*?)\n {4}\}/.exec(turbo);
    expect(task, 'turbo.json declares no `bench` task').not.toBeNull();
    expect(
      task[1],
      'the `bench` turbo task must set "cache": false — a replayed benchmark reports another ' +
        "machine's measurement as this run's",
    ).toMatch(/"cache"\s*:\s*false/);
  });

  it('keeps the `bench` comment honest about whether a workflow runs the task', () => {
    // turbo.json's comment and bench.yml are two statements of one fact, kept in
    // two files with nothing between them. The task BODY is not what is at risk —
    // `cache: false` is asserted directly above. The SENTENCE is: a branch written
    // before this workflow existed says, correctly, that nothing invokes the task,
    // and goes on saying it through a merge — at which point it documents the
    // opposite of what the repo does. No assertion here can catch that today,
    // because the task body is byte-identical whichever comment sits above it, so
    // every existing check stays green either way.
    //
    // Checked in both directions, since it can drift either way: a comment
    // claiming a nightly runner must find one, and a nightly runner that exists
    // must not be denied by the comment. The second half is the one that fires on
    // a rebase, at exactly the sentence that needs rewriting.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const block = /\n((?:[ \t]*\/\/.*\n)+)[ \t]*"bench"\s*:/.exec(turbo);
    expect(block, 'no comment block immediately above the `bench` task').not.toBeNull();
    const comment = block[1];
    // The positive control. Every absence assertion below passes on an empty
    // string, and a regex that stopped matching would hand back exactly that.
    expect(comment, 'the comment block above `bench` says nothing about it').toMatch(/bench/i);

    // Reality, read from the workflow rather than from what the comment says
    // about it — a schedule is what makes the job run unattended.
    const nightly = existsSync(WORKFLOW) && /^\s+schedule:/m.test(readFileSync(WORKFLOW, 'utf8'));

    if (nightly) {
      // Denials by shape rather than by exact wording, so a reworded one is still
      // caught. A form that slips past belongs in this list.
      // MANUAL_ONLY plus the one phrase only THIS case can afford: scoped to the
      // single block above the `bench` task, "does not exist" is unambiguous,
      // while tree-wide it reads unrelated prose. Two independent lists would be
      // free to drift, so the shared shapes are shared.
      const denials = [...MANUAL_ONLY, /\bdoes not exist\b/i];
      expect(
        denials.filter((d) => d.test(comment)).map(String),
        `${WORKFLOW_REL} runs this task on a schedule, but the comment above \`bench\` still ` +
          'denies that any workflow does',
      ).toEqual([]);
    } else {
      expect(
        comment,
        `the comment above \`bench\` claims a nightly run, but ${WORKFLOW_REL} schedules none`,
      ).not.toMatch(/nightly/i);
    }
  });

  it('keeps every claim about how the benchmarks run honest, not only turbo.json’s', () => {
    // The case above guards ONE sentence in ONE file. The same claim is made in
    // prose all over the tree — a perf suite explaining why its durations live in
    // bench/ rather than in an assertion, a bench file explaining what it leaves
    // to a human — and each of those is a statement about a SIBLING file with
    // nothing between them.
    //
    // That is not hypothetical. The header of
    // packages/plugin-sdk/test/performance/project-files-walk.test.ts said the
    // durations were "advisory and run by hand", written on a branch four hours
    // AFTER bench.yml landed on main, and it stayed green through the merge and
    // every run since — because no assertion anywhere read that sentence, and a
    // stale justification reads exactly like a live one.
    //
    // Pinning the two known sites by name would repeat that mistake one file
    // wider: the third site would be written tomorrow, guarded by nothing, and
    // the list would read as exhaustive. So the sites are DERIVED — any prose
    // block in the tracked tree that talks about benchmarks and claims a human is
    // the only thing that runs them.
    //
    // This suite already cannot run without bench.yml (the advisory describe
    // reads it at module scope), so the schedule is a precondition here rather
    // than a branch — asserted, so a workflow that loses its schedule fails
    // naming that rather than quietly turning the filter below into a tautology.
    expect(
      readFileSync(WORKFLOW, 'utf8'),
      `${WORKFLOW_REL} schedules no unattended run, so nothing below means anything`,
    ).toMatch(/^\s+schedule:/m);

    const benchProse = [];
    for (const file of TRACKED) {
      const kind = proseKindOf(file);
      if (kind === undefined) continue;
      const text = readFileSync(join(REPO_ROOT, file), 'utf8');
      for (const { line, block } of proseBlocks(text, kind)) {
        if (/\bbench/i.test(block)) benchProse.push({ file, line, block });
      }
    }

    // The positive control. The assertion below is an absence check over this
    // list, so an extractor that stopped matching — a comment syntax it does not
    // know, a `trackedFiles()` that came back empty — would satisfy it perfectly
    // while having read nothing at all. The floor is far under the ~90 blocks
    // across ~30 files the tree carries today, because this is a canary for a
    // scan that broke, not a second inventory to keep up to date.
    expect(
      benchProse.length,
      'found no prose about the benchmarks anywhere in the tracked tree',
    ).toBeGreaterThan(20);

    const stale = benchProse
      .filter(({ block }) => deniesSchedule(block))
      .map(({ file, line }) => `${file}:${line}`);

    expect(
      stale,
      `${WORKFLOW_REL} runs the benchmarks on a schedule, but these blocks still say a human is ` +
        `the only thing that does:\n  ${stale.join('\n  ')}`,
    ).toEqual([]);
  });

  it('can still recognise the claim it is looking for', () => {
    // The case above is an absence assertion over a filter, so EMPTYING
    // `MANUAL_ONLY` — or narrowing a pattern until it matches nothing — satisfies
    // it perfectly, over a tree it has read in full. The positive control there
    // counts blocks and so cannot see this: the scan keeps working, the predicate
    // stops. This drives the predicate itself, against the wording that actually
    // went stale and against the wording that replaced it.
    expect(
      deniesSchedule(
        'The durations live in `bench/x.bench.ts`, which is advisory and run by hand.',
      ),
      '`MANUAL_ONLY` no longer matches the phrasing that motivated this guard',
    ).toBe(true);
    expect(deniesSchedule('These benchmarks are run manually, and gate nothing.')).toBe(true);

    // And the other half: acknowledging the schedule is not an offence, or the
    // only way to a green tree would be to say nothing about the benchmarks.
    expect(
      deniesSchedule(
        'The durations live in `bench/x.bench.ts` — run by the nightly workflow and by hand.',
      ),
      'a block that names the unattended run is honest and must not be reported',
    ).toBe(false);
    expect(deniesSchedule('Run by hand, and by `.github/workflows/bench.yml` overnight.')).toBe(
      false,
    );

    // Prose about benchmarks that makes no claim about how they run is not the
    // subject at all.
    expect(deniesSchedule('This bench file measures the SessionStart walk.')).toBe(false);
  });

  it('states a property count that follows from the list rather than from memory', () => {
    // CLAUDE.md claims a NUMBER of load-bearing properties and names this file as
    // what enforces each. Nothing read that sentence, so the two cases added
    // alongside it took the count from four to six by hand — and a seventh, or a
    // deletion, would leave it stale with every test green. §1 of that document
    // records this exact drift about its own hook shapes: "it claimed four shapes
    // while six were reaching stdout".
    //
    // The count is derived from the bullets the sentence introduces, so the list
    // is the source and the word merely reports it.
    const section = sectionOf(readConventions(), BENCH_HEADING);
    const bullets = section.slice(section.search(PROPERTY_COUNT_SENTENCE)).match(/^- \*\*/gm);
    expect(bullets, `no property list under ${BENCH_HEADING}`).not.toBeNull();
    expect(
      countWordIn(section, PROPERTY_COUNT_SENTENCE, 'how many properties are load-bearing'),
    ).toBe(cardinalFor(bullets.length));
  });

  it('lints and typechecks the bench directory like any other source directory', () => {
    // A bench file imports product code and test helpers, so it is code — and
    // code outside every lint target and every tsconfig `include` has its types
    // stripped unchecked and its network bans never applied. The per-package
    // lint-coverage guard in effective-config.test.js reaches the lint half on
    // its own; the tsconfig half has nothing else looking at it.
    const gaps = [];
    for (const p of PACKAGES) {
      if (p.benchFiles.length === 0) continue;
      if (!p.lintScript.split(/\s+/).includes(BENCH_DIR)) {
        gaps.push(`${p.name}: \`lint\` does not target ${BENCH_DIR}/ (${p.lintScript})`);
      }
      if (!existsSync(p.tsconfig)) {
        gaps.push(`${p.name}: no tsconfig.json`);
        continue;
      }
      const include = JSON.parse(readFileSync(p.tsconfig, 'utf8')).include ?? [];
      if (!include.includes(BENCH_DIR)) {
        gaps.push(`${p.name}: tsconfig include omits ${BENCH_DIR} (${JSON.stringify(include)})`);
      }
    }
    expect(gaps).toEqual([]);
  });
});

describe('the benchmark workflow stays advisory', () => {
  const workflow = readFileSync(WORKFLOW, 'utf8');

  it('parses as the file this suite thinks it is reading', () => {
    // Every absence assertion below passes on an empty string. This is what
    // makes them mean something.
    //
    // Anchored to the start of a line, because `name:` appears twice in this
    // workflow and the substring form was satisfied by the WRONG one: the job
    // is named `Benchmarks (advisory)`, which contains `name: Benchmarks`, so
    // renaming the workflow itself left this green. A canary that a rename
    // cannot move is only guarding the half of the file nobody renames.
    expect(workflow).toMatch(/^name: Benchmarks$/m);
    expect(workflow).toMatch(/^jobs:$/m);
  });

  it('has no pull_request trigger', () => {
    // THE rule. One line converts this from a trend recorder into a wall-clock
    // gate on every PR, on runners whose variance this repository has already
    // been bitten by three times.
    const triggers = /^on:([\s\S]*?)^permissions:/m.exec(workflow);
    expect(triggers, 'could not find the `on:` block').not.toBeNull();
    expect(triggers[1]).not.toMatch(/^\s+pull_request/m);
    expect(triggers[1]).not.toMatch(/^\s+push:/m);
  });

  it('runs nightly and on demand', () => {
    // The positive control for the case above: a workflow with no triggers at
    // all also has no pull_request trigger, and would satisfy it while
    // recording nothing forever.
    const triggers = /^on:([\s\S]*?)^permissions:/m.exec(workflow);
    expect(triggers[1]).toMatch(/^\s+schedule:/m);
    expect(triggers[1]).toMatch(/^\s+- cron:/m);
    expect(triggers[1]).toMatch(/^\s+workflow_dispatch:/m);
  });

  it('actually runs the benchmarks', () => {
    // The upload is asserted below, and an upload step is not a measurement. A
    // workflow that schedules, checks out, installs and uploads — but never
    // invokes the task — satisfies every other case in this file, finds no
    // files, and WARNS rather than failing, because `if-no-files-found: warn` is
    // part of what keeps this job advisory. The Actions UI shows a green nightly
    // run either way, and the trend simply stops gaining points.
    // `\b` rather than an end anchor: `pnpm bench --filter …` is a legitimate
    // narrowing and must not redden the build, while `echo skipped` still fails.
    const step = /^(\s+)run:\s*pnpm(?: run)? bench\b.*$/m.exec(workflow);
    expect(step, `${WORKFLOW_REL} never invokes the bench task`).not.toBeNull();

    // A matched step is not a step that RUNS. `if:` on it satisfies the match
    // above while skipping the task on every trigger, which is the same silent
    // green arrived at one line lower down.
    const stepBlock = workflow.slice(workflow.lastIndexOf('- name:', step.index), step.index);
    expect(stepBlock, `the \`pnpm bench\` step is gated by an \`if:\` condition`).not.toMatch(
      /^\s+if:/m,
    );

    // …and that the command is real. A workflow calling a script the root
    // manifest does not declare fails at run time — nightly, unattended, where
    // the failure is a red square nobody is subscribed to.
    expect(rootScripts()?.bench, 'the root manifest declares no `bench` script').toMatch(
      /turbo run bench/,
    );
  });

  it('uploads its results', () => {
    // A benchmark whose numbers are not kept measures nothing over time, which
    // is the only thing this job is for.
    expect(workflow).toContain('actions/upload-artifact');
    expect(workflow).toMatch(/retention-days:\s*\d+/);
  });

  it('is not listed as a check that gates main', () => {
    // required-checks.test.js drives the CONTRIBUTING.md table forwards — every
    // name in it must still belong to a real job. It cannot see the other
    // direction, so nothing there would notice this workflow being added to the
    // table and made required.
    const contributing = readFileSync(join(REPO_ROOT, 'CONTRIBUTING.md'), 'utf8');
    const section = /### Checks that gate `main`([\s\S]*?)```bash/.exec(contributing);
    expect(section, 'could not find the required-check table').not.toBeNull();
    expect(section[1]).not.toContain('bench.yml');
  });
});

describe('benchmarks run behind the no-network guard', () => {
  // Benchmarks execute product code, so the runtime half of the no-network
  // guarantee has to reach them. It does, and by construction: `vitest bench`
  // resolves the same `vitest.config.ts` as `vitest run`, whose `setupFiles`
  // entry no-network-runtime.test.js already asserts for every package. Both
  // halves of the guard were confirmed live in bench mode — the throw on a
  // non-loopback connect, and the `afterAll` backstop that fails a run where a
  // refusal was swallowed.
  //
  // What that argument rests on is the script not steering vitest somewhere
  // else. `--config` / `-c` / `--root` each point it at a different resolution,
  // and a bench-only config that forgot `setupFiles` would run product code
  // with no runtime guard at all while every existing assertion stayed green,
  // because they all read the config the TEST script uses.
  const STEERING = ['--config', '-c', '--root', '--project', '--workspace'];

  it('runs vitest against each package’s own config', () => {
    const steered = [];
    for (const p of PACKAGES) {
      if (p.benchScript === '') continue;
      const args = p.benchScript.split(/\s+/);
      const flag = args.find((a) => STEERING.some((s) => a === s || a.startsWith(`${s}=`)));
      if (flag !== undefined) steered.push(`${p.name}: ${p.benchScript} (steered by ${flag})`);
    }
    expect(
      steered,
      'A bench script pointing vitest at another config resolves another `setupFiles`, and a ' +
        'bench-only config missing the no-network guard would run product code unguarded while ' +
        `every existing assertion stayed green:\n  ${steered.join('\n  ')}`,
    ).toEqual([]);
  });

  it('runs vitest at all, so the case above is not vacuous', () => {
    // A `bench` script that shelled out to something other than vitest would
    // carry none of these flags and pass the case above perfectly.
    const notVitest = PACKAGES.filter(
      (p) => p.benchScript !== '' && !/(^|\s)vitest\s+bench(\s|$)/.test(p.benchScript),
    ).map((p) => `${p.name}: ${p.benchScript}`);
    expect(notVitest).toEqual([]);
  });
});
