import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  publishCommands,
  publishCommandsByWorkflow,
  publishSteps,
} from './helpers/release-workflows.js';

// Which npm dist-tag a release publishes under is decided by a `case` block
// inside each publish step's `run:`, and it is the one piece of release logic a
// mistake in is invisible until after the publish has happened: a beta that
// lands on `latest` is served to every `npm install -g` on earth, and moving a
// dist-tag back does not un-install it.
//
// So the guard EXECUTES the shell rather than reading it. A token check would
// pass on `*-*) dist_tag="beta"` — right words, wrong arm — and would fail on a
// correct block spelled differently, which is how a formatting rule ends up
// deciding a release. Running it asks the only question that matters: given
// this version, which tag does this step publish under?
//
// Order is part of the answer, and it is the part a reader cannot see. `case`
// takes the FIRST matching pattern, so a `*-*` arm placed above `*-beta.*`
// silently swallows every beta into `rc` while every pattern and every tag name
// in the block is still correct. Only execution separates those two files.
const STEPS = publishSteps();
const RAW = publishCommandsByWorkflow();

// Seven today: one CLI publish, plus an npm and a GitHub Packages publish for
// each of the three plugins. Asserted as a FLOOR because a fourth plugin would
// add two more, and asserted at all because every case below is per-step — with
// no steps found, an empty loop reports green.
//
// A floor alone stops being a non-vacuity check the day a fifth workflow lands:
// nine invocations clear a floor of seven while two of them are attributed to
// nothing. So the floor sits beside an EQUALITY against the same invocations
// counted over the raw text, which pins whatever the current number happens to
// be without anybody maintaining it.
const MIN_PUBLISH_STEPS = 7;

describe('a commented-out publish does not count as one', () => {
  // Measured against the un-fixed `PUBLISH` regex: it carries no notion of `#`,
  // so a remark that merely mentions a publish materializes as one and is
  // routed under a `case` block exactly like the real thing, while the
  // workflow itself runs nothing.
  const COMMENTED = '      # pnpm --filter @akasecurity/plugin-codex publish --tag $DIST_TAG';
  const LIVE = '      pnpm --filter @akasecurity/plugin-codex publish --tag $DIST_TAG';

  it('is not returned by publishCommands', () => {
    expect(publishCommands(COMMENTED)).toEqual([]);
  });

  it('is still returned live, at the same indentation (positive control)', () => {
    expect(publishCommands(LIVE)).toEqual([LIVE.trim()]);
  });
});

/**
 * A version and the dist-tag its publish must choose.
 *
 * `0.9.0-rc1` and `1.0.0-rc.2` are both here on purpose: one carries no dot
 * after the identifier and one does, and `rc` is the RESIDUAL arm rather than a
 * pattern of its own, so both have to reach it by falling through the two named
 * channels. They are also what keeps the refinement backwards-compatible — an
 * arm that stopped matching either would change what today's prereleases
 * publish under.
 */
const SAMPLES = Object.freeze({
  '0.9.12': 'latest',
  '0.10.0-beta.1': 'beta',
  '0.10.0-nightly.20260918.gabc1234': 'nightly',
  '0.9.0-rc1': 'rc',
  '1.0.0-rc.2': 'rc',
});

const BASH = '/bin/bash';

/**
 * Skip on a host that cannot run the extracted shell.
 *
 * A skip rather than a bare return: a returning body is a PASSING body, so on
 * Windows every case here would report as covered while asserting nothing.
 * @param {{ skip: (note?: string) => void }} ctx
 */
function requirePosixShell(ctx) {
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the extracted block is POSIX shell, as GitHub runs it`);
  }
}

/**
 * The environment the extracted shell runs under: an empty PATH, plus the one
 * variable the block reads.
 *
 * PATH bound to the EMPTY STRING, and the shell itself named by absolute path.
 * Omitting the key does NOT give the script an empty search path: bash falls
 * back to a compiled-in default when PATH is unset, and that default includes
 * the WORKING DIRECTORY — measured here as
 * `/usr/gnu/bin:/usr/local/bin:/bin:/usr/bin:.`. Bound empty, no external
 * command resolves and the block runs on builtins alone.
 *
 * Read that as HYGIENE and not as a sandbox. The extracted block is repository
 * text this suite already trusts to run; what the empty environment buys is
 * that the routing cannot come out differently because of what happens to be
 * installed on the machine running the suite, or of what sits in the directory
 * it runs from. It confines nothing — a block that called `rm` would still be
 * a block this repository contains.
 *
 * One function rather than an object literal per call site, so the case below
 * pins the PATH this really hands the shell rather than one it built itself.
 * @param {string} subject the shell variable the `case` switches on
 * @param {string} value the version to bind to it
 */
const shellEnv = (subject, value) => ({ PATH: '', [subject]: value });

/**
 * The dist-tag one publish step's own `case` block chooses for `version`.
 *
 * The version is bound through the ENVIRONMENT and never written into the
 * script. Interpolating it would put the test's own fixture inside the shell
 * under test, so a sample carrying a quote or a `$` would be testing the
 * harness; bound as an environment variable it reaches the `case` as data, the
 * way the workflow's own `node -p` output does.
 *
 * The two identifiers that ARE interpolated are the variable names the helper
 * read out of the workflow, and it only ever returns `[A-Za-z_][A-Za-z0-9_]*`
 * — a shell name, with nothing in it a shell re-reads.
 * @param {import('./helpers/release-workflows.js').PublishStep} step
 * @param {string} version
 */
function routeOf(step, version) {
  // Asserted rather than assumed: with no block there is no script, and handing
  // bash the word `undefined` fails as `command not found` — a real failure, but
  // one whose message says nothing about the release. The unrouted-steps case
  // below is what a reader should act on, so this one says the same thing.
  //
  // All three, because each is a different missing half and only the block being
  // absent fails loudly on its own: an unnamed subject binds the version to the
  // variable `undefined`, and an unnamed tag variable prints an empty string —
  // both then surface as a routing mismatch against whichever sample ran first,
  // which names the wrong defect.
  expect(
    [step.caseBlock, step.caseSubject, step.tagVariable].every((part) => part !== undefined),
    `${step.workflow} :: ${step.name} has no dist-tag \`case\` block this guard can run: ` +
      `block ${step.caseBlock === undefined ? 'missing' : 'found'}, version variable ` +
      `${step.caseSubject ?? 'unnamed'}, tag variable ${step.tagVariable ?? 'unnamed'}`,
  ).toBe(true);
  const script = `${step.caseBlock}\nprintf '%s' "\${${step.tagVariable}-}"`;
  return execFileSync(BASH, ['-c', script], {
    encoding: 'utf8',
    env: shellEnv(step.caseSubject, version),
    timeout: 30_000,
  });
}

describe('every release publish routes a version to a dist-tag', () => {
  it('runs the extracted blocks on builtins alone, with no reachable PATH', (ctx) => {
    requirePosixShell(ctx);
    // The environment `routeOf` really hands the shell, not one built here: a
    // control over its own literal would go on passing after `PATH: ''` was
    // dropped from the call site it describes.
    const env = shellEnv('AKA_ROUTE_PROBE', '1.2.3');
    const under = (script) =>
      execFileSync(BASH, ['-c', script], { encoding: 'utf8', env, timeout: 30_000 }).trim();

    // Bound, and bound EMPTY — an absent key is what leaves bash's compiled-in
    // fallback search path in force, `.` and all.
    expect(env.PATH, 'the extracted shell is handed a PATH it can resolve tools through').toBe('');

    // And what that leaves reachable, in both directions. A builtin — which is
    // all a routing `case` and the `printf` reading its answer need — still
    // runs; nothing installed on the machine does. Without the second half an
    // `env` key misspelled `Path` would satisfy every routing case here.
    expect(under('printf ok')).toBe('ok');
    expect(under('case "$AKA_ROUTE_PROBE" in *-*) printf rc ;; *) printf latest ;; esac')).toBe(
      'latest',
    );
    expect(() => under('uname -s')).toThrow();
  });

  it('finds every publish step, each with the shell that tags it', () => {
    const raw = RAW.reduce((total, w) => total + w.commands.length, 0);
    expect(
      raw,
      'the release workflows carry fewer publish invocations than exist, so every per-step case ' +
        'below is asserting nothing',
    ).toBeGreaterThanOrEqual(MIN_PUBLISH_STEPS);
    expect(
      STEPS.length,
      `${raw} publish invocations sit in the release workflows and ${STEPS.length} were ` +
        'attributed to a step. Fewer means a publish no case below routes; more means the step ' +
        'walk overlaps and one publish is being routed twice under two names:\n  ' +
        RAW.map((w) => `${w.workflow}: ${w.commands.length}`).join('\n  '),
    ).toBe(raw);

    // A publish whose tag is not decided by a `case` at all — the block deleted,
    // its `--tag` argument no longer a variable, or two blocks assigning the same
    // variable so which one feeds the publish is ambiguous. Every routing case
    // below reads `step.caseBlock`, and an undefined block makes a shell script
    // out of the word `undefined`, so this is what turns that into one named
    // failure instead of a confusing shell error per sample.
    const unrouted = STEPS.filter(
      (s) =>
        s.caseBlock === undefined || s.tagVariable === undefined || s.caseSubject === undefined,
    ).map((s) => `${s.workflow} :: ${s.name || s.command}`);
    expect(
      unrouted,
      'These publish steps do not take their dist-tag from a `case` block this guard can find ' +
        `and run, so nothing below decides which tag they publish under:\n  ${unrouted.join('\n  ')}`,
    ).toEqual([]);
  });

  describe.each(STEPS.map((s) => [`${s.workflow} :: ${s.name || s.packageName}`, s]))(
    '%s',
    (_label, step) => {
      it.for(Object.entries(SAMPLES))('%s publishes under %s', ([version, expected], ctx) => {
        requirePosixShell(ctx);
        expect(routeOf(step, version)).toBe(expected);
      });
    },
  );

  it('routes the same way in every workflow', (ctx) => {
    // A skip rather than a conditional around the body: on a host with no bash
    // the body asserts nothing, and a body that asserts nothing must not report
    // as a pass.
    requirePosixShell(ctx);
    // The refinement had to land in all seven steps, and a partial edit is the
    // likely mistake: one workflow keeping the old two-arm block still publishes
    // a beta under `rc`, and the per-step cases above name it while this names
    // the DISAGREEMENT, which is the thing a reader acts on.
    for (const [version, expected] of Object.entries(SAMPLES)) {
      const disagreeing = STEPS.filter(
        (s) => s.caseBlock !== undefined && routeOf(s, version) !== expected,
      ).map((s) => `${s.workflow} :: ${s.name || s.packageName}`);
      expect(disagreeing, `${version} is routed elsewhere by these steps`).toEqual([]);
    }
  });
});
