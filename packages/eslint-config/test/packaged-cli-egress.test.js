import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import { jobBlock } from './helpers/workflow.js';

// The PACKAGED-ARTIFACT half of the no-network guarantee.
//
// The three gates the sibling suites cover all observe either source text or an
// executed call: lint reads workspace source, the vitest guard patches
// transports inside a worker, and the CI namespace job reaches whatever the
// SUITE runs. A published tarball is none of those — it is a build output no
// lint pass targets, nothing loads it into a worker, and the suite never
// installs it. `tools/ci/packaged-cli-egress.sh` closes that by installing the
// packed tarball and exercising it inside the namespace.
//
// Its value is in refusing to run vacuously, in two directions rather than one.
// Its wrapper proves the block is real before it starts; what THIS file pins is
// the control the script owns — a scan that examined nothing exits 0 and reports
// no findings, which is byte-for-byte the shape of a clean run. Delete that
// check and the leg goes green having installed the tarball and established
// nothing about it, which is worse than not having the leg at all: it is a green
// tick read as coverage.
//
// The script is driven here with a PATH of hand-written stubs, so every refusal
// is produced on demand with no tarball, no namespace and no real network.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');

const SCRIPT_REL = 'tools/ci/packaged-cli-egress.sh';
const SCRIPT_ABS = join(REPO_ROOT, ...SCRIPT_REL.split('/'));
const WRAPPER_REL = 'tools/ci/no-network-test.sh';
const FIXTURE_REL = 'rules/secrets/fixtures/aws-access-key.json';
const FIXTURE_ABS = join(REPO_ROOT, ...FIXTURE_REL.split('/'));
const RULE_ID = 'secrets/aws-access-key';

const BASH = '/bin/bash';
const CI_YML = join(REPO_ROOT, '.github', 'workflows', 'ci.yml');

/** The positive example the script seeds its scan with, read the way the script reads it. */
function seedText() {
  const examples = JSON.parse(readFileSync(FIXTURE_ABS, 'utf8'));
  const hit = examples.find((e) => e.shouldMatch === true);
  expect(hit, `${FIXTURE_REL} carries no positive example`).toBeDefined();
  return hit.text;
}

// --- 1. The seed is derived from the rule, not written out -------------------

// The script builds its seeded file from this fixture rather than from a literal
// so the two cannot drift: a hand-written value the rule stopped matching makes
// the scan report nothing, which is indistinguishable from a clean scan. It is
// also why no secret-shaped literal is written into this public tree.
describe('the seeded value comes from the rule the leg asserts on', () => {
  it('names a fixture that exists and carries a positive example', () => {
    expect(existsSync(FIXTURE_ABS), `${FIXTURE_REL} is missing`).toBe(true);
    expect(seedText().length).toBeGreaterThan(0);
  });

  it('is the rule the script asserts fired', () => {
    const script = readFileSync(SCRIPT_ABS, 'utf8');
    expect(script).toContain(FIXTURE_REL);
    expect(script).toContain(RULE_ID);
  });
});

// --- 2. CI wiring ------------------------------------------------------------

/**
 * The packaged-artifact job's body from ci.yml.
 *
 * Shared with required-checks.test.js rather than re-rolled: that helper escapes
 * the key, strips comments line by line, and — the part that matters here —
 * asserts the captured text really is a job body. Every assertion below it is an
 * ABSENCE check, and an absence check passes on a block that captured nothing.
 */
const packagedJob = () => jobBlock(readFileSync(CI_YML, 'utf8'), 'packaged-artifact');

describe('the packaged-artifact leg in ci.yml', () => {
  it('runs the script under the namespace wrapper rather than bare', () => {
    // Bare, the script installs and exercises the artifact with a full route off
    // the host — every assertion inside it still passes, and the one property
    // the leg exists to establish is the one nothing checks.
    expect(packagedJob()).toContain(`${WRAPPER_REL} ${SCRIPT_REL}`);
  });

  it('packs the tarball and resolves its published graph before the block', () => {
    // The install under test happens inside the namespace, so the graph has to
    // reach npm's cache before then — and `node_modules` has to be gone again,
    // or `npm ci` inside has nothing left to do and the leg exercises an install
    // that already happened with the network up.
    const block = packagedJob();
    const prepare = block.indexOf('pack --pack-destination');
    const verify = block.indexOf(WRAPPER_REL);
    expect(prepare, 'the job never packs the CLI').toBeGreaterThan(-1);
    expect(verify, 'the job never runs the blocked step').toBeGreaterThan(-1);
    expect(prepare).toBeLessThan(verify);
    expect(block).toMatch(/rm -rf node_modules/);
    // The CLI specifically. Packing a different workspace package produces a
    // tarball, an install and a green leg that exercised the wrong artifact.
    expect(block).toMatch(/--filter @akasecurity\/cli pack/);
  });

  it('hands the blocked step the workdir the prepare step built', () => {
    // The two steps are separate processes, so the path crosses between them
    // through the job environment. Exported under one name and read under
    // another, the script is handed an empty argument and refuses — loudly, but
    // for a reason that reads nothing like the wiring mistake it is.
    const block = packagedJob();
    const exported = /echo "([A-Z_]+)=\$work" >> "\$GITHUB_ENV"/.exec(block);
    expect(exported, 'the prepare step exports no workdir').not.toBeNull();
    expect(block).toContain(`${WRAPPER_REL} ${SCRIPT_REL} "$${exported[1]}"`);
  });

  it('runs on every pull request, not only at release', () => {
    // A privacy gate that fires after the artifact is published is weaker than
    // one that fires before merge. ci.yml triggers on pull_request; a condition
    // here could still take this job out of a PR run.
    expect(packagedJob()).not.toMatch(/^ {4}if:/m);
  });

  it('is uncached, so the artifact is built from this commit', () => {
    // The same reasoning the no-network job carries one step up: a restore key
    // falls back to an earlier commit's entry, and turbo would hand back a build
    // belonging to a tree this run never saw. Paired with the wrapper match,
    // because an absence assertion passes on a block that captured nothing.
    const block = packagedJob();
    expect(block).toContain(SCRIPT_REL);
    expect(block).not.toMatch(/uses: actions\/cache/);
  });
});

// The script refuses unless the wrapper's phase marker is set, and that marker is
// the WRAPPER's internal flag rather than anything this file owns. The harness
// below sets it by hand, so nothing else here would notice the wrapper renaming
// it — and the failure that produces is a leg refusing on every PR with a
// message insisting it be run exactly the way it already was.
describe('the marker the script demands is the one the wrapper sets', () => {
  it('is set by no-network-test.sh before it hands over', () => {
    const wrapper = readFileSync(join(REPO_ROOT, ...WRAPPER_REL.split('/')), 'utf8');
    const demanded = /"\$\{(AKA_[A-Z_]+):-\}" != "1"/.exec(readFileSync(SCRIPT_ABS, 'utf8'));
    expect(demanded, 'the script demands no phase marker').not.toBeNull();
    expect(wrapper).toContain(`${demanded[1]}=1`);
  });
});

// --- 3. The script itself, driven through every refusal ----------------------

/**
 * Skip where the harness cannot run rather than passing vacuously. Asserted
 * before the platform test, so a miswired case fails everywhere rather than only
 * on the platform that reaches the skip.
 * @param {import('vitest').TestContext} ctx
 */
function requirePosixShell(ctx) {
  if (typeof ctx?.skip !== 'function') {
    throw new TypeError(
      'requirePosixShell needs a vitest TestContext to skip with, and was given none. Declare ' +
        'the case with `it` or `it.for`; `it.each` does not pass one.',
    );
  }
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the script is the Linux CI leg's mechanism`);
  }
}

/** Where the aka stub records its argv, inside the work dir the caller gets back. */
const ARGV_LOG = 'aka-argv.log';

const GOOD_REPORT = JSON.stringify({
  target: '/seed',
  scanned: 1,
  findings: [{ ruleId: RULE_ID, severity: 'critical', maskedMatch: 'A******E' }],
});

/**
 * An npm stub that installs a tree: `aka` from `payload`, and `server.js` copied
 * from `serverFile` (null for a tarball that ships no dashboard).
 *
 * Both files are COPIED rather than interpolated into the stub's text. A snippet
 * carrying an apostrophe — `console.log('up')` is the obvious next fixture —
 * would close the shell quote it was embedded in and produce a stub that fails
 * with a syntax error pointing at the harness rather than at the property.
 */
const npmStub = (payload, serverFile) =>
  '#!/bin/sh\n' +
  '[ "$1" = "ci" ] || exit 0\n' +
  'mkdir -p node_modules/.bin node_modules/@akasecurity/cli/web-ui/web-ui\n' +
  `cp "${payload}" node_modules/.bin/aka\n` +
  'chmod +x node_modules/.bin/aka\n' +
  (serverFile === null
    ? ''
    : `cp "${serverFile}" node_modules/@akasecurity/cli/web-ui/web-ui/server.js\n`) +
  'exit 0\n';

// Stays alive, so a poll that fails is measuring the poll rather than a server
// that had already exited.
const LIVE_SERVER = 'setInterval(function () {}, 1000);';
// Exits at once, which is how the "never came up" branch is reached without
// waiting out the script's full retry window.
const DEAD_SERVER = 'process.exit(1);';

// The coreutils the script genuinely shells out to. PATH is built from stubs
// alone, so without these the run dies at the first `mkdir` with a 127 that reads
// like any other failure. They are symlinked into their OWN directory rather than
// borrowed by putting `/usr/bin` on PATH: that directory also holds a real `curl`
// on most hosts, which would quietly make the "curl is missing" case unreachable
// while still reporting green.
const SYSTEM_TOOLS = ['mkdir', 'rm', 'cat', 'cp', 'chmod', 'sleep'];

let systemToolsDir = null;

/** A directory holding a link to each tool in SYSTEM_TOOLS, and nothing else. */
function systemTools() {
  if (systemToolsDir !== null) return systemToolsDir;
  const dir = mkdtempSync(join(tmpdir(), 'aka-packaged-sys-'));
  for (const tool of SYSTEM_TOOLS) {
    const found = spawnSync('/bin/sh', ['-c', `command -v ${tool}`], { encoding: 'utf8' });
    const target = (found.stdout ?? '').trim();
    // Loud rather than skipped: a missing link makes every case below fail with a
    // 127 that says nothing about which tool went missing.
    expect(target, `${tool} is not on this host's PATH, so the harness cannot run`).toBeTruthy();
    symlinkSync(target, join(dir, tool));
  }
  systemToolsDir = dir;
  return dir;
}

// Memoised for the file's lifetime, so it is removed once at the end rather than
// per case. Without this every run of this file leaves an `aka-packaged-sys-*`
// directory behind, on a temp volume CI shares between jobs.
afterAll(() => {
  if (systemToolsDir !== null) {
    rmSync(systemToolsDir, { recursive: true, force: true });
    systemToolsDir = null;
  }
});

/**
 * Drive the script with a PATH built from `stubs` alone.
 *
 * `node` is a stub too — a shim execing this process's own binary — rather than
 * the real one reached through its own directory. That directory also holds
 * `npm`, so inheriting it would make the "npm is missing" case unreachable while
 * still reporting green.
 *
 * The work dir is handed back rather than removed, so a caller can read what the
 * run left behind; every caller removes it.
 *
 * @param {{ stubs?: Record<string, string>, drop?: string[], report?: string,
 *           args?: string[] | null, scriptDir?: string | null, server?: string | null,
 *           initStatus?: number, scanStatus?: number, withLock?: boolean,
 *           underWrapper?: boolean }} options
 */
function runScript({
  stubs = {},
  drop = [],
  report = GOOD_REPORT,
  args = null,
  scriptDir = null,
  server = LIVE_SERVER,
  initStatus = 0,
  scanStatus = 0,
  withLock = true,
  underWrapper = true,
} = {}) {
  const binDir = mkdtempSync(join(tmpdir(), 'aka-packaged-stub-'));
  const work = mkdtempSync(join(tmpdir(), 'aka-packaged-work-'));
  try {
    writeFileSync(join(work, 'package.json'), '{"name":"verify","version":"1.0.0"}\n');
    if (withLock) writeFileSync(join(work, 'package-lock.json'), '{"lockfileVersion":3}\n');
    const reportFile = join(binDir, 'report.json');
    writeFileSync(reportFile, report);

    // The bin the script resolves out of the INSTALLED tree, not off PATH — so
    // the npm stub copies it into place exactly as a real install would.
    const payload = join(binDir, 'aka-payload');
    writeFileSync(
      payload,
      '#!/bin/sh\n' +
        // Records the argv before doing anything else, so a case can assert what
        // each command was POINTED AT rather than only that it was run. Tabs
        // rather than spaces: a temp path carrying a space would otherwise split
        // into two arguments on the way back out.
        "{ printf 'CALL'; for a in \"$@\"; do printf '\\t%s' \"$a\"; done; printf '\\n'; } " +
        '>> "$AKA_ARGV_LOG"\n' +
        'case "$1" in\n' +
        '  init) exit "${FAKE_INIT_STATUS:-0}" ;;\n' +
        '  scan) cat "$FAKE_REPORT"; exit "${FAKE_SCAN_STATUS:-0}" ;;\n' +
        'esac\n' +
        'exit 0\n',
    );
    chmodSync(payload, 0o755);

    let serverFile = null;
    if (server !== null) {
      serverFile = join(binDir, 'server-payload.js');
      writeFileSync(serverFile, server);
    }

    const all = {
      node: `#!/bin/sh\nexec ${process.execPath} "$@"\n`,
      curl: '#!/bin/sh\nexit 0\n',
      npm: npmStub(payload, serverFile),
      ...stubs,
    };
    for (const name of drop) delete all[name];

    for (const [name, body] of Object.entries(all)) {
      const file = join(binDir, name);
      writeFileSync(file, body);
      chmodSync(file, 0o755);
    }

    // scriptDir relocates the script so its `${0%/*}/../..` no longer reaches the
    // repo, which is how the missing-fixture branch is produced.
    let script = SCRIPT_ABS;
    if (scriptDir !== null) {
      script = join(scriptDir, 'packaged-cli-egress.sh');
      writeFileSync(script, readFileSync(SCRIPT_ABS, 'utf8'));
      chmodSync(script, 0o755);
    }

    const result = spawnSync(BASH, [script, ...(args ?? [work])], {
      encoding: 'utf8',
      env: {
        PATH: binDir + delimiter + systemTools(),
        HOME: binDir,
        FAKE_REPORT: reportFile,
        FAKE_INIT_STATUS: String(initStatus),
        FAKE_SCAN_STATUS: String(scanStatus),
        AKA_ARGV_LOG: join(work, ARGV_LOG),
        // The wrapper's own phase marker. Every case but one runs as if
        // `no-network-test.sh` had handed over, because that is the only way the
        // script is ever meant to be reached.
        ...(underWrapper ? { AKA_NO_NETWORK_INSIDE: '1' } : {}),
      },
    });
    return {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      work,
    };
  } catch (err) {
    // `work` is normally the caller's to remove, because the caller reads what
    // the run left in it. On a throw there is no caller to hand it to — the
    // `expect` inside systemTools and a failing write both land here — so it
    // would leak, with whatever a partial run installed under it.
    rmSync(work, { recursive: true, force: true });
    throw err;
  } finally {
    rmSync(binDir, { recursive: true, force: true });
  }
}

/** `runScript`, with the work dir removed for the callers that do not read it. */
function run(options) {
  const result = runScript(options);
  rmSync(result.work, { recursive: true, force: true });
  return result;
}

const DONE = 'installs, scans and serves the dashboard with egress blocked';

// Every case below spawns a real shell and up to three node processes, so what
// it costs is dominated by process startup under whatever else the runner is
// doing — not by the property being asserted. This package deliberately sets no
// package-wide override (its vitest.config.ts says why: the default has to stay
// tight for the ~1,300 assertions here that run in under a millisecond), so the
// budget is spelled on the work that needs it instead.
//
// It is loose on purpose and measures nothing. A ceiling wide enough to survive
// an oversubscribed runner can only separate "this stopped terminating" from
// "this got slower", and the second is not a defect worth a red PR. Measured
// standalone at ~400ms a case and ~1s for the green path; observed past 12s
// under a full-package run on a contended machine.
// It also has to clear the SCRIPT's own retry window, which is the tighter of the
// two constraints: the dashboard poll sleeps 2s up to 30 times before reporting
// failure, so a case that exercises that path can legitimately take ~60s. At a
// 60s budget vitest wins that race and a correct refusal is reported as a
// timeout — a hang, rather than the passing assertion it actually is.
const SUBPROCESS_TIMEOUT_MS = 120_000;

describe(
  'the packaged-artifact script refuses to run vacuously',
  { timeout: SUBPROCESS_TIMEOUT_MS },
  () => {
    it('runs clean when the artifact behaves', (ctx) => {
      requirePosixShell(ctx);
      // The positive control for this whole block. Every case below asserts a
      // refusal, and a script that refused unconditionally would satisfy all of
      // them while never exercising the artifact at all.
      const result = run();
      expect(result.status).toBe(0);
      expect(result.stdout).toContain(DONE);
    });

    it('seeds the scan from the rule fixture', (ctx) => {
      requirePosixShell(ctx);
      // Read back what the run actually wrote. A script that seeded an empty file —
      // or one the rule cannot match — still reaches the control below and reports
      // "no findings", which reads exactly like a clean scan.
      const result = runScript();
      try {
        const file = join(result.work, 'seed', 'credentials.txt');
        expect(existsSync(file), 'the script wrote no seed file').toBe(true);
        expect(readFileSync(file, 'utf8')).toContain(seedText());
      } finally {
        rmSync(result.work, { recursive: true, force: true });
      }
    });

    it('points init and scan at the seeded directory, under one home', (ctx) => {
      requirePosixShell(ctx);
      // The seed case above proves the file was WRITTEN from the rule fixture. It
      // says nothing about what the scan was aimed at, and a scan pointed anywhere
      // else reports no findings — which is the same bytes as a clean scan, so it
      // would satisfy every other case here while establishing nothing about the
      // packaged artifact.
      const result = runScript();
      try {
        const log = readFileSync(join(result.work, ARGV_LOG), 'utf8');
        const calls = log
          .split('\n')
          .filter((line) => line.startsWith('CALL\t'))
          .map((line) => line.split('\t').slice(1));
        const init = calls.find(([verb]) => verb === 'init');
        const scan = calls.find(([verb]) => verb === 'scan');
        expect(init, 'aka init was never invoked').toBeDefined();
        expect(scan, 'aka scan was never invoked').toBeDefined();

        const home = join(result.work, 'home');
        expect(init).toContain('--home');
        expect(init[init.indexOf('--home') + 1]).toBe(home);

        // The TARGET is the first argument after the verb, and it has to be the
        // seeded directory rather than the home or the work dir.
        expect(scan[1]).toBe(join(result.work, 'seed'));
        expect(scan[scan.indexOf('--home') + 1]).toBe(home);
        expect(scan).toContain('--format');
        expect(scan[scan.indexOf('--format') + 1]).toBe('json');
      } finally {
        rmSync(result.work, { recursive: true, force: true });
      }
    });

    it('refuses to run outside the namespace wrapper', (ctx) => {
      requirePosixShell(ctx);
      // Run bare, every other case in this block still passes — with a full route
      // off the host — and the script's closing line claims egress was blocked
      // anyway. It does not verify that itself (the wrapper does, with two probes),
      // so it refuses to make the claim rather than making it on trust.
      const result = run({ underWrapper: false });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain('no-network-test.sh');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses with no workdir', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ args: [] });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain('usage:');
      expect(result.stdout).not.toContain(DONE);
    });

    // `it.for`, not `it.each`: only `for` passes the TestContext these skip through.
    it.for(['node', 'npm', 'curl'])('refuses when the tool %s is missing', (missing, ctx) => {
      requirePosixShell(ctx);
      // A step whose own tool is absent fails in a way that reads like the thing it
      // was checking — no `npm` looks like a broken artifact, no `curl` like a
      // dashboard that never came up — so each is named before anything runs.
      const result = run({ drop: [missing] });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`'${missing}' is not installed`);
      expect(result.stdout).not.toContain(DONE);
    });

    it.for([
      ['an empty workdir argument', ''],
      ['a workdir that does not exist', '/no-such-aka-packaged-workdir'],
    ])('refuses %s before deriving any path from it', ([, arg], ctx) => {
      requirePosixShell(ctx);
      // Everything below builds `$work/...`, and one of those lines is an
      // `rm -rf`. An empty argument still satisfies `$# -eq 1`, so it reaches that
      // line with the targets resolved to `/home`, `/seed` and `/scan.json`.
      //
      // The MESSAGE is the assertion, not the status: the lockfile check further
      // down also exits 2, and on an empty argument it is looking at
      // `/package.json` — so a run that reports its refusal in those words has
      // already got past the point this guard exists to stop it at.
      const result = run({ args: [arg] });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain('is not a directory');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the prepare step left no lockfile', (ctx) => {
      requirePosixShell(ctx);
      // Without it `npm ci` has nothing to install from, and an install that did
      // nothing leaves an empty tree the checks below would misread.
      const result = run({ withLock: false });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain('package-lock.json is missing');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the rule fixture cannot be found', (ctx) => {
      requirePosixShell(ctx);
      const elsewhere = mkdtempSync(join(tmpdir(), 'aka-packaged-relocated-'));
      try {
        const result = run({ scriptDir: elsewhere });
        expect(result.status).toBe(1);
        expect(result.stderr).toContain('rule fixture is missing');
        expect(result.stdout).not.toContain(DONE);
      } finally {
        rmSync(elsewhere, { recursive: true, force: true });
      }
    });

    it('refuses when installing the tarball needed the network', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ stubs: { npm: '#!/bin/sh\nexit 1\n' } });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('needed the network');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the installed tarball ships no aka bin', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ stubs: { npm: '#!/bin/sh\nexit 0\n' } });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('aka bin is missing');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when aka init fails under the block', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ initStatus: 1 });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("'aka init' did not succeed");
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when aka scan fails under the block', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ scanStatus: 1 });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("'aka scan' did not succeed");
      expect(result.stdout).not.toContain(DONE);
    });

    // THE control this file exists for. A scan that walked nothing exits 0 and
    // reports no findings, which is the same bytes a clean scan produces — so "no
    // findings" has to be a failure here rather than a pass.
    it.for([
      ['nothing at all', JSON.stringify({ findings: [] })],
      ['only some other rule', JSON.stringify({ findings: [{ ruleId: 'secrets/other' }] })],
      ['no findings key at all', JSON.stringify({ scanned: 0 })],
    ])('refuses when the packaged scan reported %s', ([, report], ctx) => {
      requirePosixShell(ctx);
      const result = run({ report });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(RULE_ID);
      expect(result.stderr).toContain('proved nothing');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the scan report is not JSON', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ report: 'not json at all' });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('not JSON');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the scan report echoes the raw seeded value', (ctx) => {
      requirePosixShell(ctx);
      // Findings carry the masked value and never the raw one. The packaged build
      // is the copy of that promise nothing else in this repository exercises.
      const result = run({
        report: JSON.stringify({ findings: [{ ruleId: RULE_ID, rawMatch: seedText() }] }),
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('echoed the raw seeded value');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the scan report echoes only PART of the raw seeded value', (ctx) => {
      requirePosixShell(ctx);
      // The run-by-run form is what makes the check above worth having. A branch
      // that interpolated a truncated value has still disclosed a live secret's
      // prefix, and a whole-value `includes` stays green on exactly that.
      // Sliced out of the SECRET, not out of the seeded line. The script windows
      // over the high-entropy run for the reason its own comment gives — an
      // eight-character window over `const key = "` collides with ordinary
      // output — so a partial taken from the code prefix is not what it guards.
      const secret = /[A-Za-z0-9_\-+/=]{16,}/.exec(seedText());
      expect(secret, 'the fixture carries no high-entropy run to truncate').not.toBeNull();
      const partial = secret[0].slice(0, 12);
      expect(partial.length).toBeGreaterThan(8);
      const result = run({
        report: JSON.stringify({ findings: [{ ruleId: RULE_ID, hint: partial }] }),
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('echoed the raw seeded value');
      expect(result.stdout).not.toContain(DONE);
    });

    it('does not fail on ordinary code text from the seeded line', (ctx) => {
      requirePosixShell(ctx);
      // The other side of the echo check, and the reason it windows over the
      // secret rather than over the whole seeded line. `const key = ` is code, not
      // a credential; windowed over the full fixture it matches, and the leg goes
      // red reporting a leak that did not happen — the flavour of false alarm
      // people learn to re-run until it is green.
      const prefix = seedText().slice(0, 12);
      expect(prefix).not.toMatch(/[A-Za-z0-9_\-+/=]{16,}/);
      const result = run({
        report: JSON.stringify({ findings: [{ ruleId: RULE_ID, note: prefix }] }),
      });
      expect(result.stdout).toContain(DONE);
      expect(result.status).toBe(0);
    });

    it('refuses when the tarball ships no bundled dashboard', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ server: null });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('bundled standalone server is missing');
      expect(result.stdout).not.toContain(DONE);
    });

    it('refuses when the bundled dashboard never comes up', (ctx) => {
      requirePosixShell(ctx);
      const result = run({ server: DEAD_SERVER, stubs: { curl: '#!/bin/sh\nexit 7\n' } });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('did not serve /security');
      expect(result.stdout).not.toContain(DONE);
    });
  },
);
