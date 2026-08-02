import { execFileSync, spawnSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import dns, { resolve4 as namedResolve4 } from 'node:dns';
import {
  chmodSync,
  existsSync,
  globSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createConnection, createServer, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Linter } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';

import { networkGuard } from '../src/index.js';
import {
  blockedTcpTarget,
  dgramAddress,
  isLoopbackHost,
  takeBlockedAttempts,
} from '../../../test/setup/no-network.ts';

// The RUNTIME half of the no-network guarantee, the companion to no-network.test.js
// (which covers the lint half).
//
// The lint ban stops a network primitive being WRITTEN. It says nothing about
// whether anything DEPENDS on the network at runtime: a transitive dependency, a
// non-literal `import()`, or a host global all reach the wire without tripping a rule.
// test/setup/no-network.ts closes that by refusing the connection itself, and
// every package loads it as a vitest setupFile — including this one, so the
// behavioral cases below exercise the guard that is already installed rather
// than a copy of it.
//
// Five properties are guarded here:
//
//  1. STRUCTURAL — every package that runs tests does so through vitest, wires
//     the guard, and wires a relative path that actually resolves to the one
//     guard file. Thirteen hand-written paths at two different depths is exactly
//     the shape that drifts, and a package that quietly drops the entry — or
//     tests through a runner with no setupFiles at all — would run unguarded
//     with CI green. turbo.json and ci.yml are pinned for the same reason: the
//     guard outside every package's inputs would replay cached greens, and the
//     CI job is the only thing covering child processes.
//
//  2. BEHAVIORAL — the installed guard refuses a real non-loopback connect, UDP
//     datagram and DNS query; allows a real loopback round trip; and NAMES THE
//     CALL SITE. A refusal that is swallowed by a fail-open `catch` is still
//     recorded, which is what the setup file's afterEach/afterAll turn into a
//     failure.
//
//  3. THE CI SCRIPT — driven directly, with a PATH of stubs, through every
//     refusal it can produce plus the one green path. It is the only gate that
//     can see a child process, and its value is entirely in a positive control
//     that refuses to run vacuously; nothing exercising that control leaves it
//     one edit from decorative.
//
//  4. THE EGRESS PROBE — the three exit codes the script branches on, including
//     the one that must never be read as "blocked": the probe reporting that it
//     could not run.
//
//  5. AUDITED OPT-OUTS — the guard imports node:net / node:dgram / node:dns and
//     the probe imports node:net, which the shared ban forbids. That is the
//     enforcement, not a violation of it, but it is only defensible while it
//     stays exactly that: both files are linted here with the raw ban and one
//     more specifier in either fails this suite.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');

const GUARD_REL = 'test/setup/no-network.ts';
const GUARD_ABS = join(REPO_ROOT, ...GUARD_REL.split('/'));
const CI_SCRIPT_REL = 'tools/ci/no-network-test.sh';
const CI_SCRIPT_ABS = join(REPO_ROOT, ...CI_SCRIPT_REL.split('/'));
const PROBE_REL = 'tools/ci/egress-probe.mjs';
const PROBE_ABS = join(REPO_ROOT, ...PROBE_REL.split('/'));
// The two no-network enforcement suites, which live in HERE and reach no other
// ESLint pass than lint:root's `eslint.root.guard.config.mjs` network-only pass.
const NW_SUITE_ABS = join(HERE, 'no-network.test.js');
const NW_RUNTIME_SUITE_ABS = join(HERE, 'no-network-runtime.test.js');

// --- 1. Structural: every vitest package wires the guard ---------------------

/**
 * Strip comments so prose mentioning a path is not mistaken for live wiring.
 * @param {string} source
 */
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * The package globs declared under `packages:` in pnpm-workspace.yaml. Derived
 * rather than hardcoded so a new package cannot fall outside this guard; the
 * pinned expectation below is what catches a parse that silently under-counts.
 * @returns {string[]}
 */
function workspaceGlobs() {
  const raw = readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8').replace(/\r\n/g, '\n');
  const globs = [];
  let inBlock = false;
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.replace(/#.*$/, '');
    if (!inBlock) {
      if (/^packages:[ \t]*$/.test(line)) inBlock = true;
      continue;
    }
    if (/^\S/.test(line)) break; // a new column-0 key ends the block
    const entry = line.match(/^[ \t]+-[ \t]*['"]?([^'"\n]+?)['"]?[ \t]*$/);
    if (entry) globs.push(entry[1].trim());
  }
  return globs;
}

// `setupFiles: [noNetworkGuard]` plus the `new URL('<rel>', import.meta.url)`
// the binding is built from. Both halves matter: the first proves the entry is
// wired, the second is where a wrong `../..` depth would hide.
const SETUP_ENTRY = /setupFiles\s*:\s*\[[^\]]*\bnoNetworkGuard\b[^\]]*\]/;
const GUARD_URL = /new URL\(\s*'([^']*test\/setup\/no-network\.ts)'\s*,\s*import\.meta\.url\s*\)/;

/**
 * Every workspace package that runs tests AT ALL, tagged with whether it does so
 * through vitest and, if it does, how (and whether) its config wires the guard.
 *
 * Enumerating on `test` rather than on `vitest` is the point. Filtering to
 * vitest up front would drop a package that runs `node --test` from BOTH sides
 * of the pinned comparison below — missing from the derived list and missing
 * from the expectation — so it would ship an unguarded suite with this file
 * green. The runner is a property to assert, not a precondition for looking.
 */
function testPackages() {
  const dirs = [
    ...new Set(
      workspaceGlobs()
        .flatMap((g) => globSync(g, { cwd: REPO_ROOT }))
        .filter((rel) => existsSync(join(REPO_ROOT, rel, 'package.json'))),
    ),
  ].sort();

  return dirs
    .map((dir) => {
      const posixDir = dir.split(sep).join('/');
      const pkg = JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));
      return { dir, posixDir, name: pkg.name ?? posixDir, testScript: pkg.scripts?.test ?? '' };
    })
    .filter((p) => p.testScript.trim() !== '')
    .map((p) => {
      const runsVitest = /(^|[\s/])vitest([\s/]|$)/.test(p.testScript);
      const configAbs = join(REPO_ROOT, p.dir, 'vitest.config.ts');
      if (!runsVitest || !existsSync(configAbs)) {
        return { ...p, runsVitest, hasConfig: false, wired: false, resolved: null };
      }
      const source = stripComments(readFileSync(configAbs, 'utf8'));
      const url = GUARD_URL.exec(source);
      return {
        ...p,
        runsVitest,
        hasConfig: true,
        wired: SETUP_ENTRY.test(source),
        resolved: url ? resolve(dirname(configAbs), url[1]) : null,
      };
    });
}

const TEST_PACKAGES = testPackages();
const VITEST_PACKAGES = TEST_PACKAGES.filter((p) => p.runsVitest);

// The exact set expected to run vitest, pinned by name. A derived-vs-derived
// comparison cannot catch a package the enumeration silently dropped, because it
// would be missing from both sides. An exact set fails loudly on any add, drop
// or rename — at which point the new package must either wire the guard or be
// argued out of it in review.
const EXPECTED_VITEST_PACKAGES = [
  '@akasecurity/ai-tc-claude-code',
  '@akasecurity/audit-gate',
  '@akasecurity/cli',
  '@akasecurity/dashboard-ui',
  '@akasecurity/detections',
  '@akasecurity/eslint-config',
  '@akasecurity/extract',
  '@akasecurity/local-ops',
  '@akasecurity/persistence',
  '@akasecurity/plugin-runtime',
  '@akasecurity/plugin-sdk',
  '@akasecurity/scanner',
  '@akasecurity/schema',
  '@akasecurity/web-ui',
];

// Packages that run tests through something other than vitest, and so cannot
// load a vitest setupFile. Keep this EMPTY. Every entry is a suite running with
// no runtime network guard at all, which is a hole in the guarantee and must be
// a deliberate, reviewed decision carrying its reason — the guard would have to
// be re-implemented for that runner, or the package argued out of needing one.
const EXPECTED_NON_VITEST_TEST_PACKAGES = [];

describe('every vitest package loads the no-network guard', () => {
  it('enumerates exactly the packages that run vitest', () => {
    expect(VITEST_PACKAGES.map((p) => p.name).sort()).toEqual([...EXPECTED_VITEST_PACKAGES].sort());
  });

  it('no package runs tests outside vitest without a named exemption', () => {
    // The gap this closes: a package whose `test` script is `node --test` is
    // invisible to a vitest-only enumeration, so it would be absent from the
    // derived list AND from the expectation above and fail nothing, while
    // running every one of its tests with the network wide open.
    const outside = TEST_PACKAGES.filter((p) => !p.runsVitest).map((p) => p.name);
    expect(outside.sort()).toEqual([...EXPECTED_NON_VITEST_TEST_PACKAGES].sort());
  });

  it('the guard file the configs point at exists', () => {
    expect(existsSync(GUARD_ABS)).toBe(true);
  });

  it('each ships a vitest.config.ts', () => {
    const missing = VITEST_PACKAGES.filter((p) => !p.hasConfig).map((p) => p.posixDir);
    expect(missing).toEqual([]);
  });

  it('each names the guard in setupFiles', () => {
    const unwired = VITEST_PACKAGES.filter((p) => p.hasConfig && !p.wired).map((p) => p.posixDir);
    expect(unwired).toEqual([]);
  });

  it('each relative path resolves to the one guard file', () => {
    const wrong = VITEST_PACKAGES.filter((p) => p.hasConfig && p.resolved !== GUARD_ABS).map(
      (p) => `${p.posixDir} -> ${String(p.resolved)}`,
    );
    expect(wrong).toEqual([]);
  });
});

describe('the guard cannot be cached or dropped out of CI', () => {
  it('turbo.json declares test/setup/** as a global dependency', () => {
    // Without this the guard is in no package's task hash, so weakening it would
    // leave every package replaying a cached green produced under the old guard.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    expect(turbo).toMatch(/"globalDependencies"\s*:\s*\[[^\]]*"test\/setup\/\*\*"/);
  });

  it("turbo.json puts ci.yml, the CI script and the repo-root sources in this suite's task inputs", () => {
    // Without these entries the assertions below are self-defeating. They read
    // files that live in no package, so deleting the No-network job leaves this
    // task's hash untouched; turbo replays the cached pass from a prior commit
    // and the assertion guarding the job never executes. The one job that would
    // have re-run it from scratch is the job that was deleted.
    //
    // The repo-root glob is the same hazard for ADDING rather than deleting.
    // effective-config.test.js derives the lintable files that belong to no
    // workspace package and fails when a lint pass covers none of them — but the
    // per-package input globs there all require a directory segment, so a new
    // file at the repo ROOT (the one place a file belongs to no package) leaves
    // this hash untouched and that check never runs against it.
    const turbo = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
    const inputs =
      /"@akasecurity\/eslint-config#test"\s*:\s*\{[\s\S]*?"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(
        turbo,
      );
    expect(inputs).not.toBeNull();
    expect(inputs[1]).toContain('$TURBO_ROOT$/.github/workflows/ci.yml');
    expect(inputs[1]).toContain('$TURBO_ROOT$/tools/ci/**');
    expect(inputs[1]).toContain('$TURBO_ROOT$/*.{ts,tsx,mts,cts,js,jsx,mjs,cjs}');
  });

  it('ci.yml runs the suite through the egress-blocking script', () => {
    // The vitest guard cannot see a child process; this job is what does.
    const ci = readFileSync(join(REPO_ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
    expect(ci).toContain(CI_SCRIPT_REL);
  });

  it('ci.yml runs the repo-root lint and typecheck passes', () => {
    // `turbo run lint`/`turbo run typecheck` drive per-package scripts, and the
    // repo root is not a package — so the guard, the probe, the repo-root configs
    // and the enforcement suites are covered by these two passes and nothing
    // else. Drop a target and those sources go back to being lint- or
    // tsc-covered by nothing.
    const ci = readFileSync(join(REPO_ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
    expect(ci).toContain('pnpm lint:root');
    expect(ci).toContain('pnpm typecheck:root');

    const root = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
    const lintRoot = root.scripts['lint:root'];
    // The workspace-wide scripts CHAIN the root passes, so every caller of them —
    // the pre-push hook, the two release workflows, a contributor before pushing —
    // covers the repo root too rather than reading green while a file there is
    // unlinted or unchecked. Those callers run ONLY these scripts; they never run
    // the CI steps above.
    //
    // Matched as an unconditional `&&` chain rather than as a substring, because
    // the substring is still there in every way of NOT running the pass: `||`
    // runs it only once the workspace pass has already failed, `#` comments it
    // out, and both leave a green run that has skipped the repo root entirely.
    for (const [name, chained] of [
      ['lint', 'lint:root'],
      ['typecheck', 'typecheck:root'],
    ]) {
      expect(
        root.scripts[name],
        `\`pnpm ${name}\` must chain \`${chained}\` with &&, so the pre-push hook and the release ` +
          'workflows cover the repo root',
      ).toMatch(new RegExp(`&&\\s*(?:pnpm|npm)(?:\\s+run)?\\s+${chained}(?:\\s|$)`));
    }
    // The targets below are a readable statement of intent, not the gate. What
    // actually decides whether a repo-root file is linted is the DERIVED
    // non-package check in effective-config.test.js, which reads the same script
    // and names any file no invocation covers. Rewording this script is fine as
    // long as that check stays green — these lines then come along with it.
    expect(lintRoot).toContain('test/setup');
    expect(lintRoot).toContain('tools/ci');
    // The second pass is the ONLY thing that lints the enforcement suites — the
    // eslint-config package's own `lint` is a deliberate no-op — and it hangs off
    // a `&&` in a shell string, one careless edit from vanishing with the first
    // pass still exit 0. Those suites sit INSIDE a package, so the derived
    // non-package check cannot see them; this is their only structural guard.
    expect(lintRoot).toContain('packages/eslint-config/test');
    expect(lintRoot).toContain('eslint.root.guard.config.mjs');
    expect(root.scripts['typecheck:root']).toContain('tsconfig.root.json');

    const rootTsconfig = readFileSync(join(REPO_ROOT, 'tsconfig.root.json'), 'utf8');
    expect(rootTsconfig).toContain('test/setup');
    expect(rootTsconfig).toContain('tools/ci');
    expect(rootTsconfig).toContain('eslint.root.config.mjs');
    expect(rootTsconfig).toContain('eslint.root.guard.config.mjs');
  });

  it('the CI script is tracked as executable', () => {
    // `run: tools/ci/no-network-test.sh …` execs the file directly, so a mode
    // that lost its executable bit fails the job with a confusing "Permission
    // denied" rather than a network finding.
    let entry;
    try {
      entry = execFileSync('git', ['ls-files', '-s', '--', CI_SCRIPT_REL], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
      });
    } catch (cause) {
      throw new Error(
        'Could not read the git index mode. This assertion is about what ships, so it must run ' +
          'inside a git checkout.',
        { cause },
      );
    }
    expect(entry.trim()).not.toBe('');
    expect(entry.startsWith('100755 ')).toBe(true);
  });
});

// --- 2. Behavioral: the installed guard --------------------------------------

/**
 * Run `fn`, expecting the guard to refuse it. Returns the thrown error and the
 * drained record. Draining is mandatory: the setup file's afterEach fails any
 * test that leaves a refusal behind, which is how a swallowed throw stays fatal.
 * @param {() => unknown} fn
 */
function provoke(fn) {
  /** @type {unknown} */
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  return { error, attempts: takeBlockedAttempts() };
}

describe('host classification', () => {
  // Pure, so the exotic spellings are covered without needing a stack that can
  // actually route them (an IPv6-less CI runner cannot connect to ::1).
  it.each([
    'localhost',
    'LOCALHOST',
    '127.0.0.1',
    '127.1',
    '127.0.0.53',
    '::1',
    '[::1]',
    '::ffff:127.0.0.1',
    '0:0:0:0:0:0:0:1',
  ])('treats %s as loopback', (host) => {
    expect(isLoopbackHost(host)).toBe(true);
  });

  it.each([
    'registry.npmjs.org',
    'api.anthropic.com',
    '1.1.1.1',
    '0.0.0.0',
    '::',
    // A hostname that merely RESOLVES to loopback is not loopback here:
    // resolving it is itself a query that leaves the machine.
    'localtest.me',
    // `127` alone is 0.0.0.127 to inet_aton, not loopback.
    '127',
    '2606:4700:4700::1111',
  ])('treats %s as remote', (host) => {
    expect(isLoopbackHost(host)).toBe(false);
  });

  it('reads all three connect overloads', () => {
    expect(blockedTcpTarget([443, 'example.com'])).toBe('example.com:443');
    expect(blockedTcpTarget([{ host: 'example.com', port: 443 }])).toBe('example.com:443');
    // The pre-normalized `[options, callback]` array net.connect() hands down.
    expect(blockedTcpTarget([[{ host: 'example.com', port: 443 }, undefined]])).toBe(
      'example.com:443',
    );
    // A path is IPC — addressed by filename, never routed.
    expect(blockedTcpTarget(['/tmp/aka.sock'])).toBeNull();
    expect(blockedTcpTarget([{ path: '\\\\.\\pipe\\aka' }])).toBeNull();
    // Host omitted: Node defaults to localhost.
    expect(blockedTcpTarget([4319])).toBeNull();
    expect(blockedTcpTarget([{ port: 4319 }])).toBeNull();
  });

  it('reads the dgram address argument out of every arity', () => {
    expect(dgramAddress(['payload', 53, '8.8.8.8'])).toBe('8.8.8.8');
    expect(dgramAddress([Buffer.from('x'), 0, 1, 53, '8.8.8.8'])).toBe('8.8.8.8');
    // No address given: Node defaults to 127.0.0.1, so there is nothing to block.
    expect(dgramAddress(['payload', 41234])).toBeUndefined();
    expect(dgramAddress([Buffer.from('x'), 0, 1, 41234])).toBeUndefined();
  });
});

describe('outbound attempts are refused', () => {
  it('blocks a TCP connect to a remote host, and names the call site', () => {
    const { error, attempts } = provoke(() => new Socket().connect(443, 'registry.npmjs.org'));

    expect(error).toBeInstanceOf(Error);
    expect(/** @type {Error} */ (error).name).toBe('NoNetworkError');
    expect(/** @type {Error} */ (error).message).toContain('registry.npmjs.org:443');

    // The whole point of the runtime guard over a firewall rule: it says WHERE.
    // The call site is in the message, not only buried in the stack, because a
    // reader (and a CI log) sees the message first.
    expect(/** @type {Error} */ (error).message).toContain('no-network-runtime.test');
    expect(attempts).toHaveLength(1);
    expect(attempts[0].target).toBe('registry.npmjs.org:443');
    expect(attempts[0].callSite).toContain('no-network-runtime.test');
    expect(attempts[0].callSite).not.toContain('no-network.ts');
  });

  it('names the call site through a stack of library internals', () => {
    // `fetch()` reaches the socket through ~58 frames of bundled undici, all of
    // them opaque `node:internal/...`. Node's default 10-frame capture drops the
    // caller off the end entirely, and picking "the first frame" would report
    // `at Object.connect (node:internal/tls/wrap)` — true and useless. This is
    // the case that decides whether the guard is worth more than a firewall
    // rule, so it is pinned separately from the direct-connect case above.
    // eslint-disable-next-line no-restricted-globals -- a real fetch() is the point here: the runtime guard must refuse it. The ban stays live everywhere else in these suites.
    const reachOut = () => fetch('https://api.anthropic.com/v1/messages');
    const { attempts } = provoke(() => {
      // The rejection is irrelevant: the refusal is thrown and recorded
      // synchronously, inside fetch's own connect.
      void reachOut().catch(() => undefined);
    });

    expect(attempts.map((a) => a.target)).toEqual(['api.anthropic.com:443']);
    expect(attempts[0].callSite).toContain('no-network-runtime.test');
    expect(attempts[0].callSite).not.toMatch(/^node:|\(node:/);
  });

  it('blocks the options form and net.createConnection alike', () => {
    const viaOptions = provoke(() => new Socket().connect({ host: 'example.com', port: 80 }));
    expect(viaOptions.attempts.map((a) => a.target)).toEqual(['example.com:80']);

    const viaFactory = provoke(() => createConnection(80, 'example.com'));
    expect(viaFactory.attempts.map((a) => a.target)).toEqual(['example.com:80']);
  });

  it('blocks a UDP datagram to a remote address', () => {
    const socket = createSocket('udp4');
    try {
      const { error, attempts } = provoke(() => {
        socket.send('probe', 53, '8.8.8.8');
      });
      expect(/** @type {Error} */ (error).name).toBe('NoNetworkError');
      expect(attempts.map((a) => a.target)).toEqual(['8.8.8.8']);
    } finally {
      socket.close();
    }
  });

  it('blocks a DNS query on the module, its promise twin, and a Resolver', () => {
    const viaModule = provoke(() => {
      dns.resolve4('example.com', () => undefined);
    });
    expect(viaModule.attempts.map((a) => a.target)).toEqual(['example.com']);

    const viaPromises = provoke(() => dns.promises.resolveTxt('example.com'));
    expect(viaPromises.attempts.map((a) => a.target)).toEqual(['example.com']);

    const viaResolver = provoke(() => {
      new dns.Resolver().resolveMx('example.com', () => undefined);
    });
    expect(viaResolver.attempts.map((a) => a.target)).toEqual(['example.com']);
  });

  it('blocks a DNS query reached through a named ESM import', () => {
    // The module object and the Resolver prototypes are patched by property
    // assignment. A named import binds to the snapshot Node's ESM facade takes on
    // first evaluation, so without `syncBuiltinESMExports()` in the setup file
    // `namedResolve4` would be the ORIGINAL, unpatched resolver and reach the
    // nameserver. This is the vector an externalized dependency has and a
    // first-party file does not (a repo-authored `node:dns` import is lint-banned).
    const viaNamedImport = provoke(() => {
      namedResolve4('example.com', () => undefined);
    });
    expect(viaNamedImport.attempts.map((a) => a.target)).toEqual(['example.com']);
  });

  it('records a refusal even when the caller swallows it', () => {
    // Nearly every boundary in this codebase is deliberately fail-open, so a
    // guard that only threw would be silently defeated by a bare `catch {}`.
    // The record is what the setup file's afterEach turns into a failure.
    try {
      new Socket().connect(443, 'api.anthropic.com');
    } catch {
      // swallowed on purpose — exactly what a fail-open catch does
    }
    const undrained = takeBlockedAttempts();
    expect(undrained.map((a) => a.target)).toEqual(['api.anthropic.com:443']);
  });
});

describe('loopback still works', () => {
  // The positive control. Every assertion above is an absence, and an absence
  // passes vacuously if the guard simply blocks everything — including the
  // loopback the CLI's port probe and the dashboard boot test depend on.
  it('completes a real 127.0.0.1 round trip', async () => {
    const server = createServer((socket) => {
      socket.end('pong');
    });
    try {
      await new Promise((done) =>
        server.listen(0, '127.0.0.1', () => {
          done(undefined);
        }),
      );
      const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());

      const reply = await new Promise((done, fail) => {
        const client = createConnection(port, '127.0.0.1');
        let received = '';
        client.on('data', (chunk) => (received += String(chunk)));
        client.on('end', () => {
          done(received);
        });
        client.on('error', fail);
      });

      expect(reply).toBe('pong');
    } finally {
      await new Promise((done) =>
        server.close(() => {
          done(undefined);
        }),
      );
    }
    expect(takeBlockedAttempts()).toEqual([]);
  });
});

// --- 3. The CI script: the only gate that can see a child process ------------

// Everything above covers the IN-PROCESS guard. A shell-out has its own copy of
// node:net and is invisible to it, so tools/ci/no-network-test.sh is the only
// thing standing between the guarantee and `npm view` / `claude -p`. Its whole
// value is a positive control that refuses to run vacuously — and a positive
// control nothing exercises is one edit away from being decorative. Deleting its
// probes leaves the job green, exiting 0, having proved nothing.
//
// Phase 3 is driven directly here: PATH holds nothing but hand-written stubs, so
// each outcome is produced on demand with no namespace, no sudo and no real
// network. AKA_NO_NETWORK_INSIDE/_DROPPED are the script's own phase markers.

const BASH = '/bin/bash';

/** A stub that just exits. @param {number} code */
const exits = (code) => `#!/bin/sh\nexit ${String(code)}\n`;
/** A stub that prints and exits 0. @param {string} text */
const prints = (text) => `#!/bin/sh\necho '${text}'\n`;

const MARKER = 'the-suite-actually-ran';

/**
 * Skip where the harness cannot run at all rather than passing vacuously.
 *
 * The context check runs BEFORE the platform test, so a miswired case fails on
 * every platform instead of only the one that reaches the skip. `it.each` does
 * not hand its callback a TestContext — the second parameter is the next case
 * value, or undefined for a flat array — while `it` and `it.for` both do. Wired
 * through `it.each`, this function therefore dereferences undefined, and only
 * where the skip is taken: green on every POSIX machine, `Cannot read properties
 * of undefined (reading 'skip')` on Windows. Asserting the context up front is
 * what turns that into one loud failure everywhere.
 * @param {import('vitest').TestContext} ctx
 */
function requirePosixShell(ctx) {
  if (typeof ctx?.skip !== 'function') {
    throw new TypeError(
      'requirePosixShell needs a vitest TestContext to skip with, and was given none. Declare the ' +
        'case with `it` or `it.for`; `it.each` does not pass one.',
    );
  }
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the script is the Linux CI job's mechanism`);
  }
}

/**
 * Run the CI script with a PATH built from `stubs` alone.
 * @param {{ stubs: Record<string, string>, args?: string[], env?: Record<string, string>,
 *           scriptDir?: string | null }} options
 */
function runCiScript({ stubs, args = [MARKER], env = {}, scriptDir = null }) {
  const binDir = mkdtempSync(join(tmpdir(), 'aka-no-network-stub-'));
  try {
    for (const [name, body] of Object.entries(stubs)) {
      const file = join(binDir, name);
      writeFileSync(file, body);
      chmodSync(file, 0o755);
    }
    // scriptDir relocates the script so `${0%/*}/egress-probe.mjs` misses.
    let script = CI_SCRIPT_ABS;
    if (scriptDir !== null) {
      script = join(scriptDir, 'no-network-test.sh');
      writeFileSync(script, readFileSync(CI_SCRIPT_ABS, 'utf8'));
      chmodSync(script, 0o755);
    }
    const result = spawnSync(BASH, [script, ...args], {
      encoding: 'utf8',
      env: {
        PATH: binDir,
        HOME: binDir,
        AKA_NO_NETWORK_INSIDE: '1',
        AKA_NO_NETWORK_DROPPED: '1',
        ...env,
      },
    });
    return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
  } finally {
    rmSync(binDir, { recursive: true, force: true });
  }
}

/** The stub set for a run where egress really is gone: nothing resolves, nothing connects. */
const blockedStubs = () => ({
  id: prints('1001'),
  getent: exits(1), // no name resolves
  node: exits(0), // the probe reports the target unreachable
  [MARKER]: prints(MARKER),
});

describe('the CI script refuses to run vacuously', () => {
  it('runs the command when egress is genuinely gone', (ctx) => {
    requirePosixShell(ctx);
    // The positive control for this whole block: every case below asserts a
    // refusal, and a script that refused unconditionally would satisfy all of
    // them while never running the suite it exists to run.
    const run = runCiScript({ stubs: blockedStubs() });
    expect(run.status).toBe(0);
    expect(run.stdout).toContain('egress is blocked, loopback is up');
    expect(run.stdout).toContain(MARKER);
  });

  it('refuses to start as root, before reaching sudo', (ctx) => {
    requirePosixShell(ctx);
    // Started as root there is no unprivileged identity to drop back to, so the
    // read-only-store cases in packages/persistence would report
    // `effective: false` and skip — a quieter suite still reporting green.
    const run = runCiScript({
      stubs: { ...blockedStubs(), id: prints('0') },
      env: { AKA_NO_NETWORK_INSIDE: '', AKA_NO_NETWORK_DROPPED: '' },
    });
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('started as root');
    // sudo is not on the stub PATH, so reaching it would be a 127 instead.
    expect(run.status).not.toBe(127);
  });

  it('refuses with no command to run', (ctx) => {
    requirePosixShell(ctx);
    const run = runCiScript({ stubs: blockedStubs(), args: [] });
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('usage:');
  });

  // `it.for`, not `it.each`: only `for` passes the TestContext these cases skip
  // through. See requirePosixShell.
  it.for(['getent', 'node'])('fails when the probe tool %s is missing', (missing, ctx) => {
    requirePosixShell(ctx);
    // A probe whose own tooling is absent reports "not blocked = false" and the
    // control passes having probed nothing. This is the exact vacuous pass the
    // tool check exists to prevent, so each tool is pinned by name.
    const stubs = blockedStubs();
    delete stubs[missing];
    const run = runCiScript({ stubs });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain(`'${missing}' is not installed`);
    expect(run.stdout).not.toContain(MARKER);
  });

  it('fails when DNS still resolves', (ctx) => {
    requirePosixShell(ctx);
    const run = runCiScript({ stubs: { ...blockedStubs(), getent: exits(0) } });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('DNS still resolves');
    expect(run.stdout).not.toContain(MARKER);
  });

  it('fails when the TCP probe reports the target answered', (ctx) => {
    requirePosixShell(ctx);
    const run = runCiScript({ stubs: { ...blockedStubs(), node: exits(1) } });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('1.1.1.1:443 succeeded');
    expect(run.stdout).not.toContain(MARKER);
  });

  it('fails when the probe reports itself broken rather than treating it as blocked', (ctx) => {
    requirePosixShell(ctx);
    // Exit 3 is "I could not run", which must never be read as "the network is
    // gone" — that conflation is the whole failure mode this file guards.
    const run = runCiScript({ stubs: { ...blockedStubs(), node: exits(3) } });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('could not run');
    expect(run.stdout).not.toContain(MARKER);
  });

  it('fails when the probe file is missing', (ctx) => {
    requirePosixShell(ctx);
    const elsewhere = mkdtempSync(join(tmpdir(), 'aka-no-network-relocated-'));
    try {
      const run = runCiScript({ stubs: blockedStubs(), scriptDir: elsewhere });
      expect(run.status).toBe(1);
      expect(run.stderr).toContain('egress probe is missing');
      expect(run.stdout).not.toContain(MARKER);
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });
});

// --- 4. The egress probe itself ----------------------------------------------

// The probe replaces a bash `/dev/tcp` one-liner, whose failure is ambiguous:
// bash built without --enable-net-redirections fails the redirection for reasons
// that have nothing to do with the network, and the caller reads that as "egress
// blocked". So the probe proves its own mechanism against a loopback listener
// first, and the three outcomes below are its whole contract with the script.
//
// These cases spawn the probe as a CHILD process (runProbe → spawnSync), which
// the in-process guard structurally cannot see, and both probe targets are
// loopback anyway. The only socket this realm opens is the loopback listener in
// listenOnLoopback, and the guard patches connect/send/resolve, not listen — so
// section 4 makes no in-process outbound attempt for the guard to record.

/** @param {string} host @param {number} port */
function runProbe(host, port) {
  const result = spawnSync(process.execPath, [PROBE_ABS, host, String(port)], {
    encoding: 'utf8',
  });
  return { status: result.status, stderr: result.stderr ?? '' };
}

/** A listening loopback server, and its port. */
function listenOnLoopback() {
  return new Promise((done) => {
    const server = createServer((connection) => {
      connection.destroy();
    });
    server.listen(0, '127.0.0.1', () => {
      done({ server, port: server.address().port });
    });
  });
}

/** @param {import('node:net').Server} server */
function closeServer(server) {
  return new Promise((done) => {
    server.close(() => {
      done(undefined);
    });
  });
}

describe('the egress probe', () => {
  it('reports a reachable target as NOT blocked', async () => {
    const { server, port } = await listenOnLoopback();
    try {
      const run = runProbe('127.0.0.1', port);
      expect(run.status).toBe(1);
      expect(run.stderr).toContain('ANSWERED');
    } finally {
      await closeServer(server);
    }
  });

  it('reports an unreachable target as blocked', async () => {
    // Bind then release, so the port is one nothing is listening on rather than
    // a number guessed to be free.
    const { server, port } = await listenOnLoopback();
    await closeServer(server);

    const run = runProbe('127.0.0.1', port);
    expect(run.status).toBe(0);
    // The mechanism proof has to appear too: "unreachable" is only meaningful
    // once the probe has shown it can reach something.
    expect(run.stderr).toContain('loopback round trip');
    expect(run.stderr).toContain('unreachable');
  });

  it('reports junk arguments as broken, not as blocked', async () => {
    const run = runProbe('127.0.0.1', 'not-a-port');
    expect(run.status).toBe(3);
    expect(run.stderr).toContain('not a port');
  });
});

// --- 5. Both opt-outs, measured rather than assumed --------------------------

// Two files in this repo import banned network modules on purpose: the vitest
// guard patches node:net/node:dgram/node:dns, and the CI probe opens a socket.
// In both cases that IS the enforcement — but only while it stays exactly what
// it is today. eslint.root.config.mjs grants each file its opt-out so the FULL
// ruleset can cover it; these cases lint the same files with the raw ban (no
// `allow`) so widening the config cannot quietly widen what is permitted.

/**
 * Which network specifiers a file trips, named per finding. Anything that is not
 * a plain import of an expected module comes back as a describable string so the
 * failure says what it actually found.
 * @param {string} file @param {readonly string[]} expected
 */
function networkBansTrippedBy(file, expected) {
  const source = readFileSync(file, 'utf8');
  const lines = source.split('\n');
  // No filename: flat config resolves a path against the linter's base path, and
  // these files sit outside the package, which reports "no matching
  // configuration" instead of linting. The rules here are path-independent.
  //
  // `allowInlineConfig: false` is load-bearing. The one opt-out route the guard
  // config grants these suites is an inline `eslint-disable` (the deliberate
  // fetch), and `Linter#verify` honours those by default — so with the default,
  // this measure would be blind to the exact route it exists to bound: a smuggled
  // inline-disabled network global would pass unseen. lint:root still honours the
  // disable; this measure deliberately does not.
  const messages = new Linter().verify(
    source,
    {
      languageOptions: { parser: tseslint.parser, ecmaVersion: 'latest', sourceType: 'module' },
      rules: networkGuard[0].rules,
    },
    { allowInlineConfig: false },
  );
  const specifiers = messages.map((message) => {
    const line = lines[message.line - 1] ?? '';
    const named = expected.find((mod) => line.includes(`'${mod}'`));
    if (named) return named;
    // A non-import ban (a network global / member access) — name it by the
    // offending identifier, not the line number, so the expectation stays put
    // when the file shifts a line.
    if (message.endLine === message.line && message.column && message.endColumn) {
      return `global:${line.slice(message.column - 1, message.endColumn - 1)}`;
    }
    return `${String(message.ruleId)} @ line ${String(message.line)}: ${line.trim()}`;
  });
  return {
    // Deduped for a readable failure; `count` is the raw total, so a SECOND
    // inline-disabled fetch (which collapses into the first here) is still caught.
    specifiers: [...new Set(specifiers)].sort(),
    count: messages.length,
    allImports: messages.every((m) => m.ruleId === 'no-restricted-imports'),
  };
}

describe('the guard file trips exactly the bans it must', () => {
  // Defensible only while it stays these three. A fourth ban — a fetch, an http
  // import, a dynamic require — fails here.
  const EXPECTED_OPT_OUTS = ['node:dgram', 'node:dns', 'node:net'];

  it('reports only the three module imports it exists to enforce', () => {
    const { specifiers, count, allImports } = networkBansTrippedBy(GUARD_ABS, EXPECTED_OPT_OUTS);
    expect(specifiers).toEqual(EXPECTED_OPT_OUTS);
    expect(count).toBe(3);
    expect(allImports).toBe(true);
  });
});

describe('the egress probe trips exactly the ban it must', () => {
  // The probe opens TCP sockets and nothing else. A SECOND specifier here means
  // the CI tooling grew a network surface nobody reviewed.
  const EXPECTED_OPT_OUTS = ['node:net'];

  it('reports only node:net', () => {
    const { specifiers, count, allImports } = networkBansTrippedBy(PROBE_ABS, EXPECTED_OPT_OUTS);
    expect(specifiers).toEqual(EXPECTED_OPT_OUTS);
    expect(count).toBe(1);
    expect(allImports).toBe(true);
  });
});

// These two suites are the third opted-out site (via eslint.root.guard.config.mjs),
// so they are held to the same raw-guard measure as the guard and probe above.

describe('the no-network unit suite trips no bans at all', () => {
  // no-network.test.js exercises every banned construct as a STRING fed to the
  // linter; it imports nothing banned and calls nothing banned. A finding here
  // means a fixture string became live code, or the suite grew a real network
  // call — either way the guard.config need not, and does not, opt it out.
  it('reports nothing', () => {
    const { specifiers } = networkBansTrippedBy(NW_SUITE_ABS, []);
    expect(specifiers).toEqual([]);
  });
});

describe('the no-network runtime suite trips exactly the bans it must', () => {
  // It imports the three transports it drives against the patched guard, plus the
  // one deliberate fetch() the runtime block exercises. That fetch carries an
  // inline `no-restricted-globals` disable — which lint:root honours but this
  // measure does NOT (allowInlineConfig: false), so the fetch surfaces here and is
  // pinned like any other ban. A smuggled fourth specifier fails on `specifiers`;
  // a SECOND inline-disabled fetch — which the deduped set collapses into the
  // first — fails on `count`. That is what stops the inline-disable route from
  // quietly widening what these suites may reach.
  const EXPECTED_OPT_OUTS = ['global:fetch', 'node:dgram', 'node:dns', 'node:net'];

  it('reports the three module imports and the one deliberate fetch, nothing else', () => {
    const { specifiers, count, allImports } = networkBansTrippedBy(
      NW_RUNTIME_SUITE_ABS,
      EXPECTED_OPT_OUTS,
    );
    expect(specifiers).toEqual(EXPECTED_OPT_OUTS);
    expect(count).toBe(4);
    expect(allImports).toBe(false);
  });
});
