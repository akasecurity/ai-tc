import { execFileSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import dns from 'node:dns';
import { existsSync, globSync, readFileSync } from 'node:fs';
import { createConnection, createServer, Socket } from 'node:net';
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
// dynamic specifier, or a host global all reach the wire without tripping a rule.
// test/setup/no-network.ts closes that by refusing the connection itself, and
// every package loads it as a vitest setupFile — including this one, so the
// behavioral cases below exercise the guard that is already installed rather
// than a copy of it.
//
// Three properties are guarded here:
//
//  1. STRUCTURAL — every package that runs vitest wires the guard, and the
//     relative path it wires actually resolves to the one guard file. Thirteen
//     hand-written paths at two different depths is exactly the shape that
//     drifts, and a package that quietly drops the entry would run unguarded
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
//  3. AUDITED OPT-OUT — the guard file imports node:net / node:dgram / node:dns,
//     which the shared ban forbids. That is the enforcement, not a violation of
//     it, but it is only defensible while it stays exactly those three: the file
//     is linted here and any FOURTH network ban it trips fails this suite.

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');

const GUARD_REL = 'test/setup/no-network.ts';
const GUARD_ABS = join(REPO_ROOT, ...GUARD_REL.split('/'));
const CI_SCRIPT_REL = 'tools/ci/no-network-test.sh';

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
 * Every workspace package whose `test` script runs vitest, with how (and
 * whether) its vitest config wires the guard.
 */
function vitestPackages() {
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
    .filter((p) => /(^|[\s/])vitest([\s/]|$)/.test(p.testScript))
    .map((p) => {
      const configAbs = join(REPO_ROOT, p.dir, 'vitest.config.ts');
      if (!existsSync(configAbs)) return { ...p, hasConfig: false, wired: false, resolved: null };
      const source = stripComments(readFileSync(configAbs, 'utf8'));
      const url = GUARD_URL.exec(source);
      return {
        ...p,
        hasConfig: true,
        wired: SETUP_ENTRY.test(source),
        resolved: url ? resolve(dirname(configAbs), url[1]) : null,
      };
    });
}

const VITEST_PACKAGES = vitestPackages();

// The exact set expected to run vitest, pinned by name. A derived-vs-derived
// comparison cannot catch a package the enumeration silently dropped, because it
// would be missing from both sides. An exact set fails loudly on any add, drop
// or rename — at which point the new package must either wire the guard or be
// argued out of it in review.
const EXPECTED_VITEST_PACKAGES = [
  '@akasecurity/ai-tc-claude-code',
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

describe('every vitest package loads the no-network guard', () => {
  it('enumerates exactly the packages that run vitest', () => {
    expect(VITEST_PACKAGES.map((p) => p.name).sort()).toEqual([...EXPECTED_VITEST_PACKAGES].sort());
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

  it('ci.yml runs the suite through the egress-blocking script', () => {
    // The vitest guard cannot see a child process; this job is what does.
    const ci = readFileSync(join(REPO_ROOT, '.github', 'workflows', 'ci.yml'), 'utf8');
    expect(ci).toContain(CI_SCRIPT_REL);
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

// --- 3. The guard file's own opt-out, measured rather than assumed -----------

describe('the guard file trips exactly the bans it must', () => {
  // node:net / node:dgram / node:dns are banned workspace-wide, and the guard
  // imports all three — that IS the enforcement. It is defensible only while it
  // stays those three, so lint the real file with the shared network guard and
  // pin the result. A fourth ban (a fetch, an http import, a dynamic require)
  // fails here.
  const EXPECTED_OPT_OUTS = ['node:dgram', 'node:dns', 'node:net'];

  it('reports only the three module imports it exists to enforce', () => {
    const source = readFileSync(GUARD_ABS, 'utf8');
    const lines = source.split('\n');
    // No filename: flat config resolves a path against the linter's base path,
    // and this file sits outside the package, which reports "no matching
    // configuration" instead of linting. The rules here are path-independent.
    const messages = new Linter().verify(source, {
      languageOptions: {
        parser: tseslint.parser,
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      rules: networkGuard[0].rules,
    });

    // Every finding must be an import of one of the three, on its own import
    // line — not a fetch, a global, or a dynamic specifier.
    const specifiers = messages.map((message) => {
      const line = lines[message.line - 1] ?? '';
      const named = EXPECTED_OPT_OUTS.find((mod) => line.includes(`'${mod}'`));
      return named ?? `${String(message.ruleId)} @ line ${String(message.line)}: ${line.trim()}`;
    });

    expect([...new Set(specifiers)].sort()).toEqual(EXPECTED_OPT_OUTS);
    expect(messages.every((m) => m.ruleId === 'no-restricted-imports')).toBe(true);
  });
});
