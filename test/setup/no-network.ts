/**
 * The runtime half of the no-network guarantee, loaded by every workspace
 * package as a vitest `setupFiles` entry.
 *
 * The lint ban (`no-restricted-globals` / `no-restricted-imports` /
 * `no-restricted-syntax` in `@akasecurity/eslint-config`) stops a network
 * primitive being WRITTEN. It cannot show that nothing DEPENDS on the network at
 * runtime: a transitive dependency, a dynamic specifier, or a host global all
 * reach the wire without ever tripping a rule. This file closes that half by
 * refusing the connection itself, and it names the call site that made it.
 *
 * WHY THIS FILE IMPORTS THE BANNED MODULES. `node:net`, `node:dgram` and
 * `node:dns` are on the lint ban list; importing them here is the enforcement,
 * not a violation of it. The file ships nowhere (no package `files` array
 * reaches it) and runs only under vitest. `packages/eslint-config/test/
 * no-network-runtime.test.js` lints it with the shared network guard and asserts
 * these three specifiers are the ONLY bans it trips, so the opt-out is measured
 * rather than assumed.
 *
 * WHAT IS ALLOWED. Loopback only — `127.0.0.0/8`, `::1`, `localhost`, and the
 * IPv4-mapped forms — plus unix-domain sockets and Windows named pipes, which
 * are addressed by path and never leave the machine. Everything else throws.
 *
 * WHY A THROW IS NOT ENOUGH. Nearly every boundary in this codebase is
 * deliberately fail-open (CLAUDE.md §1), so a throw raised inside a `catch {}`
 * would be swallowed and the run would go green having reached the network. Each
 * refusal is therefore also RECORDED, and `afterEach`/`afterAll` hooks fail the
 * run on any recording that was not drained. A swallowed refusal is still fatal.
 *
 * KNOWN RESIDUALS, stated rather than silently covered:
 *   - A CHILD PROCESS is a separate process with its own copy of these modules,
 *     so a shell-out (`npm view`, `claude -p`) is invisible here. That is the
 *     gap the `No-network` CI job closes by running the whole suite inside a
 *     loopback-only network namespace — see tools/ci/no-network-test.sh.
 *   - `dns.lookup` is NOT patched. It is the OS resolver `net.connect` itself
 *     calls, so guarding it would duplicate the connect guard while risking the
 *     internal `util.promisify` contract that `dns.promises` is built on. A bare
 *     `dns.lookup` with no connect after it is a DNS query, not a dependency on
 *     a remote service. The `resolve*` family IS patched: those speak to a
 *     nameserver directly and nothing internal routes through them.
 *   - A native addon opening its own socket bypasses every JS-level patch. No
 *     dependency here has one, and the namespace job catches it anyway.
 */
import dgram from 'node:dgram';
import dns from 'node:dns';
import { Socket } from 'node:net';

import { afterAll, afterEach } from 'vitest';

/** One refused outbound attempt, kept so a swallowed throw is still fatal. */
export interface BlockedAttempt {
  /** Human-readable kind, e.g. `TCP connection`. */
  readonly kind: string;
  /** Where it was headed, e.g. `registry.npmjs.org:443`. */
  readonly target: string;
  /** The first frame outside Node's internals — the code that reached out. */
  readonly callSite: string;
  /** The refusal's full stack. */
  readonly stack: string;
}

const attempts: BlockedAttempt[] = [];

/**
 * Drain the recorded refusals. Called by the `afterEach`/`afterAll` backstops
 * below, and by the guard's own tests to consume an attempt they provoked on
 * purpose (an undrained attempt fails the test that made it).
 */
export function takeBlockedAttempts(): BlockedAttempt[] {
  return attempts.splice(0, attempts.length);
}

// Node's own default when a connect omits the host (lib/net.js).
const DEFAULT_HOST = 'localhost';

const LOOPBACK_NAMES = new Set([
  'localhost',
  '::1',
  '0:0:0:0:0:0:0:1',
  '0000:0000:0000:0000:0000:0000:0000:0001',
]);

// Any dotted form under 127/8, shorthand included: `inet_aton` reads `127.1` as
// 127.0.0.1. A bare `127` is deliberately NOT matched — that parses as 0.0.0.127.
const IPV4_LOOPBACK = /^127(?:\.\d{1,3}){1,3}$/;

const IPV4_MAPPED_PREFIX = '::ffff:';

/**
 * Whether `host` addresses this machine's loopback interface. Conservative by
 * design: a hostname that merely happens to resolve to loopback is NOT loopback
 * here, because resolving it is itself a query that leaves the machine.
 */
export function isLoopbackHost(host: string): boolean {
  let value = host.trim().toLowerCase();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  const zone = value.indexOf('%'); // fe80::1%eth0 — drop the scope id
  if (zone !== -1) value = value.slice(0, zone);
  if (LOOPBACK_NAMES.has(value)) return true;
  if (IPV4_LOOPBACK.test(value)) return true;
  if (value.startsWith(IPV4_MAPPED_PREFIX)) {
    return isLoopbackHost(value.slice(IPV4_MAPPED_PREFIX.length));
  }
  return false;
}

const MESSAGE_TAIL = [
  '',
  'ai-tc is local-first: nothing in the suite may depend on the network, so the',
  'whole suite passes with egress blocked. Loopback (127.0.0.1, ::1, localhost)',
  'and unix/named-pipe sockets are allowed; everything else is refused here.',
  '',
  'Reach the outside world only through a seam a test can inject — see',
  "local-ops' ReportDeps.viewVersion and judge.ts's spawnClaude — never from a",
  'test itself.',
].join('\n');

// Node's default of 10 frames is spent entirely inside undici for a `fetch()`,
// so the line that actually reached out falls off the end — and naming that line
// is the whole reason this guard exists rather than a firewall rule.
const STACK_DEPTH = 80;

const stackFrames = (stack: string): string[] =>
  stack.split('\n').filter((line) => /^\s+at /.test(line));

// A frame in Node itself (`at node:internal/...`, `at connect (node:...)`) or
// with no source location at all (`at new Promise (<anonymous>)`). Everything
// undici does on the way to a `fetch()` looks like this, and none of it is the
// line a reader has to change.
const OPAQUE_FRAME = /^\s+at node:|\((?:node:|<anonymous>)/;

/**
 * The innermost frame belonging to real source: the code that reached out. Falls
 * back to the OUTERMOST frame rather than reporting nothing — if every frame is
 * opaque, the caller furthest from the socket is the most informative one left.
 */
function callSiteOf(frames: readonly string[]): string {
  const own =
    frames.find((line) => !OPAQUE_FRAME.test(line) && !line.includes('no-network.ts')) ??
    frames[frames.length - 1];
  return own?.trim().replace(/^at /, '') ?? '(call site unavailable)';
}

/**
 * Record and refuse one outbound attempt. `caller` is the guard wrapper that
 * intercepted it; passing it to `captureStackTrace` drops this frame and the
 * wrapper's, so the stack starts at the code that reached out.
 */
function refuse(kind: string, target: string, caller: (...args: never[]) => unknown): never {
  const error = new Error();
  const previousDepth = Error.stackTraceLimit;
  Error.stackTraceLimit = STACK_DEPTH;
  Error.captureStackTrace(error, caller);
  const frames = stackFrames(error.stack ?? '');
  Error.stackTraceLimit = previousDepth;

  const callSite = callSiteOf(frames);
  error.name = 'NoNetworkError';
  error.message = `no-network: blocked an outbound ${kind} to ${target}\n  reached from ${callSite}\n${MESSAGE_TAIL}`;
  // Re-render the header now that the message exists: V8 formatted the stack
  // when `error.stack` was first read above, so the cached string still carries
  // the empty message it was built with.
  error.stack = `${error.name}: ${error.message}\n${frames.join('\n')}`;

  attempts.push({ kind, target, callSite, stack: error.stack });
  throw error;
}

// --- net (TCP, and therefore TLS / HTTP / HTTP2 / fetch / WebSocket) ---------

/**
 * Mirrors Node's `isPipeName()`: a first argument that parses as a non-negative
 * number is a port, anything else is a pipe/socket path.
 */
function isPortLike(value: string): boolean {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0;
}

/**
 * The `host:port` a `Socket.connect(...)` call is headed for, or `null` when the
 * call is allowed — an IPC path, or a loopback address. Covers all three
 * overloads: `(options)`, `(path)`, and `(port[, host])`.
 */
export function blockedTcpTarget(args: readonly unknown[]): string | null {
  const first = args[0];

  // `net.connect()` / `net.createConnection()` pre-normalize their arguments and
  // hand `Socket.prototype.connect` a single `[options, callback]` ARRAY (Node
  // tags it with an internal symbol). Reading `.host`/`.port` off that array
  // finds nothing, so the factory forms would sail past the guard the direct
  // `socket.connect(port, host)` form trips. Unwrap it and re-read.
  if (Array.isArray(first)) return blockedTcpTarget(first as unknown[]);

  let host: string;
  let port: unknown;

  if (typeof first === 'object' && first !== null) {
    const options = first as { path?: unknown; host?: unknown; port?: unknown };
    if (typeof options.path === 'string') return null; // IPC — never leaves the box
    host = typeof options.host === 'string' ? options.host : DEFAULT_HOST;
    port = options.port;
  } else if (typeof first === 'string' && !isPortLike(first)) {
    return null; // a pipe/socket path
  } else {
    const second = args[1];
    host = typeof second === 'string' ? second : DEFAULT_HOST;
    port = first;
  }

  if (isLoopbackHost(host)) return null;
  return `${host}:${typeof port === 'number' || typeof port === 'string' ? String(port) : '?'}`;
}

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;

const realConnect = Socket.prototype.connect as unknown as AnyFn;

function guardedConnect(this: unknown, ...args: unknown[]): unknown {
  const target = blockedTcpTarget(args);
  if (target !== null) refuse('TCP connection', target, guardedConnect);
  return realConnect.apply(this, args);
}

Socket.prototype.connect = guardedConnect as unknown as typeof Socket.prototype.connect;

// --- dgram (UDP) ------------------------------------------------------------

/**
 * The destination address of a `dgram` `send(...)` / `connect(...)` call, or
 * `undefined` when none was given. Both take the address as the last string
 * argument after the leading message/port, and Node defaults an omitted address
 * to 127.0.0.1 — so `undefined` is loopback and is allowed. Index 0 is skipped
 * because `send()`'s message may itself be a string.
 */
export function dgramAddress(args: readonly unknown[]): string | undefined {
  for (let i = args.length - 1; i >= 1; i--) {
    const arg = args[i];
    if (typeof arg === 'string') return arg;
  }
  return undefined;
}

function guardDgram(method: 'send' | 'connect', kind: string): void {
  const prototype = dgram.Socket.prototype as unknown as Record<string, AnyFn>;
  const real = prototype[method];
  if (typeof real !== 'function') return;
  function guarded(this: unknown, ...args: unknown[]): unknown {
    const address = dgramAddress(args);
    if (address !== undefined && !isLoopbackHost(address)) {
      refuse(kind, address, guarded);
    }
    return real.apply(this, args);
  }
  prototype[method] = guarded;
}

guardDgram('send', 'UDP datagram');
guardDgram('connect', 'UDP association');

// --- dns (the resolver family only — see the residual note in the header) ----

// Every method that speaks to a nameserver directly. `lookup`/`lookupService`
// are deliberately absent: they are the OS resolver, which `net.connect` calls
// for us and which the connect guard above has already gated.
const DNS_RESOLVER_METHODS = [
  'resolve',
  'resolve4',
  'resolve6',
  'resolveAny',
  'resolveCaa',
  'resolveCname',
  'resolveMx',
  'resolveNaptr',
  'resolveNs',
  'resolvePtr',
  'resolveSoa',
  'resolveSrv',
  'resolveTxt',
  'reverse',
] as const;

/**
 * Patch the resolver family on one carrier object (the `dns` module, its
 * `promises` twin, or a `Resolver` prototype). A missing method is skipped
 * rather than assumed: the set differs slightly across carriers and Node
 * versions, and inventing one would change the surface instead of guarding it.
 */
function guardDnsResolvers(carrier: Record<string, unknown> | undefined): void {
  if (!carrier) return;
  for (const method of DNS_RESOLVER_METHODS) {
    const real = carrier[method];
    if (typeof real !== 'function') continue;
    const realFn = real as AnyFn;
    function guarded(this: unknown, ...args: unknown[]): unknown {
      const name = args[0];
      refuse('DNS query', typeof name === 'string' ? name : '(unknown host)', guarded);
      // Unreachable — kept so the wrapper's shape matches what it replaces.
      return realFn.apply(this, args);
    }
    carrier[method] = guarded;
  }
}

const dnsModule = dns as unknown as Record<string, unknown>;
guardDnsResolvers(dnsModule);
guardDnsResolvers(dns.promises as unknown as Record<string, unknown>);
guardDnsResolvers(dns.Resolver.prototype as unknown as Record<string, unknown>);
guardDnsResolvers(dns.promises.Resolver.prototype as unknown as Record<string, unknown>);

// --- backstops --------------------------------------------------------------

/**
 * Fail the run on any refusal that was recorded but never surfaced. Without
 * this, a `catch {}` on a fail-open path would eat the throw and the suite would
 * report green having reached for the network.
 */
function reportUndrained(scope: string): void {
  const undrained = takeBlockedAttempts();
  if (undrained.length === 0) return;
  const detail = undrained
    .map((a) => `  - ${a.kind} to ${a.target}\n    from ${a.callSite}\n${a.stack}`)
    .join('\n\n');
  throw new Error(
    `no-network: ${String(undrained.length)} outbound attempt(s) were blocked during ${scope}, ` +
      'and the refusal was swallowed by a catch. Every one of these reached for the ' +
      `network:\n\n${detail}`,
  );
}

afterEach(() => {
  reportUndrained('this test');
});

// Catches what `afterEach` cannot: an attempt made while a test FILE is loading,
// inside a `beforeAll`/`afterAll`, or from a timer that fired after the last test.
afterAll(() => {
  reportUndrained('this test file, outside any single test');
});
