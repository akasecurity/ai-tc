/**
 * The runtime half of the no-network guarantee, loaded by every workspace
 * package as a vitest `setupFiles` entry.
 *
 * The lint ban (`no-restricted-globals` / `no-restricted-imports` /
 * `no-restricted-syntax` in `@akasecurity/eslint-config`) stops a network
 * primitive being WRITTEN. It cannot show that nothing DEPENDS on the network at
 * runtime: a transitive dependency, a non-literal `import()`, or a host global all
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
 * `takeBlockedAttempts()` is the one seam through that: a test provoking a
 * refusal on purpose has to drain it, and draining is therefore also the way to
 * hide one. It is deliberate, it is exported for the guard's own suite, and it
 * is the only opt-out that exists — there is no env switch and no config flag.
 *
 * WHY A WORKER NEEDS ITS OWN COPY. A `worker_thread` gets a FRESH module
 * registry, so none of the patches below exist there — a worker reaching out
 * was, until this file grew the section at the bottom, both allowed and
 * SILENT: nothing threw, and the parent recorded nothing for `afterEach` to
 * fail on. This is not hypothetical, because the product itself starts a worker
 * (`@akasecurity/plugin-sdk`'s isolated scan, CLAUDE.md §5) and tests drive it.
 * So the guard re-installs itself into every worker spawned from a guarded
 * thread, by wrapping the `Worker` constructor rather than by patching call
 * sites — which is what reaches a worker PRODUCT code starts, not merely one a
 * test wrote. A worker's refusal cannot land in the parent's array, so it is
 * appended to a file the parent drains in the same `takeBlockedAttempts()`; a
 * refusal swallowed inside a worker stays just as fatal as one swallowed here.
 *
 * KNOWN RESIDUALS, stated rather than silently covered:
 *   - A CHILD PROCESS is a separate process with its own copy of these modules,
 *     so a shell-out (`npm view`, `claude -p`) is invisible here. That is the
 *     gap the `No-network` CI job closes by running the whole suite inside a
 *     loopback-only network namespace — see tools/ci/no-network-test.sh. A
 *     worker started BY such a child is out of reach for the same reason: the
 *     wrapper below lives in this process, and the child never loaded it.
 *   - `dns.lookup` is NOT patched. It is the OS resolver `net.connect` itself
 *     calls, so guarding it would duplicate the connect guard while risking the
 *     internal `util.promisify` contract that `dns.promises` is built on. Be
 *     clear about what that leaves open: a bare `dns.lookup` with no connect
 *     after it still discloses the hostname to whoever runs the resolver, which
 *     for a local-first product is real egress, not a non-event. What it is not
 *     is a DEPENDENCY on a remote service, which is what this guard measures.
 *     Only the Linux namespace job blocks it; every other platform does not.
 *     The `resolve*` family IS patched — on the `dns` object, on both `Resolver`
 *     prototypes, and, via `syncBuiltinESMExports`, on named ESM imports of
 *     `node:dns`/`node:dns/promises` — since those speak to a nameserver
 *     directly and nothing internal routes through them.
 *   - A native addon opening its own socket bypasses every JS-level patch. No
 *     dependency here has one, and the namespace job catches it anyway.
 *   - ATTRIBUTION IS BEST-EFFORT across an await. A refusal recorded after its
 *     test has finished — a floating promise, a late timer — fails the NEXT
 *     test's `afterEach`, because that is the next hook to run. The run still
 *     fails, which is the point; the recorded stack is what identifies the real
 *     culprit, so read that rather than the test the failure is attached to.
 */
import { randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { appendFileSync, readFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import workerThreads from 'node:worker_threads';

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

// This module is loaded two ways, and the query string is what tells them
// apart. As a vitest `setupFiles` entry it is loaded by plain path, and it owns
// the array and the hooks. Re-loaded inside a worker via `--import` (see
// `guardWorkerConstructor` at the bottom) it carries `?akaReport=<path>` and
// records to that file instead, because its `attempts` array is a DIFFERENT
// array the parent cannot read.
//
// The discriminator is deliberately the query rather than `isMainThread`: under
// a vitest `pool: 'threads'` run the setup file itself executes off the main
// thread, and keying on that would silently drop the backstop hooks for the
// whole workspace.
const SELF_URL = new URL(import.meta.url);
const WORKER_REPORT = SELF_URL.searchParams.get('akaReport');
const IN_INJECTED_WORKER = WORKER_REPORT !== null;

const attempts: BlockedAttempt[] = [];

// The parent's side of the worker channel. Named on the first worker spawn and
// not before, so a run that starts no worker names nothing.
let reportPath: string | null = null;

// How much of the report has already been drained, as an offset into the file's
// decoded text.
let drainedChars = 0;

/**
 * The path worker refusals are appended to.
 *
 * Only the PATH is decided here. The file itself is created by the first
 * `appendFileSync` a REFUSING worker makes, so a run in which nothing reaches
 * the network writes nothing at all — and the drain below reads its absence as
 * "no refusals" rather than as an error. The name carries a uuid rather than a
 * pid because a pid is recycled: a stale file from an earlier run would
 * otherwise be drained as if it belonged to this one.
 */
function ensureReportPath(): string {
  reportPath ??= join(tmpdir(), `aka-no-network-${randomUUID()}.jsonl`);
  return reportPath;
}

/**
 * Read whatever workers have recorded since the last drain. A line that will
 * not parse is surfaced as an attempt rather than skipped: two threads
 * appending at once could in principle interleave, and losing a refusal is the
 * one outcome this file may not produce.
 *
 * The file is APPENDED to and never truncated, and that is the whole reason for
 * the offset. Reading and then truncating races a worker that is still
 * refusing: a refusal appended between the two is destroyed unread, which
 * measured at 49 lost out of 400 against a worker refusing in a loop. An offset
 * has no destructive step for an append to race, so a drain can only decline to
 * advance — never lose.
 */
function drainWorkerAttempts(): BlockedAttempt[] {
  if (reportPath === null) return [];
  let raw: string;
  try {
    raw = readFileSync(reportPath, 'utf8');
  } catch (cause) {
    // A file that does not exist yet is the one tolerable failure, and it is
    // the ordinary case: no worker has refused. Anything else — a permission
    // denial, a Windows sharing violation — must fail the run. Reporting zero
    // refusals because the channel could not be READ is exactly the silent pass
    // this file exists to prevent, and it would look identical to a clean run.
    if ((cause as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw new Error(
      `no-network: could not read the worker refusal report at ${reportPath}. Whatever a ` +
        'worker recorded there cannot be accounted for, so this run is not evidence that ' +
        'nothing reached the network.',
      { cause },
    );
  }
  // Stop at the last complete line: a worker may be mid-append, and advancing
  // past a partial line would turn a real refusal into an unreadable one.
  const complete = raw.lastIndexOf('\n') + 1;
  if (complete <= drainedChars) return [];
  const pending = raw.slice(drainedChars, complete);
  drainedChars = complete;
  return pending
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => {
      try {
        return JSON.parse(line) as BlockedAttempt;
      } catch {
        return {
          kind: 'unreadable record from a worker',
          target: '(unknown)',
          callSite: '(unknown)',
          stack: line,
        };
      }
    });
}

/**
 * Record one refusal where the drain can find it. In a worker that is a file,
 * because the parent's `afterEach` cannot see a worker's heap — and an
 * unrecorded refusal in a worker is the same silent pass as an unrecorded one
 * here.
 */
function record(attempt: BlockedAttempt): void {
  if (IN_INJECTED_WORKER) {
    appendFileSync(WORKER_REPORT, `${JSON.stringify(attempt)}\n`);
    return;
  }
  attempts.push(attempt);
}

/**
 * Drain the recorded refusals — this thread's, and any a worker appended.
 * Called by the `afterEach`/`afterAll` backstops below, and by the guard's own
 * tests to consume an attempt they provoked on purpose (an undrained attempt
 * fails the test that made it).
 */
export function takeBlockedAttempts(): BlockedAttempt[] {
  const own = attempts.splice(0, attempts.length);
  return [...own, ...drainWorkerAttempts()];
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
// the built-in `fetch()` does on the way to the socket looks like this, and none
// of it is the line a reader has to change.
const OPAQUE_FRAME = /^\s+at node:|\((?:node:|<anonymous>)/;

// A frame inside an installed dependency. Skipped in favour of repo code for the
// same reason: naming `node_modules/some-client/dist/index.js` is true but not
// where the fix goes. This matters most for the case the lint ban structurally
// cannot see — a TRANSITIVE dependency reaching out — where every non-opaque
// frame near the socket belongs to the dependency rather than to us.
const VENDOR_FRAME = /[\\/]node_modules[\\/]/;

/**
 * The innermost frame belonging to this repo's own source: the code that reached
 * out. Degrades in steps rather than reporting nothing — a dependency's frame if
 * that is all there is, then the OUTERMOST frame, since with everything opaque
 * the caller furthest from the socket is the most informative one left.
 */
function callSiteOf(frames: readonly string[]): string {
  const visible = frames.filter(
    (line) => !OPAQUE_FRAME.test(line) && !line.includes('no-network.ts'),
  );
  const own =
    visible.find((line) => !VENDOR_FRAME.test(line)) ?? visible[0] ?? frames[frames.length - 1];
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

  record({ kind, target, callSite, stack: error.stack });
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

// Read through a cast to a plain function PROPERTY rather than as a method
// reference. Capturing the original unbound function is the mechanism —
// `guardedConnect` re-applies it with the caller's own `this` — and the shape
// below is what the dgram and dns guards use for the same reason.
const realConnect = (Socket.prototype as unknown as { connect: AnyFn }).connect;

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
  // Rebound rather than closed over directly: `noUncheckedIndexedAccess` types
  // the lookup as `AnyFn | undefined`, and the narrowing above does not reach
  // inside the closure. Same shape as `guardDnsResolvers` below.
  const realFn: AnyFn = real;
  function guarded(this: unknown, ...args: unknown[]): unknown {
    const address = dgramAddress(args);
    if (address !== undefined && !isLoopbackHost(address)) {
      refuse(kind, address, guarded);
    }
    return realFn.apply(this, args);
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
guardDnsResolvers(dns.promises);
guardDnsResolvers(dns.Resolver.prototype as unknown as Record<string, unknown>);
guardDnsResolvers(dns.promises.Resolver.prototype as unknown as Record<string, unknown>);

// The calls above patch the `dns` exports object and both `Resolver` prototypes
// by property assignment. Node's builtin ESM facade snapshots a module's named
// exports on first evaluation — which the `import dns from 'node:dns'` above
// forces before these run — so a named import (`import { resolve4 } from
// 'node:dns'`, or the same off `node:dns/promises`, which shares the exports
// object) would bind to the ORIGINAL resolver and slip the guard. Re-syncing the
// facade rebinds those names to the guarded functions. The TCP/UDP halves patch
// prototypes, resolved at call time, so this does not affect them.
syncBuiltinESMExports();

// --- worker_threads (a fresh module registry, so a fresh copy of all of it) --

// Everything above patches THIS thread. A worker gets none of it, so the
// wrapper below re-runs this file inside every worker spawned from a guarded
// thread — `--import` accepts a file URL and Node applies it before the
// worker's own entry, which is why it reaches a worker started by product code
// rather than only one a test wrote by hand.
//
// The whole ruleset for what counts as loopback therefore stays in one file
// with one implementation. A second, worker-shaped copy of the classifiers is
// exactly the drift this avoids.

/** This module's own path, with any `?akaReport=` stripped back off. */
const SELF_PREFIX = SELF_URL.href.split('?')[0] ?? SELF_URL.href;

/**
 * The `execArgv` a spawned worker should run with: whatever it would have
 * inherited, plus this file.
 *
 * Any inherited `--import` of this same file is dropped first. A worker started
 * from inside a worker would otherwise accumulate one per level of nesting,
 * since `process.execArgv` in an injected worker already carries ours.
 */
function execArgvWithGuard(inherited: readonly string[], report: string): string[] {
  const kept: string[] = [];
  for (let i = 0; i < inherited.length; i++) {
    const flag = inherited[i];
    if (flag === '--import' && (inherited[i + 1] ?? '').startsWith(SELF_PREFIX)) {
      i++; // skip the flag and its value
      continue;
    }
    if (flag !== undefined) kept.push(flag);
  }
  const preload = new URL(SELF_PREFIX);
  preload.searchParams.set('akaReport', report);
  return [...kept, '--import', preload.href];
}

/**
 * Wrap `Worker` so every worker re-loads this guard. Assigned onto the module
 * object and re-synced for the same reason the dns patch above is: product code
 * reaches `Worker` through a NAMED import (`isolated-scan.ts` does), which binds
 * to the facade's snapshot rather than to the live property.
 */
function guardWorkerConstructor(): void {
  const carrier = workerThreads as unknown as Record<string, unknown>;
  const RealWorker = carrier.Worker as typeof workerThreads.Worker;
  if (typeof RealWorker !== 'function') return;

  class GuardedWorker extends RealWorker {
    constructor(filename: string | URL, options: workerThreads.WorkerOptions = {}) {
      // In an injected worker the parent already owns a report file; a nested
      // worker reports to that same one, so its refusals surface in the drain
      // that the top-level thread performs.
      const report = IN_INJECTED_WORKER ? WORKER_REPORT : ensureReportPath();
      super(filename, {
        ...options,
        execArgv: execArgvWithGuard(options.execArgv ?? process.execArgv, report),
      });
    }
  }

  carrier.Worker = GuardedWorker;
  syncBuiltinESMExports();
}

guardWorkerConstructor();

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

// Only the `setupFiles` load registers hooks. The copy re-loaded inside a
// worker has no suite to attach to — importing vitest there throws outright —
// and its refusals reach the parent's hooks through the report file instead.
// The import is dynamic for the same reason: a worker must not pay for
// resolving vitest's module graph on every spawn.
if (!IN_INJECTED_WORKER) {
  const { afterAll, afterEach } = await import('vitest');

  afterEach(() => {
    reportUndrained('this test');
  });

  // Catches what `afterEach` cannot: an attempt made while a test FILE is
  // loading, inside a `beforeAll`/`afterAll`, or from a timer that fired after
  // the last test.
  afterAll(() => {
    reportUndrained('this test file, outside any single test');
  });
}
