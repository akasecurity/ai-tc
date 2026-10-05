// Antigravity stdio helpers — the only tool-specific glue the adapter keeps.
// Detection, policy, and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between Antigravity and the runtime.
//
// Two things differ from the Claude Code / Codex siblings, and both are
// load-bearing:
//
//  1. THE HOST FAILS CLOSED. Claude Code and Codex read "no output, exit 0" as
//     "no opinion" (allow). Antigravity does not: a PreToolUse hook that exits
//     non-zero is read as a `deny`, and one that prints a payload the schema
//     rejects surfaces as "Tool call denied by <hook>" (invalid_args). A hook
//     that merely crashes therefore BLOCKS EVERY TOOL CALL — the exact opposite
//     of this repo's fail-open rule. So every entry here runs through
//     `runHookFailOpen`, which writes an explicit host-shaped allow payload
//     before exiting 0 on every path that yields — a throw, an undecided body,
//     and a body that outruns the watchdog. It cannot cover a body that blocks
//     this thread; see `runHookFailOpen` for that limit and why closing it
//     needs a worker rather than a longer timer.
//
//  2. THE PAYLOAD IS camelCase AND NESTS THE TOOL CALL. Antigravity sends
//     `{ toolCall: { name, args }, conversationId, workspacePaths, … }` where
//     Claude Code and Codex send flat snake_case (`tool_name`, `tool_input`,
//     `session_id`, `cwd`). `workspacePaths` is an ARRAY — there is no `cwd`.

import { spawn } from 'node:child_process';
import { isAbsolute, join, normalize, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

// The host kills a hook that outruns its `timeout` (SIGTERM) and aborts the
// turn. Because a killed hook never prints, that reads as a deny too — so the
// hook races its own watchdog and emits the fail-open payload first. Kept
// comfortably under the 10s registered in hooks.json.
const WATCHDOG_MS = 8_000;

// What the watchdog resolves the race with. A value no body can return, so a
// body that resolves `undefined` (declining to decide) is never mistaken for
// one that ran out of time.
const WATCHDOG_FIRED: unique symbol = Symbol('watchdog fired');

/**
 * The built fail-open counting child's filename, resolved as a sibling of the
 * running hook script.
 *
 * Exported so the spawn and the build check read one string. The published
 * plugin ships `scripts/` only, so this resolves against the bundle rather than
 * the source tree.
 */
export const FAIL_OPEN_COUNT_SCRIPT_NAME = 'fail-open-count.js';

export async function readStdin(): Promise<string> {
  return new Promise<string>((resolve) => {
    let data = '';
    let settled = false;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.stdin.removeListener('data', onData);
      process.stdin.removeListener('end', finish);
      resolve(data);
    };
    const onData = (chunk: string): void => {
      data += chunk;
    };
    // A stalled or never-closed stdin must not hang the hook past the host's
    // own timeout: settle with whatever arrived and let the caller fail open.
    const timer = setTimeout(finish, 5_000);

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', onData);
    process.stdin.on('end', finish);
    // An unhandled 'error' here would be an uncaughtException, not a
    // rejection — settle instead so the hook still exits 0.
    process.stdin.on('error', finish);
  });
}

export function parseJson(raw: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function getString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

/**
 * The tool call an Antigravity PreToolUse/PostToolUse payload describes:
 * `{ toolCall: { name, args } }`, where Claude Code and Codex send a flat
 * `tool_name` + `tool_input` pair. Returns undefined when the payload carries
 * no usable tool call, so the caller fails open rather than scanning nothing
 * and reporting success.
 */
export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

export function readToolCall(input: Record<string, unknown>): ToolCall | undefined {
  const raw = input.toolCall;
  if (typeof raw !== 'object' || raw === null) return undefined;
  const call = raw as Record<string, unknown>;
  const name = getString(call, 'name');
  if (name === undefined || name === '') return undefined;
  const args = call.args;
  return {
    name,
    args: typeof args === 'object' && args !== null ? (args as Record<string, unknown>) : {},
  };
}

/**
 * First workspace path, the closest thing Antigravity's payload has to Claude
 * Code's `cwd`. The field is an array (a session can span several roots); repo
 * identity is resolved from the first entry, and the caller falls back to the
 * hook process's own cwd when it is absent.
 *
 * The SCOPE key does not follow this rule: `captureScopeKey` keys an event
 * that names a target by the checkout holding that file (a relative target is
 * read against the one root there is), and an event with no target only when
 * every root agrees.
 */
export function primaryWorkspacePath(input: Record<string, unknown>): string | undefined {
  const paths = input.workspacePaths;
  if (!Array.isArray(paths)) return undefined;
  for (const entry of paths) {
    if (typeof entry === 'string' && entry !== '') return entry;
  }
  return undefined;
}

// Hook output protocol: write one JSON object to stdout and exit 0.
//
// Unlike the Claude Code and Codex adapters, writing NOTHING is not a valid
// "no opinion" here — see the module header. Callers must always hand `emit` a
// payload; `runHookFailOpen` guarantees they do.
//
// The flush must be awaited: hook entries exit right after main(), and exit
// does not wait for pending pipe writes — anything past the ~64KB pipe buffer
// is dropped, Antigravity sees invalid JSON, and (fail-closed) denies the call.
export function emit(output: unknown): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };
    // Same hazard as readStdin: an unhandled 'error' on stdout (e.g. EPIPE if
    // the caller closed its end) is an uncaughtException, not a rejection —
    // resolve instead so the hook still exits 0 rather than crashing on
    // write. Deliberately never removed: a hook process exits right after, so
    // one leftover no-op listener is free.
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

/**
 * Run a hook body so the host is left with a VALID payload rather than silence.
 *
 * Not necessarily a permissive one: a body that reaches a decision has it
 * forwarded verbatim, which is how PreToolUse denies. `failOpen` is the event's
 * own "carry on unchanged" payload — `{ decision: 'allow' }` for PreToolUse,
 * `{}` for the rest — and is written on the three paths where no decision was
 * reached: the body throws, the body declines to decide (returns undefined), or
 * the body outruns the watchdog. This is the fail-open rule (Architecture
 * principles §1) expressed for a host that fails CLOSED.
 *
 * Two of those three are failures, and only those two are counted for
 * `aka status`: a body that threw or outran the watchdog. Declining to decide
 * is an ordinary answer and is not counted. The count is asked for once per
 * run, after `emit` has settled and before `process.exit(0)`, so it never
 * delays the payload — and it is taken by a DETACHED CHILD, so the exit never
 * waits on it either. The tally write is synchronous filesystem work nothing
 * can interrupt; on a wedged home it would hold this process past the host's
 * timeout, which is a deny. Neither a worker thread nor async `fs` would bound
 * that, since exiting waits on both, so the write happens in a process this
 * one does not wait for.
 *
 * THE BOUND IS WHAT YIELDS, and it is not a detail — a path it does not cover
 * is a denied tool call. The watchdog is a `setTimeout`, so it fires only when
 * the event loop gets a turn, and a body that blocks this thread cannot be
 * preempted from this thread. (`main()` is the first element of the race, so it
 * is even invoked before the timer is armed: a body that blocks before its
 * first `await` runs with no timer pending at all.) A block that clears inside
 * the host's own 10s (`hooks.json`) still emits and still exits 0 — the denial
 * needs the block to outlast the HOST, not merely the watchdog.
 *
 * Two blocking stretches sit on the capture path and compose. `openLocalDatabase`
 * is synchronous `node:sqlite`, and its `PRAGMA busy_timeout = 2000` is charged
 * PER contended statement rather than once per open — the migration probe, the
 * repository prepares and every later write each pay it, and the PreToolUse
 * body loops a capture per scannable field, so the reachable total is a
 * multiple of 2s, not 2s. (Three processes share one `aka.db` by design.) §5's
 * fast-path `scan()` is the other: in-process and synchronous whenever the
 * effective ruleset carries no pulled or custom regex rule.
 *
 * `emit` is outside the race as well, so a full or stalled pipe has no deadline
 * at all — and on that one path the closing `process.exit(0)` is never reached
 * either, since `emit` settles only on stdout's completion callback or its
 * error event. Bounding any of this needs the work moved off the thread — §5's
 * own argument — not a longer timer here.
 *
 * `watchdogMs` is a parameter so those timing properties can be driven in
 * milliseconds rather than seconds, and `countFailOpen` so the counting can be
 * observed without starting a process; every shipped hook takes both defaults.
 *
 * Never rejects, and never returns to its caller.
 */
export async function runHookFailOpen(
  main: () => Promise<unknown>,
  failOpen: unknown,
  watchdogMs: number = WATCHDOG_MS,
  countFailOpen: () => void = spawnFailOpenCount,
): Promise<never> {
  let output: unknown = failOpen;
  let failed = false;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const decided = await Promise.race([
      main(),
      new Promise<typeof WATCHDOG_FIRED>((resolve) => {
        watchdog = setTimeout(() => {
          resolve(WATCHDOG_FIRED);
        }, watchdogMs);
      }),
    ]);
    if (decided === WATCHDOG_FIRED) failed = true;
    else if (decided !== undefined) output = decided;
  } catch {
    // Fail-open: never break the user's session. `output` is still `failOpen`.
    failed = true;
  } finally {
    // Cleared rather than left pending: a live timer would hold the event loop
    // open past the emit below on a fast path that never raced it.
    if (watchdog !== undefined) clearTimeout(watchdog);
  }
  try {
    await emit(output);
  } catch {
    // stdout is gone; exiting 0 is all that is left to try.
  }
  if (failed) {
    // Guarded here as well as inside the default: a throw at this point would
    // skip the exit below and reject the entry's top-level await, which exits
    // non-zero — a deny on this host.
    try {
      countFailOpen();
    } catch {
      // A fail-open that cannot be counted is still a fail-open.
    }
  }
  process.exit(0);
}

/**
 * Start the detached child that counts one fail-open exit, and return without
 * waiting on it.
 *
 * `detached` + `unref()` is what lets the child outlive a hook that exits on
 * the next line. The child resolves the home and writes the tally itself, so
 * nothing that can stall runs in the hook process.
 *
 * NEVER THROWS. It runs between the payload and the exit.
 */
export function spawnFailOpenCount(
  scriptUrl: URL = new URL(FAIL_OPEN_COUNT_SCRIPT_NAME, import.meta.url),
): void {
  try {
    const child = spawn(process.execPath, [fileURLToPath(scriptUrl)], {
      detached: true,
      stdio: 'ignore',
    });
    // MANDATORY, not defensive. libuv reports some spawn failures (EAGAIN,
    // EMFILE, EACCES, ENOENT) by emitting 'error' on a LATER tick rather than by
    // throwing, and an unhandled 'error' on an EventEmitter is rethrown as an
    // uncaughtException — a non-zero exit, and so a deny, if it lands first.
    child.on('error', () => {
      // Nothing to do about a count that could not be started.
    });
    child.unref();
  } catch {
    // A count that cannot be started is a lost count, never a denied call.
  }
}

// Base event metadata every Antigravity hook can derive from its stdin payload:
// the conversation id and the repo slug. Repo is resolved from the first
// `workspacePaths` entry, falling back to the hook process's own cwd. Returns
// undefined when nothing could be derived, so callers keep passing the optional
// metadata through unchanged. Per-hook fields (filePath, toolName, …) are
// layered on by the caller.
//
// The slug stays the FIRST root's even where `captureScopeKey` keys the same
// event by another repository: `repo` rides the published event metadata, and
// what a machine attachment sends must not change. It is read through
// `resolveRepoAttribution`, the memoised walk the key shares, so the first root
// is walked once however many times this hook asks about it. `repo` is exactly
// what `resolveRepo` returned here before.
export function baseMetadata(input: Record<string, unknown>): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = getString(input, 'conversationId');
  if (sessionId) metadata.sessionId = sessionId;
  const repo = resolveRepoAttribution(primaryWorkspacePath(input) ?? process.cwd()).repo;
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

/**
 * Every workspace root the payload names, in order, each once. Entries that are
 * not non-empty strings are skipped, the same leniency `primaryWorkspacePath`
 * applies to the first.
 */
function workspaceRoots(input: Record<string, unknown>): string[] {
  const paths = input.workspacePaths;
  if (!Array.isArray(paths)) return [];
  const roots: string[] = [];
  for (const entry of paths) {
    if (typeof entry === 'string' && entry !== '' && !roots.includes(entry)) roots.push(entry);
  }
  return roots;
}

/**
 * The scope key for an event in this session: the canonical `host/owner/repo`
 * of the remote of the checkout the event belongs to, or undefined.
 *
 * Antigravity hands every hook ALL of the session's roots, and one session can
 * span a work repo and a personal one. Keying by the first root, as
 * `baseMetadata`'s slug does, would key a write into the second root by the
 * first. That would forward personal content from a work-first session, or
 * hold back work content from a personal-first one. So:
 *
 *   - an ABSOLUTE `targetPath` keys by the checkout that holds that path,
 *     found by walking up from the path itself. The roots are not consulted,
 *     whether or not the path lies under one: a clone or submodule nested in
 *     a root is its own checkout with its own key, a root that is a plain
 *     folder of clones has no key while the path's clone does, and a path
 *     outside every checkout, or in one with no remote, gets no key at all.
 *     It never falls back to a root's key, or a write into a personal folder
 *     from a session rooted in a work repo would leave under the work key;
 *   - a NON-EMPTY RELATIVE `targetPath` also names a location, and is keyed by
 *     where it lands. It is read against the one root there is: with exactly one
 *     root, and that root absolute, the target is resolved against it and keyed
 *     as an absolute one is, so a `..` that leaves the root lands in the
 *     checkout it really reaches, or in none. With several roots the payload
 *     does not say which one a relative target is relative to, and with a root
 *     that is itself relative there is no known location, so either gives no
 *     key, even when every root would agree on one;
 *   - otherwise (no path, as on a `run_command`, or an empty path) the event is
 *     keyed only when every root resolves to the SAME key. Roots that disagree,
 *     or a mix of keyed and keyless roots, give no key. The contract is that a
 *     scoped attachment's forward check is meant to keep a keyless event local.
 *     A single root is therefore that root's key, as a Claude Code hook keys a
 *     path-less event by its cwd.
 *
 * A relative target is never resolved against the hook's own cwd except where
 * the payload names no root at all, and then the cwd stands in as the one root,
 * as it does for the slug. Whether the host sends `TargetFile` absolute is
 * unverified against a live host (see pre-tool-use-decision.ts).
 *
 * The walk starts at the target ITSELF, not at its parent. The resolver climbs
 * by name and probes `<start>/.git` before it climbs, so one rule serves every
 * shape a target can have. A file has no `.git` of its own, so the walk reaches
 * the checkout its directory is in; a target that does not exist yet has none
 * either, and lands the same way. A directory that is a checkout's top level,
 * or a clone nested in a root, is found at the first probe, which starting at
 * the parent would skip: the nested clone would be keyed by the checkout around
 * it.
 *
 * The target is resolved first. Resolving an absolute path is lexical: it never
 * reads `process.cwd()`, and it drops `..` segments, which the walk would
 * otherwise climb back through into the checkout the path left.
 *
 * With no root in the payload, the hook process's own cwd stands in. That is
 * the fallback `baseMetadata` takes and the one the session root
 * (pre-invocation.ts) is resolved from, so a path-less event and its root agree.
 *
 * COST. Every lookup goes through `resolveRepoAttribution`, memoised per
 * directory. A target is one walk (one existence check per level up to its
 * `.git`, one config read). A path-less event shares the first root's
 * walk with `baseMetadata`, and with several roots walks each further root once.
 *
 * TOTAL. Any throw (`process.cwd()` on a deleted directory included) answers no
 * key rather than reaching `runHookFailOpen`'s catch, which would cost the
 * capture as well as the key.
 */
export function captureScopeKey(
  input: Record<string, unknown>,
  targetPath?: string,
): string | undefined {
  try {
    if (targetPath !== undefined && isAbsolute(targetPath)) {
      return resolveRepoAttribution(resolvePath(targetPath)).scopeKey;
    }
    const named = workspaceRoots(input);
    const roots = named.length > 0 ? named : [process.cwd()];
    if (targetPath !== undefined && targetPath !== '') {
      // A relative target: it names a location, read against the only root.
      const [only] = roots;
      if (roots.length !== 1 || only === undefined || !isAbsolute(only)) return undefined;
      return resolveRepoAttribution(normalize(join(only, targetPath))).scopeKey;
    }
    const [first, ...rest] = roots.map((dir) => resolveRepoAttribution(dir).scopeKey);
    return rest.every((key) => key === first) ? first : undefined;
  } catch {
    return undefined;
  }
}
