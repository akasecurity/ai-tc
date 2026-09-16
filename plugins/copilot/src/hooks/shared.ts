// GitHub Copilot stdio helpers — the only host-specific glue this adapter
// keeps. Detection, policy and persistence live in @akasecurity/plugin-sdk;
// these just move bytes between the host and the runtime.
//
// Three things differ from the Claude Code / Codex siblings, and all three are
// load-bearing:
//
//  1. ONE EVENT FAILS CLOSED AND THE REST FAIL OPEN. On the Copilot CLI a
//     `preToolUse` hook that exits non-zero or crashes is read as a **deny**
//     (1.0.62+), while a timeout allows; every other event fails open. Whether
//     exit 0 with EMPTY STDOUT allows or denies is **not measured** — the one
//     probe that would settle it did not run (see
//     `test/fixtures/cli/README.md`, "Not measured"). So `preToolUse` prints an
//     explicit allow on every path, which is correct under BOTH readings, and
//     every other event stays silent in the sibling plugins' shape. That turns
//     the unmeasured probe from a gate into an optimisation.
//
//  2. NO PATH EVER EXITS NON-ZERO, and none exits 2. On the CLI a non-zero exit
//     from `preToolUse` denies; under VS Code exit 2 is the BLOCK channel. An
//     accidental 2 from an unhandled rejection would block a tool call by a
//     route nothing in this package ever writes to.
//
//  3. TWO DIALECTS SHARE ONE `emit`. The narrowed `HookOutput` union below
//     spans both; see `./dialect.ts` for how a payload is placed.

import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

import type { Dialect } from './dialect.ts';
import { readCwd, readSessionId } from './dialect.ts';

/**
 * The watchdog `runHookFailOpen` races the hook body against.
 *
 * `hooks.json` registers `timeoutSec: 30`, this host's documented default, and
 * this sits comfortably under it — the same ratio Antigravity's 8s keeps under
 * its 10s. The margin is reserved for `emit`'s awaited flush, which sits
 * OUTSIDE the race by design and is therefore unbounded on a stalled pipe. 30s
 * is more headroom than Antigravity's 10s; it is not a different property.
 */
export const WATCHDOG_MS = 24_000;

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
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
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

// ─── The wire ────────────────────────────────────────────────────────────────

/** The CLI's `preToolUse` verdict. `ask` is deliberately absent — see below. */
export interface CliPermissionDecisionOutput {
  // Recorded: a deny returned this way with exit 0 blocked the call.
  //
  // `ask` is a third value the host accepts and this union does not carry,
  // because it is not a third OUTCOME here: in non-interactive mode it was
  // observed resolving to `denied-no-approval-rule-and-could-not-request-from-
  // user` after a ~25s stall, i.e. a deny that costs most of the hook budget
  // first. A policy that wants a deny emits one.
  permissionDecision: 'allow' | 'deny';
  permissionDecisionReason?: string;
  systemMessage?: string;
}

/** The CLI's input rewrite. Observed to replace the executed shell command. */
export interface CliModifiedArgsOutput {
  modifiedArgs: Record<string, unknown>;
  systemMessage?: string;
}

/** The CLI's output rewrite, for `postToolUse`. Documented; not observed. */
export interface CliModifiedResultOutput {
  modifiedResult: Record<string, unknown>;
  systemMessage?: string;
}

/** VS Code's `PreToolUse` verdict and its input rewrite, which share a field. */
export interface VsCodePreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny';
    permissionDecisionReason?: string;
    // Validated against the tool's own input schema, and LAST HOOK WINS — a
    // user's or repo's own hook returning one discards this.
    updatedInput?: Record<string, unknown>;
  };
  systemMessage?: string;
}

/** VS Code's only channel on a tool RESULT: block it, or say something. */
export interface VsCodeBlockOutput {
  decision: 'block';
  additionalContext?: string;
  systemMessage?: string;
}

/** A message with no verdict attached — the warn channel on both dialects. */
export interface SystemMessageOutput {
  systemMessage: string;
}

/**
 * Everything this adapter is allowed to write to stdout.
 *
 * `emit` takes this union rather than `unknown` for the reason the Claude Code
 * sibling's does: a payload outside it then cannot reach the wire at all, and
 * a widening back to `unknown` fails `test/hook-output-shapes.test.ts` rather
 * than shipping.
 *
 * Its six shapes are the CLI's `permissionDecision`, `modifiedArgs` and
 * `modifiedResult`, VS Code's `hookSpecificOutput` and `decision`, and the
 * `systemMessage` both dialects share. That enumeration is DERIVED in the test
 * rather than remembered here — each variant is named by its one required key,
 * the count word is read out of this sentence, and both are driven against the
 * union in both directions. A seventh variant fails that test until this
 * sentence names it.
 */
export type HookOutput =
  | CliPermissionDecisionOutput
  | CliModifiedArgsOutput
  | CliModifiedResultOutput
  | VsCodePreToolUseOutput
  | VsCodeBlockOutput
  | SystemMessageOutput;

/**
 * The "carry on unchanged" payload for `preToolUse`, per dialect.
 *
 * This is the one thing on this host that must never be silence. It is a
 * FUNCTION rather than two frozen constants so a caller cannot hold a reference
 * to the object that goes on the wire and mutate it.
 *
 * `systemMessage` rides WITH the allow rather than replacing it. That is not a
 * convenience: a degradation notice returned on its own is a payload carrying
 * no verdict, which on this event is the silence the whole adapter is arranged
 * to avoid. Anything this hook wants to say, it says while allowing.
 */
export function allowFor(dialect: Dialect | undefined, systemMessage?: string): HookOutput {
  const message = systemMessage === undefined ? {} : { systemMessage };
  return dialect === 'vscode'
    ? {
        hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
        ...message,
      }
    : { permissionDecision: 'allow', ...message };
}

// Hook output protocol: write one JSON object to stdout and exit 0.
//
// The flush must be awaited: hook entries exit right after main(), and exit
// does not wait for pending pipe writes — anything past the ~64KB pipe buffer
// is dropped and the host reads a truncated object as invalid JSON.
export function emit(output: HookOutput): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };
    // Same hazard as readStdin: an unhandled 'error' on stdout (e.g. EPIPE if
    // the caller closed its end) is an uncaughtException, not a rejection —
    // resolve instead so the hook still exits 0 rather than crashing on write.
    // Deliberately never removed: a hook process exits right after, so one
    // leftover no-op listener is free.
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

/**
 * Run a hook body so the host is left with a VALID payload rather than silence.
 *
 * Not necessarily a permissive one: a body that reaches a decision has it
 * forwarded verbatim, which is how `preToolUse` denies. `failOpen` is the
 * event's own "carry on unchanged" payload — `allowFor(dialect)` — and is
 * written on the three paths where no decision was reached: the body throws,
 * the body declines to decide (returns undefined), or the body outruns the
 * watchdog.
 *
 * THE BOUND IS WHAT YIELDS, and it is not a detail — a path it does not cover
 * is a denied tool call. The watchdog is a `setTimeout`, so it fires only when
 * the event loop gets a turn, and a body that blocks this thread cannot be
 * preempted from this thread. (`main()` is the first element of the race, so it
 * is invoked before the timer is armed: a body that blocks before its first
 * `await` runs with no timer pending at all.) A block that clears inside the
 * host's own 30s (`hooks.json`) still emits and still exits 0 — the denial
 * needs the block to outlast the HOST, not merely the watchdog.
 *
 * Two blocking stretches sit on the capture path and compose. `openLocalDatabase`
 * is synchronous `node:sqlite`, and its `PRAGMA busy_timeout = 2000` is charged
 * PER contended statement rather than once per open — the migration probe, the
 * repository prepares and every later write each pay it, and the `preToolUse`
 * body loops a capture per scannable field, so the reachable total is a
 * multiple of 2s, not 2s. (Three processes share one `aka.db` by design.) The
 * fast-path `scan()` is the other: in-process and synchronous whenever the
 * effective ruleset carries no pulled or custom regex rule.
 *
 * `emit` is outside the race as well, so a full or stalled pipe has no deadline
 * at all — and on that one path the closing `process.exit(0)` is never reached
 * either, since `emit` settles only on stdout's completion callback or its
 * error event. Bounding any of this needs the work moved off the thread, not a
 * longer timer here.
 *
 * `watchdogMs` is a parameter so those timing properties can be driven in
 * milliseconds rather than seconds; every shipped hook takes the default.
 *
 * Never rejects, and never returns to its caller.
 */
export async function runHookFailOpen(
  main: () => Promise<HookOutput | undefined>,
  failOpen: HookOutput,
  watchdogMs: number = WATCHDOG_MS,
): Promise<never> {
  let output: HookOutput = failOpen;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const decided = await Promise.race([
      main(),
      new Promise<undefined>((resolve) => {
        watchdog = setTimeout(() => {
          resolve(undefined);
        }, watchdogMs);
      }),
    ]);
    if (decided !== undefined) output = decided;
  } catch {
    // Fail-open: never break the user's session. `output` is still `failOpen`.
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
  process.exit(0);
}

/**
 * Base event metadata every hook can derive from its stdin payload: the session
 * id and the repo slug.
 *
 * The repo is resolved from the payload's own `cwd`. On the CLI that is the
 * workspace and the hook process's own cwd is an acceptable fallback; under VS
 * Code the spawn's cwd defaults to the HOME DIRECTORY unless the hook entry
 * declared one, so falling back there would resolve a repo from `~` and stamp
 * every capture with whatever happens to live in the user's home. That host
 * therefore gets no fallback, and the metadata simply carries no repo.
 *
 * Returns undefined when nothing could be derived, so callers keep passing the
 * optional metadata through unchanged.
 */
export function baseMetadata(
  dialect: Dialect,
  input: Record<string, unknown>,
): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = readSessionId(dialect, input);
  if (sessionId) metadata.sessionId = sessionId;
  const cwd = readCwd(dialect, input) ?? (dialect === 'cli' ? process.cwd() : undefined);
  const repo = cwd ? resolveRepo(cwd) : undefined;
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
