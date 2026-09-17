// GitHub Copilot stdio helpers — the only host-specific glue this adapter
// keeps. Detection, policy and persistence live in @akasecurity/plugin-sdk;
// these just move bytes between the host and the runtime.
//
// Three things differ from the Claude Code / Codex siblings, and each is
// load-bearing:
//
//  1. ONE HOST FAILS CLOSED ON ONE EVENT, and the rest fail open. Copilot CLI
//     reads a `preToolUse` hook that exits non-zero or crashes as a DENY
//     (1.0.62+); a `preToolUse` that times out is an allow (1.0.67+); every
//     other event fails open. VS Code agent mode fails open everywhere, with
//     exit 2 as its block channel. Neither host's behaviour on `preToolUse`
//     with exit 0 and EMPTY stdout has been observed on a live install — see
//     `test/fixtures/cli/README.md`, "Not measured".
//
//     So `preToolUse` runs through `runHookFailOpen`, which prints an explicit
//     allow on every path that yields, and every other event uses the siblings'
//     silent shape. That is correct under BOTH readings of the unmeasured case,
//     which is the point: it turns the two blocked probes from a gate into an
//     optimisation.
//
//     NO PATH IN THIS PACKAGE EXITS NON-ZERO, and none exits 2. Exit 2 is VS
//     Code's block channel, and reaching it by accident on the CLI is a deny.
//
//  2. THE EVENT NAME IS ON ARGV, NOT IN THE PAYLOAD. See `./event-name.ts`.
//
//  3. THERE ARE TWO PAYLOAD DIALECTS. See `./dialect.ts`. `emit` therefore
//     takes a union spanning both hosts' output shapes rather than `unknown`,
//     so a payload outside that union cannot reach the wire at all.

import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

import { type Dialect, readCwd, readSessionId } from './dialect.ts';

/**
 * The watchdog `runHookFailOpen` races the hook body against.
 *
 * `hooks.json` declares `timeoutSec: 30`, the host default. The margin between
 * 24 s and 30 s is reserved for `emit`'s awaited flush, which sits OUTSIDE the
 * race by design and is therefore unbounded on a stalled pipe. Same ratio as
 * Antigravity's 8 s under a 10 s host timeout; 30 s is more headroom, not a
 * different property.
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

// ─── The wire ────────────────────────────────────────────────────────────────

/** Copilot CLI (and cloud): `preToolUse` permission verdict. */
export interface CliPermissionOutput {
  permissionDecision: 'allow' | 'deny' | 'ask';
  permissionDecisionReason?: string;
}

/** Copilot CLI: `preToolUse` input rewrite — the executed call is replaced. */
export interface CliModifiedArgsOutput {
  modifiedArgs: Record<string, unknown>;
}

/** Copilot CLI: `postToolUse` output rewrite — what the model sees is replaced. */
export interface CliModifiedResultOutput {
  modifiedResult: Record<string, unknown>;
}

/** VS Code agent mode: `PreToolUse` deny. */
export interface VsCodePermissionOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'deny';
    permissionDecisionReason: string;
  };
}

/** VS Code agent mode: `PreToolUse` input rewrite, validated against the tool's schema. */
export interface VsCodeUpdatedInputOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow';
    updatedInput: Record<string, unknown>;
  };
  systemMessage?: string;
}

/** VS Code agent mode: the block-or-annotate channel, the only one `PostToolUse` has. */
export interface VsCodeBlockOutput {
  decision: 'block';
  additionalContext?: string;
}

/** A note for the user with no decision attached — valid on either host. */
export interface SystemMessageOutput {
  systemMessage: string;
}

/**
 * Every shape this package is allowed to put on stdout.
 *
 * `emit` takes this union rather than `unknown` for the reason Claude Code's
 * does: a payload outside it cannot reach the wire at all, so a shape neither
 * host understands is a compile error rather than a hook the host reads as
 * invalid JSON — which on the CLI's `preToolUse` is a DENY.
 *
 * `test/hook-output-shapes.test.ts` pins this in both directions: a variant
 * added here fails that test until its map names it, and a map entry naming a
 * variant this union does not carry fails to compile.
 */
export type HookOutput =
  | CliPermissionOutput
  | CliModifiedArgsOutput
  | CliModifiedResultOutput
  | VsCodePermissionOutput
  | VsCodeUpdatedInputOutput
  | VsCodeBlockOutput
  | SystemMessageOutput;

/**
 * The "carry on unchanged" payload for `preToolUse`, per dialect.
 *
 * On the CLI this is an EXPLICIT allow, because silence there is unmeasured and
 * a crash is a deny. On VS Code silence is a documented no-opinion, but printing
 * the same explicit allow costs nothing and keeps one wrapper covering both.
 *
 * Deliberately NOT a shared frozen constant: `emit` serializes whatever it is
 * handed, and a single object handed to two hosts invites someone to mutate it.
 */
export function allowPayload(dialect: Dialect): HookOutput {
  return dialect === 'vscode'
    ? {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: {},
        },
      }
    : { permissionDecision: 'allow' };
}

// Hook output protocol: write one JSON object to stdout and exit 0.
//
// On every event but `preToolUse`, writing NOTHING is the "no opinion" both
// hosts read as allow. On `preToolUse` the CLI's reading of that is unmeasured,
// so `runHookFailOpen` guarantees a payload there.
//
// The flush must be awaited: hook entries exit right after main(), and exit
// does not wait for pending pipe writes — anything past the ~64KB pipe buffer
// is dropped, the host sees invalid JSON, and on `preToolUse` that is a deny.
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
 * forwarded verbatim, which is how `preToolUse` denies. `failOpen` is the
 * event's own "carry on unchanged" payload — `allowPayload(dialect)` — and is
 * written on the three paths where no decision was reached: the body throws,
 * the body declines to decide (returns undefined), or the body outruns the
 * watchdog.
 *
 * THE BOUND IS WHAT YIELDS, and it is not a detail — a path it does not cover
 * is, on the CLI, a denied tool call. The watchdog is a `setTimeout`, so it
 * fires only when the event loop gets a turn, and a body that blocks this
 * thread cannot be preempted from this thread. (`main()` is the first element
 * of the race, so it is even invoked before the timer is armed: a body that
 * blocks before its first `await` runs with no timer pending at all.) A block
 * that clears inside the host's own 30 s (`hooks.json`) still emits and still
 * exits 0 — the denial needs the block to outlast the HOST, not merely the
 * watchdog.
 *
 * Two blocking stretches sit on the capture path and compose. `openLocalDatabase`
 * is synchronous `node:sqlite`, and its `PRAGMA busy_timeout = 2000` is charged
 * PER contended statement rather than once per open — the migration probe, the
 * repository prepares and every later write each pay it, and the `preToolUse`
 * body loops a capture per scannable field, so the reachable total is a
 * multiple of 2 s, not 2 s. (Three processes share one `aka.db` by design.) The
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
 * Base event metadata any Copilot hook can derive from its stdin payload: the
 * session id and the repo slug.
 *
 * Repo is resolved from the payload's `cwd`, falling back to the hook process's
 * own cwd. That fallback matters more here than on the sibling hosts: VS Code
 * sends `cwd` only when the hook's own entry declared one, and its spawn cwd
 * defaults to the HOME directory rather than the workspace — so on that host
 * the fallback can resolve no repo at all, which is honest and is why this
 * returns `undefined` rather than inventing one.
 */
export function baseMetadata(
  input: Record<string, unknown>,
  dialect: Dialect,
): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = readSessionId(input, dialect);
  if (sessionId) metadata.sessionId = sessionId;
  const repo = resolveRepo(readCwd(input, dialect) ?? process.cwd());
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
