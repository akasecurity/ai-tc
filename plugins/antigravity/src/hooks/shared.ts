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
//     `runHookFailOpen`, which always writes an explicit host-shaped allow
//     payload before exiting 0, on every path including a throw.
//
//  2. THE PAYLOAD IS camelCase AND NESTS THE TOOL CALL. Antigravity sends
//     `{ toolCall: { name, args }, conversationId, workspacePaths, … }` where
//     Claude Code and Codex send flat snake_case (`tool_name`, `tool_input`,
//     `session_id`, `cwd`). `workspacePaths` is an ARRAY — there is no `cwd`.

import { resolveRepo } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

// The host kills a hook that outruns its `timeout` (SIGTERM) and aborts the
// turn. Because a killed hook never prints, that reads as a deny too — so the
// hook races its own watchdog and emits the fail-open payload first. Kept
// comfortably under the 10s registered in hooks.json.
const WATCHDOG_MS = 8_000;

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
 * Run a hook body and guarantee the host sees a valid, permissive payload.
 *
 * This is the fail-open rule (Architecture principles §1) expressed for a host
 * that fails CLOSED. `failOpen` is the event's own "carry on unchanged" payload
 * — `{ decision: 'allow' }` for PreToolUse, `{}` for the rest. It is written
 * when the body throws, when the body declines to decide (returns undefined),
 * and when the body outruns the watchdog.
 *
 * Never rejects; never returns — it exits the process.
 */
export async function runHookFailOpen(
  main: () => Promise<unknown>,
  failOpen: unknown,
): Promise<never> {
  let output: unknown = failOpen;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  try {
    const decided = await Promise.race([
      main(),
      new Promise<undefined>((resolve) => {
        watchdog = setTimeout(() => {
          resolve(undefined);
        }, WATCHDOG_MS);
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

// Base event metadata every Antigravity hook can derive from its stdin payload:
// the conversation id and the repo slug. Repo is resolved from the first
// `workspacePaths` entry, falling back to the hook process's own cwd. Returns
// undefined when nothing could be derived, so callers keep passing the optional
// metadata through unchanged. Per-hook fields (filePath, toolName, …) are
// layered on by the caller.
export function baseMetadata(input: Record<string, unknown>): EventMetadata | undefined {
  const metadata: EventMetadata = {};
  const sessionId = getString(input, 'conversationId');
  if (sessionId) metadata.sessionId = sessionId;
  const repo = resolveRepo(primaryWorkspacePath(input) ?? process.cwd());
  if (repo) metadata.repo = repo;
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}
