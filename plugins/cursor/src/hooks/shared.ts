// Cursor stdio helpers — the only host-specific glue this adapter keeps.
// Detection, policy and persistence live in @akasecurity/plugin-sdk; these
// just move bytes between the host and the runtime.
//
// Three things are load-bearing here:
//
//  1. SILENCE IS THE NO-OPINION, AND EVERY PATH EXITS 0. Cursor runs a hook
//     that writes nothing and exits 0 as if it had allowed the action, and it
//     fails open on a crash, a timeout or output that does not parse unless
//     the entry sets `failClosed`, which `hooks.json` never does. So the
//     guarantee this module has to keep is the exit code: no path exits
//     non-zero, so no stray code can be read as a deny.
//
//  2. THIS ADAPTER NEVER EMITS AN ALLOW. `permission: "allow"` is a verdict
//     that the action runs, so printing one per clean call would pre-approve
//     what the user's own Cursor settings would have asked about.
//     `PermissionDenyOutput` carries `'deny'` alone, so an allow is a compile
//     error rather than a convention.
//
//  3. NOTICES GO TO STDERR. A warn, a store warning and a capture-only finding
//     have no confirmed model- or user-visible channel on an allowed action, so
//     they are written to stderr, which Cursor shows in its Hooks output
//     channel. Only a deny carries its own message.

import { spawn } from 'node:child_process';
import { isAbsolute, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import type { EventMetadata } from '@akasecurity/schema';

import { readEventName } from './event-name.ts';
import type { ToolCall } from './payload.ts';
import { readCwd, readSessionId, str } from './payload.ts';
import { answerAndRecord } from './recording.ts';

/**
 * The watchdog `runHookFailOpen` races the hook body against. `hooks.json`
 * registers `timeout: 30` (seconds); the margin is reserved for `emit`'s
 * awaited flush, which sits outside the race.
 */
export const WATCHDOG_MS = 24_000;

// A value no body can return, so a body that resolves `undefined` (declining
// to decide) is never mistaken for one that ran out of time.
const WATCHDOG_FIRED: unique symbol = Symbol('watchdog fired');

/** The built fail-open counting child's filename, beside the running hook. */
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
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

// ─── The wire ────────────────────────────────────────────────────────────────

/**
 * A `preToolUse` deny. The reason goes in BOTH message fields: Cursor's
 * reference says `agent_message` reaches the model and `user_message` the
 * user, and a deny is the one message that must reach both.
 */
export interface PermissionDenyOutput {
  permission: 'deny';
  user_message: string;
  agent_message: string;
}

/** A `beforeSubmitPrompt` block: the prompt is not sent. */
export interface PromptBlockOutput {
  continue: false;
  user_message: string;
}

/** Everything any hook in this package may put on stdout. */
export type HookOutput = PermissionDenyOutput | PromptBlockOutput;

export function denyOutput(reason: string): PermissionDenyOutput {
  return { permission: 'deny', user_message: reason, agent_message: reason };
}

/**
 * Write a notice to stderr. Best-effort: a closed stderr must not turn a
 * notice into a thrown hook.
 */
export function writeNotice(
  message: string,
  write: (text: string) => void = (text) => void process.stderr.write(text),
): void {
  try {
    write(`${message}\n`);
  } catch {
    // Nothing to do: the notice was advisory.
  }
}

export function emit(output: HookOutput): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };
    process.stdout.on('error', finish);
    process.stdout.write(JSON.stringify(output), finish);
  });
}

/**
 * Run a hook body under the watchdog and exit 0 whatever happens.
 *
 * A body that throws or outruns the watchdog has reached no verdict, so it
 * writes `failOpen` if one was given and nothing otherwise, and is counted in
 * the fail-open tally through a detached child so the count never holds the
 * hook up.
 */
export async function runHookFailOpen(
  main: () => Promise<HookOutput | undefined>,
  failOpen?: HookOutput,
  watchdogMs: number = WATCHDOG_MS,
  countFailOpen: () => void = spawnFailOpenCount,
): Promise<never> {
  let output: HookOutput | undefined = failOpen;
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
    failed = true;
  } finally {
    if (watchdog !== undefined) clearTimeout(watchdog);
  }
  try {
    if (output !== undefined) await emit(output);
  } catch {
    // stdout is gone; the exit code below is still the answer.
  }
  if (failed) {
    try {
      countFailOpen();
    } catch {
      // The tally is advisory.
    }
  }
  process.exit(0);
}

export function spawnFailOpenCount(
  scriptUrl: URL = new URL(FAIL_OPEN_COUNT_SCRIPT_NAME, import.meta.url),
): void {
  try {
    const child = spawn(process.execPath, [fileURLToPath(scriptUrl)], {
      detached: true,
      stdio: 'ignore',
    });
    child.on('error', () => {
      // A missing script or a refused spawn costs one uncounted fail-open.
    });
    child.unref();
  } catch {
    // Same: the tally is advisory.
  }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

export interface HookHandlerOptions {
  akaHome?: string | undefined;
  homeDir?: string | undefined;
  /**
   * Where a bounded scan's worker script lives. Defaults to the one beside the
   * running script. A location with no worker in it is how a caller drives the
   * large-input refusal without racing a slow scan.
   */
  scanWorkerUrl?: URL | undefined;
  /** Counts one partial scan in the hook fail-open tally. */
  countFailOpen?: (() => void) | undefined;
}

export function countFailOpen(count: () => void = spawnFailOpenCount): void {
  try {
    count();
  } catch {
    // The tally is advisory.
  }
}

/**
 * A hook body: the argv event token and stdin in, the payload for stdout (or
 * `undefined` for silence) out. It never exits; the entry does.
 */
export type HookHandler = (
  event: string | undefined,
  stdin: string,
  options?: HookHandlerOptions,
) => Promise<HookOutput | undefined>;

export async function runHookEntry(handler: HookHandler): Promise<never> {
  return runHookFailOpen(async () => answerAndRecord(handler, readEventName(), await readStdin()));
}

// ─── Capture attribution ─────────────────────────────────────────────────────

export function baseMetadata(input: Record<string, unknown>): EventMetadata {
  const metadata: EventMetadata = {};
  const sessionId = readSessionId(input);
  if (sessionId) metadata.sessionId = sessionId;
  const cwd = readCwd(input);
  const repo = cwd ? resolveRepoAttribution(cwd).repo : undefined;
  if (repo) metadata.repo = repo;
  const model = str(input, 'model');
  if (model) metadata.model = model;
  return metadata;
}

/**
 * The scope key a capture is stamped with: the repository of `filePath` when
 * it is absolute, else of the payload's working directory.
 */
export function captureScopeKey(
  input: Record<string, unknown>,
  filePath?: string,
): string | undefined {
  try {
    if (filePath !== undefined && isAbsolute(filePath)) {
      return resolveRepoAttribution(normalize(filePath)).scopeKey;
    }
    const cwd = readCwd(input);
    return cwd === undefined ? undefined : resolveRepoAttribution(cwd).scopeKey;
  } catch {
    return undefined;
  }
}

/** Cursor's agent tools that write a file. */
export const FILE_WRITERS: ReadonlySet<string> = new Set([
  'Write',
  'StrReplace',
  'MultiEdit',
  'EditNotebook',
  'Delete',
]);

export function callKind(toolName: string): 'code_change' | 'tool_use' {
  return FILE_WRITERS.has(toolName) ? 'code_change' : 'tool_use';
}

/**
 * The scope key for a tool call: a file write by the file it targets when that
 * path is absolute, every other call by the payload's working directory.
 */
export function callScopeKey(
  kind: 'code_change' | 'tool_use',
  input: Record<string, unknown>,
  call: ToolCall,
): string | undefined {
  if (kind !== 'code_change') return captureScopeKey(input);
  const target = str(call.args, 'file_path') ?? str(call.args, 'path');
  return target !== undefined && isAbsolute(target)
    ? captureScopeKey(input, target)
    : captureScopeKey(input);
}
