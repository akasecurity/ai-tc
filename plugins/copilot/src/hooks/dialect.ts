/**
 * Which of the two payload dialects a hook was handed.
 *
 * One package covers two hosts that share a hooks FILE format and share almost
 * nothing else about what they send:
 *
 *  - **Copilot CLI** (and the cloud coding agent, which speaks the same wire)
 *    sends flat camelCase: `{ sessionId, timestamp, cwd, toolName, toolArgs }`.
 *    Every recorded payload in `test/fixtures/cli/` has that shape. The one
 *    snake_case key at the top level of any of them is `stop_hook_active`, on
 *    `agentStop`.
 *  - **VS Code agent mode** sends flat snake_case with a self-describing
 *    envelope: `{ hook_event_name, timestamp, session_id?, transcript_path?,
 *    cwd?, tool_name, tool_input }`.
 *
 * The two tool vocabularies do not overlap either (`bash` against
 * `run_in_terminal`), which is why everything downstream takes the dialect as a
 * parameter and keeps two tables rather than one merged one: a merged table
 * would let a payload from one host be scanned under the other host's field
 * names and report success having read nothing.
 *
 * DETECTION ORDER, and why it is this order:
 *
 *  1. `hook_event_name` present and a string ⇒ `vscode`. It is the one field VS
 *     Code sends on EVERY event, so it is the only single-field test that is
 *     total over that host.
 *  2. else `sessionId` ⇒ `cli`; `session_id` ⇒ `vscode`. The casing of the
 *     session key is the next most reliable signal, and the CLI stamps
 *     `sessionId` on all eight recordings.
 *  3. else `undefined` — no opinion. The caller reads that as an explicit allow
 *     on `preToolUse` (this host denies on a crash) and silence elsewhere.
 *
 * Note the asymmetry in step 2 and keep it: `session_id` answers `vscode`
 * because the CLI never spells it that way, but a VS Code payload that somehow
 * lacked `hook_event_name` AND `session_id` falls through to `undefined` rather
 * than being guessed at. Guessing here means scanning the wrong fields.
 */

import { getString } from './shared.ts';

export type Dialect = 'cli' | 'vscode';

export function detectDialect(payload: Record<string, unknown>): Dialect | undefined {
  if (getString(payload, 'hook_event_name') !== undefined) return 'vscode';
  if (getString(payload, 'sessionId') !== undefined) return 'cli';
  if (getString(payload, 'session_id') !== undefined) return 'vscode';
  return undefined;
}

/** The tool call a PreToolUse/PostToolUse payload describes, in either dialect. */
export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

// The envelope key each dialect uses for the fields both hosts carry. A table
// rather than a branch per reader, so a third dialect is one row rather than a
// sweep — and so each reader below is provably reading the same key set.
const ENVELOPE = {
  cli: { session: 'sessionId', cwd: 'cwd', toolName: 'toolName', toolArgs: 'toolArgs' },
  vscode: { session: 'session_id', cwd: 'cwd', toolName: 'tool_name', toolArgs: 'tool_input' },
} as const satisfies Record<Dialect, Record<string, string>>;

/**
 * The tool call, or `undefined` when the payload carries none — so the caller
 * fails open rather than scanning nothing and reporting success.
 *
 * An absent or non-object args bag becomes `{}` rather than `undefined`: a tool
 * call with a name and no arguments is a real thing to have an opinion about
 * (there is simply nothing in it to scan), while a call with no NAME is one
 * this adapter cannot look up a field table for.
 */
export function readToolCall(
  payload: Record<string, unknown>,
  dialect: Dialect,
): ToolCall | undefined {
  const keys = ENVELOPE[dialect];
  const name = getString(payload, keys.toolName);
  if (name === undefined || name === '') return undefined;
  const args = payload[keys.toolArgs];
  return {
    name,
    args: typeof args === 'object' && args !== null ? (args as Record<string, unknown>) : {},
  };
}

/** The session id, in whichever casing this dialect spells it. */
export function readSessionId(
  payload: Record<string, unknown>,
  dialect: Dialect,
): string | undefined {
  return getString(payload, ENVELOPE[dialect].session);
}

/**
 * The workspace directory.
 *
 * Both dialects spell it `cwd`, but VS Code sends it only when the hook's own
 * entry declared one (its spawn cwd otherwise defaults to the home directory,
 * which is emphatically not the workspace), so this is optional on that host in
 * a way it is not on the CLI. Callers fall back to the hook process's own cwd.
 */
export function readCwd(payload: Record<string, unknown>, dialect: Dialect): string | undefined {
  return getString(payload, ENVELOPE[dialect].cwd);
}
