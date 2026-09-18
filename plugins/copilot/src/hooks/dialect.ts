/**
 * One package, two payload dialects — which is NOT the same as two hosts.
 *
 * A dialect is a payload FORMAT, and the Copilot CLI can speak both of them.
 * Its hooks reference says so plainly: "Two payload formats are supported,
 * selected by the event name used in the hook configuration" — camelCase keys
 * (`preToolUse`) give the CLI's own flat camelCase envelope, PascalCase keys
 * (`PreToolUse`) give a VS Code-compatible snake_case one. So `cli` and
 * `vscode` below name the wire shape a payload arrived in, never the program
 * that sent it.
 *
 * The CLI's camelCase envelope is `sessionId`, `timestamp`, `cwd`, plus
 * `toolName`/`toolArgs` on a tool event. The VS Code-compatible one is
 * `hook_event_name`, `session_id`, `cwd`, `tool_name`, `tool_input`. Nothing in
 * either payload names its format, so it is sniffed, and the sniff is ordered
 * so the one field the snake_case shape sends on every event decides first.
 *
 * Everything downstream takes the dialect as a PARAMETER, and the two tool
 * vocabularies are kept in separate tables: a merged one would let a tool name
 * from either format resolve against the other's field list and scan a field
 * that is not there. Those vocabularies are genuinely distinct — the same
 * reference notes that "Payloads for PascalCase `PreToolUse` report `tool_name`
 * as the Claude tool name (for example, `Bash`, not `bash`)" — but they are not
 * separated by HOST, which is why `hooks.json` registers the camelCase event
 * alone. Registering both casings there would spawn this script twice for every
 * tool call, the second time with a payload whose `Bash` matches no row in the
 * snake_case table.
 *
 * `undefined` means the envelope matched neither format, which the callers read
 * as "no opinion": nothing on stdout, on every event.
 */

export type Dialect = 'cli' | 'vscode';

/** A tool call as the hook needs it, with the dialect's spelling resolved away. */
export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function str(input: Record<string, unknown>, key: string): string | undefined {
  const value = input[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * Which dialect an envelope is in.
 *
 * 1. `hook_event_name` present as a string → `vscode`. It is the one field VS
 *    Code documents on EVERY event, so it is the strongest signal available and
 *    is checked before anything a CLI payload could also satisfy.
 * 2. else `sessionId` → `cli`; `session_id` → `vscode`. Both hosts stamp a
 *    session id on every event, in their own casing.
 * 3. else `undefined`.
 *
 * Step 1 is not redundant with step 2: VS Code's own docs say `session_id` is
 * sent "only when known", so an early-session VS Code payload can carry
 * `hook_event_name` and no session id at all.
 */
export function detectDialect(payload: unknown): Dialect | undefined {
  if (!isRecord(payload)) return undefined;
  if (typeof payload.hook_event_name === 'string') return 'vscode';
  if (typeof payload.sessionId === 'string') return 'cli';
  if (typeof payload.session_id === 'string') return 'vscode';
  return undefined;
}

/** The session id, in whichever casing this dialect spells it. */
export function readSessionId(
  dialect: Dialect,
  input: Record<string, unknown>,
): string | undefined {
  return dialect === 'cli' ? str(input, 'sessionId') : str(input, 'session_id');
}

/**
 * The working directory the event happened in.
 *
 * Both dialects spell it `cwd`, but VS Code sends it **only when the hook entry
 * declared one** — the spawn's own cwd defaults to the home directory there, so
 * the hook process's `process.cwd()` is not a usable fallback on that host and
 * the caller gets `undefined` rather than a repo resolved from `~`.
 */
export function readCwd(_dialect: Dialect, input: Record<string, unknown>): string | undefined {
  return str(input, 'cwd');
}

/**
 * The tool call on a pre/post tool event.
 *
 * Returns `undefined` when the payload carries no usable call, so the caller
 * fails open rather than scanning nothing and reporting success. An args bag
 * that is absent or not an object becomes `{}` rather than failing the read:
 * the tool NAME is what decides whether there is anything to scan, and a
 * present name with no args is a call with no scannable field, not a broken
 * envelope.
 *
 * On the CLI `toolArgs` was recorded as an object. The card notes it may also
 * arrive as a JSON **string** on some tools — unobserved, so a string is not
 * parsed here: guessing at an encoding nobody has seen would turn a shape this
 * build does not understand into a silent empty scan. It reads as no args,
 * which scans nothing and says nothing, exactly like any other unknown shape.
 */
export function readToolCall(
  dialect: Dialect,
  input: Record<string, unknown>,
): ToolCall | undefined {
  const name = dialect === 'cli' ? str(input, 'toolName') : str(input, 'tool_name');
  if (name === undefined) return undefined;
  const raw = dialect === 'cli' ? input.toolArgs : input.tool_input;
  return { name, args: isRecord(raw) ? raw : {} };
}
