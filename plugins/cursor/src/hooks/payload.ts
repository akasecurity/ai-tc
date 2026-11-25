/**
 * Reading Cursor's hook payloads.
 *
 * Every Cursor hook receives one snake_case JSON object on stdin. The fields
 * every event carries are `conversation_id`, `generation_id`, `model`,
 * `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email` and
 * `transcript_path`; `sessionStart` adds `session_id`, and the tool events add
 * `tool_name`, `tool_input`, `tool_use_id` and `cwd`.
 *
 * DOC-DERIVED. No payload in this package was recorded from a live Cursor
 * session yet; the shapes come from Cursor's published hooks reference, as the
 * payloads under `test/payloads/` restate it. Every reader here is therefore
 * tolerant: a missing or mistyped field reads as `undefined`, which the callers
 * turn into "no opinion" rather than into a guess.
 */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function str(input: Record<string, unknown>, key: string): string | undefined {
  const value = input[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * The session this event belongs to.
 *
 * `sessionStart` names it `session_id`; the other events are documented with
 * `conversation_id` only. Cursor uses one id for both — a composer
 * conversation IS the agent session — so `session_id` is read first and
 * `conversation_id` stands in for it, which keeps every capture of one
 * conversation under the root its session start opened.
 */
export function readSessionId(input: Record<string, unknown>): string | undefined {
  return str(input, 'session_id') ?? str(input, 'conversation_id');
}

/**
 * The directory the event happened in.
 *
 * The tool events carry `cwd`. `sessionStart` and `beforeSubmitPrompt` carry
 * none, only `workspace_roots`, so the first workspace root stands in for it.
 * The hook process's own `process.cwd()` is never a fallback: a user-level hook
 * in `~/.cursor/hooks.json` runs from `~/.cursor`, so it would resolve a repo
 * from the wrong directory and stamp a durable row with it.
 */
export function readCwd(input: Record<string, unknown>): string | undefined {
  const cwd = str(input, 'cwd');
  if (cwd !== undefined) return cwd;
  const roots = input.workspace_roots;
  if (!Array.isArray(roots)) return undefined;
  const first: unknown = roots[0];
  return typeof first === 'string' && first !== '' ? first : undefined;
}

/** A tool call as the hook needs it. */
export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

/**
 * The tool call on a `preToolUse` or `postToolUse` event.
 *
 * `undefined` when the payload names no tool, so the caller declines rather
 * than scanning nothing and reporting success. `tool_input` is documented as an
 * object; a JSON string that parses to one is accepted too, since the field has
 * been reported arriving as either, and anything else reads as no args
 * — a call with no scannable field, not a broken envelope.
 */
export function readToolCall(input: Record<string, unknown>): ToolCall | undefined {
  const name = str(input, 'tool_name');
  if (name === undefined) return undefined;
  return { name, args: toolArgs(input.tool_input) };
}

function toolArgs(raw: unknown): Record<string, unknown> {
  if (isRecord(raw)) return raw;
  if (typeof raw !== 'string') return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/** The event name the payload itself carries, when it carries one. */
export function readPayloadEvent(input: Record<string, unknown>): string | undefined {
  return str(input, 'hook_event_name');
}
