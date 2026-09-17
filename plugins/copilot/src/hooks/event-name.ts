/**
 * Which event a hook process was invoked for.
 *
 * It comes from **argv, always** — never from the payload. Seven of the eight
 * recorded CLI payloads carry no event name at all
 * (`test/fixtures/cli/README.md`: `hookName` is present on `permissionRequest`
 * and absent from the other seven), so a dispatcher keyed on the payload could
 * not tell them apart. The one field that does exist on one event is therefore
 * the wrong thing to read: two code paths for one fact is the defect, and the
 * path that works on one event in eight would be the one nobody notices is
 * broken.
 *
 * `hooks.json` puts the event name on each command's own argv as a literal
 * token, so `process.argv[2]` is the whole of it.
 *
 * An argv that names nothing this build knows returns `undefined`, which the
 * caller reads as "no opinion" — an explicit allow on `preToolUse` (this host
 * denies on a crash) and silence everywhere else.
 *
 * CONSEQUENCE FOR `build-info.ts`: the Claude Code / Codex / Antigravity
 * siblings pass their plugin manifest path as `argv[2]`. Here that slot is
 * taken, so the manifest moves to `argv[3]`.
 */

/**
 * The fifteen file-configurable Copilot CLI events.
 *
 * Recorded, not copied from a vendor page: a hooks file naming exactly these
 * fifteen was loaded by CLI 1.0.83 without complaint, while the schema's other
 * two (`postResult`, `prePRDescription`) were logged as unknown. See
 * `test/fixtures/cli/README.md`, "Accepted event names".
 */
export const CLI_EVENTS = [
  'sessionStart',
  'sessionEnd',
  'userPromptSubmitted',
  'userPromptTransformed',
  'preToolUse',
  'postToolUse',
  'postToolUseFailure',
  'preMcpToolCall',
  'agentStop',
  'subagentStart',
  'subagentStop',
  'errorOccurred',
  'preCompact',
  'permissionRequest',
  'notification',
] as const;

/**
 * The eight PascalCase events VS Code's agent-mode hook harness fires.
 *
 * DOC-DERIVED, not recorded. No live VS Code session has produced one of these
 * in this repository; see `test/fixtures/vscode-provisional/README.md`.
 */
export const VSCODE_EVENTS = [
  'SessionStart',
  'UserPromptSubmit',
  'PreToolUse',
  'PostToolUse',
  'PreCompact',
  'SubagentStart',
  'SubagentStop',
  'Stop',
] as const;

export type CliEventName = (typeof CLI_EVENTS)[number];
export type VsCodeEventName = (typeof VSCODE_EVENTS)[number];
export type HookEventName = CliEventName | VsCodeEventName;

// Frozen at module load so a later mutation of the arrays cannot widen what is
// accepted. The two vocabularies do not collide: every CLI name is camelCase
// and every VS Code name is PascalCase, so one set answers for both.
const KNOWN = new Set<string>([...CLI_EVENTS, ...VSCODE_EVENTS]);

/** Whether a string names an event this build dispatches. */
export function isHookEventName(value: string | undefined): value is HookEventName {
  return value !== undefined && KNOWN.has(value);
}

/**
 * The event this process was invoked for, or `undefined` when argv names none.
 *
 * `argv` is a parameter so the whole of this unit-tests without a hook process;
 * every shipped entry passes `process.argv`.
 */
export function readEventName(argv: readonly string[] = process.argv): HookEventName | undefined {
  const token = argv[2];
  return isHookEventName(token) ? token : undefined;
}
