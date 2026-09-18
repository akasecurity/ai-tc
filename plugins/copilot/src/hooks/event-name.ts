/**
 * Which event a hook process was started for.
 *
 * It comes from **argv, always**, and nothing else may be consulted for it.
 * Seven of the eight recorded CLI payloads carry no event name at all — only
 * `permissionRequest` sends `hookName` (see `test/fixtures/cli/README.md`) — so
 * a dispatcher keyed on the payload could not tell `sessionStart` from
 * `sessionEnd`, and one keyed on the payload SHAPE would be a second source of
 * truth for a fact argv already carries. Two code paths for one fact is the
 * defect this module exists to prevent; `hookName` is deliberately never read.
 *
 * `argv[2]` because `argv[0]` is node and `argv[1]` the script. It displaces
 * the manifest path the sibling plugins pass there — see
 * `MANIFEST_ARGV_INDEX` in `../build-info.ts`.
 *
 * An absent or unrecognised token answers `undefined`, and that is **not** a
 * decline. `pre-tool-use.ts` bails only on a token it recognises as some OTHER
 * event, so a hook started with no token at all goes on to scan and enforce
 * normally. The token exists to catch a MISWIRED manifest — one that pointed
 * this script at `sessionEnd` — rather than to gate the ordinary path, and the
 * distinction matters because those two cases want opposite answers: a hook
 * wired to the wrong event has nothing to say, while a hook whose token was
 * simply not passed still has a tool call in front of it.
 */

/**
 * The fifteen event names the Copilot CLI's file-hook loader accepts.
 *
 * Recorded, not documented: a hooks file naming exactly these fifteen loaded
 * without complaint on 1.0.83, while the schema's `postResult` and
 * `prePRDescription` were logged as unknown hook events and dropped. They are
 * therefore absent here — a hook that named one would never be spawned, so a
 * token for it could only ever arrive by mistake.
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
 * The eight PascalCase event names VS Code's agent mode fires.
 *
 * Doc-derived, not recorded — no live VS Code session produced any of these.
 * They are a deliberately separate vocabulary rather than aliases: the two
 * hosts' payload dialects differ too (see `./dialect.ts`), and collapsing the
 * names would hide which one a given token came from.
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

export type CliEvent = (typeof CLI_EVENTS)[number];
export type VsCodeEvent = (typeof VSCODE_EVENTS)[number];
export type HookEvent = CliEvent | VsCodeEvent;

const KNOWN: ReadonlySet<string> = new Set<string>([...CLI_EVENTS, ...VSCODE_EVENTS]);

/**
 * The event token on argv, or `undefined` when there is none this build knows.
 *
 * `argv` is a parameter so every branch is drivable without spawning a
 * process; the default is the real one.
 */
export function readEventName(argv: readonly string[] = process.argv): HookEvent | undefined {
  const token = argv[2];
  return token !== undefined && KNOWN.has(token) ? (token as HookEvent) : undefined;
}
