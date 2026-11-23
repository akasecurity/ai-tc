/**
 * Which event a hook process was started for.
 *
 * `hooks.json` passes the event token as `argv[2]` (`argv[0]` is node and
 * `argv[1]` the script), and Cursor also stamps `hook_event_name` on every
 * payload. A handler checks both against the events it is registered for, so a
 * manifest that wired a script to the wrong event is caught by either one.
 *
 * An absent or unrecognised token answers `undefined`, which is NOT a decline:
 * the token exists to catch a miswired manifest, and a hook started with no
 * token at all still has its payload in front of it.
 */

/** The agent hook events Cursor documents. */
export const CURSOR_EVENTS = [
  'sessionStart',
  'sessionEnd',
  'preToolUse',
  'postToolUse',
  'postToolUseFailure',
  'subagentStart',
  'subagentStop',
  'beforeShellExecution',
  'afterShellExecution',
  'beforeMCPExecution',
  'afterMCPExecution',
  'beforeReadFile',
  'afterFileEdit',
  'beforeSubmitPrompt',
  'preCompact',
  'stop',
  'afterAgentResponse',
  'afterAgentThought',
] as const;

export type HookEvent = (typeof CURSOR_EVENTS)[number];

const KNOWN: ReadonlySet<string> = new Set<string>(CURSOR_EVENTS);

/** The event token on argv, or `undefined` when there is none this build knows. */
export function readEventName(argv: readonly string[] = process.argv): HookEvent | undefined {
  const token = argv[2];
  return token !== undefined && KNOWN.has(token) ? (token as HookEvent) : undefined;
}

/**
 * Whether a hook registered for `own` should handle this process: false when
 * either the argv token or the payload's `hook_event_name` names some other
 * event, true otherwise.
 */
export function isOwnEvent(
  own: HookEvent,
  argvEvent: string | undefined,
  payloadEvent: string | undefined,
): boolean {
  if (argvEvent !== undefined && argvEvent !== own) return false;
  if (payloadEvent !== undefined && payloadEvent !== own) return false;
  return true;
}
