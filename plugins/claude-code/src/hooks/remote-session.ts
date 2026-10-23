// Whether this hook runs for a Remote Control session. The host sets
// CLAUDE_CODE_BRIDGE_SESSION_ID on its own subprocess environment only while a
// Remote Control connection is active; nothing in the hook payload says so.
export function isRemoteControlSession(): boolean {
  const value = process.env.CLAUDE_CODE_BRIDGE_SESSION_ID;
  return value !== undefined && value !== '';
}

/** The rule a protected-path match raises; see protected-path-fields.ts. */
export const PROTECTED_PATH_RULE_ID = 'command-risk/protected-path-access';

export const REMOTE_PROTECTED_PATH_NOTE =
  'This session is connected through Remote Control, where a protected path is blocked instead of flagged. Use the path from a local session, remove it from protectedPaths in ~/.aka/settings/settings.json, or grant an exception below.';
