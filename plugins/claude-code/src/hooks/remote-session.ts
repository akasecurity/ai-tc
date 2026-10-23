// Whether this hook runs for a Remote Control session. The host sets
// CLAUDE_CODE_BRIDGE_SESSION_ID on its own subprocess environment only while a
// Remote Control connection is active; nothing in the hook payload says so.
export function isRemoteControlSession(): boolean {
  const value = process.env.CLAUDE_CODE_BRIDGE_SESSION_ID;
  return value !== undefined && value !== '';
}
