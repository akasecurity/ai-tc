import {
  checkSessionHold,
  readHookCaptureSettings,
  toolOutputForwardFor,
} from '@akasecurity/plugin-runtime';
import { promptRedactionMode } from '@akasecurity/plugin-sdk';

import type { PreToolUseDenyOutput } from './model-guard.ts';

/**
 * The forward mark PostToolUse sets on tool output keyed `repoKey`
 * (`toolOutputForwardFor`). Without a repository list it defers to this
 * session's running mod, which marks tool output at its own tool-result door;
 * with one it always marks, since only this hook knows the file the tool
 * touched. Undefined sets no mark.
 */
export function postToolUseForward(
  dataDir: string,
  sessionId: string | undefined,
  repoKey: string | undefined,
): { maxChars: number } | undefined {
  const settings = readHookCaptureSettings(dataDir);
  const forward = toolOutputForwardFor(settings, repoKey);
  if (forward === undefined || settings.toolOutput?.repos !== undefined) return forward;
  return promptRedactionMode(dataDir, sessionId) === 'in-place' ? undefined : forward;
}

/** What a held session's tool call is refused with when the deployment gives no reason. */
export const SESSION_HELD_REASON = 'Your organization has paused tool calls in this session.';

/**
 * The refusal for this tool call when the deployment holds the session, or null
 * to let the call go on. Asked only when the capture settings turn the check on,
 * and null on any fault, since `checkSessionHold` answers not held to every one.
 */
export async function sessionHoldDenial(
  dataDir: string,
  sessionId: string | undefined,
): Promise<PreToolUseDenyOutput | null> {
  const hold = await checkSessionHold({ dataDir, sessionId });
  if (!hold.held) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `AKA: ${hold.reason ?? SESSION_HELD_REASON}`,
    },
  };
}
