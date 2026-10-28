import {
  checkSessionHold,
  readHookCaptureSettings,
  toolOutputForwardFor,
} from '@akasecurity/plugin-runtime';
import { promptRedactionMode } from '@akasecurity/plugin-sdk';

import type { PreToolUseDenyOutput } from './model-guard.ts';

/**
 * The forward mark PostToolUse sets on tool output keyed `repoKey`
 * (`toolOutputForwardFor`), unless this session's mod is running, since the
 * mod marks tool output at its own tool-result door. Undefined sets no mark.
 */
export function postToolUseForward(
  dataDir: string,
  sessionId: string | undefined,
  repoKey: string | undefined,
): { maxChars: number } | undefined {
  try {
    const forward = toolOutputForwardFor(readHookCaptureSettings(dataDir), repoKey);
    if (forward === undefined) return undefined;
    return promptRedactionMode(dataDir, sessionId) === 'in-place' ? undefined : forward;
  } catch {
    return undefined;
  }
}

/** What a held session's tool call is refused with when the deployment gives no reason. */
export const SESSION_HELD_REASON = 'Your organization has paused tool calls in this session.';

/**
 * The refusal for this tool call when the deployment holds the session, or null
 * to let the call go on. Asked only when the capture settings turn the check on,
 * and null on any fault (`checkSessionHold`).
 */
export async function sessionHoldDenial(
  dataDir: string,
  sessionId: string | undefined,
): Promise<PreToolUseDenyOutput | null> {
  try {
    const hold = await checkSessionHold({ dataDir, sessionId });
    if (!hold.held) return null;
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `AKA: ${hold.reason ?? SESSION_HELD_REASON}`,
      },
    };
  } catch {
    return null;
  }
}
