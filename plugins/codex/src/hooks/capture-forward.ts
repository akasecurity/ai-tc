import {
  checkSessionHold,
  readHookCaptureSettings,
  toolOutputForwardFor,
} from '@akasecurity/plugin-runtime';

import type { PreToolUseOutput } from './pre-tool-use-decision.ts';
import { captureScopeKey, getString } from './shared.ts';

/**
 * The forward mark PostToolUse sets on one tool's output (`toolOutputForwardFor`),
 * keyed as the capture is: by the file it names, else the session's cwd, and
 * never for an apply_patch result, which carries no repository key.
 */
export function toolOutputForward(
  dataDir: string,
  input: Record<string, unknown>,
  toolName: string | undefined,
  filePath: string | undefined,
): { maxChars: number } | undefined {
  const repoKey = toolName === 'apply_patch' ? undefined : captureScopeKey(input, filePath);
  return toolOutputForwardFor(readHookCaptureSettings(dataDir), repoKey);
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
): Promise<Extract<
  PreToolUseOutput,
  { hookSpecificOutput: { permissionDecision: 'deny' } }
> | null> {
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

/** Emits the refusal for a held session and answers true, or answers false to go on. */
export async function denyIfSessionHeld(
  dataDir: string,
  input: Record<string, unknown>,
  emit: (output: unknown) => Promise<void>,
): Promise<boolean> {
  const held = await sessionHoldDenial(dataDir, getString(input, 'session_id'));
  if (held === null) return false;
  await emit(held);
  return true;
}
