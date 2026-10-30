import { dirname } from 'node:path';

import {
  isForwardPaused,
  readControlPlaneCredentialFile,
  readForwardHealth,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type { SessionHoldResponse } from '@akasecurity/schema';
import { isAttached } from '@akasecurity/schema';

import { readHookCaptureSettings } from './capture-settings.ts';
import { withTimeout } from './with-timeout.ts';

/** How long a tool call waits for the deployment's answer before going ahead. */
export const SESSION_HOLD_TIMEOUT_MS = 300;

export interface SessionHoldDeps {
  /** `~/.aka/data`. */
  dataDir: string;
  sessionId: string | undefined;
  timeoutMs?: number;
  now?: () => number;
  /** Replaces the transport, for a test. */
  fetchHold?: (sessionId: string) => Promise<SessionHoldResponse>;
}

const NOT_HELD: SessionHoldResponse = { held: false };

/**
 * Whether the deployment holds this session, asked only when its capture
 * settings turn the check on. Never throws: no session, no credential, an open
 * forward breaker, a timeout, a refusal or an answer it cannot read are each
 * "not held". The answer is not counted toward the forward breaker, so a slow
 * reply here never pauses forwarding.
 */
export async function checkSessionHold(deps: SessionHoldDeps): Promise<SessionHoldResponse> {
  try {
    const { sessionId } = deps;
    if (sessionId === undefined || sessionId === '') return NOT_HELD;
    if (readHookCaptureSettings(deps.dataDir).sessionHold !== true) return NOT_HELD;
    const now = deps.now?.() ?? Date.now();
    if (isForwardPaused(readForwardHealth(deps.dataDir, now), now)) return NOT_HELD;
    const timeoutMs = deps.timeoutMs ?? SESSION_HOLD_TIMEOUT_MS;
    const fetchHold = deps.fetchHold ?? clientFetch(deps.dataDir, timeoutMs);
    if (fetchHold === undefined) return NOT_HELD;
    const answer = await withTimeout(fetchHold(sessionId), timeoutMs);
    return answer.held ? answer : NOT_HELD;
  } catch {
    return NOT_HELD;
  }
}

function clientFetch(
  dataDir: string,
  timeoutMs: number,
): ((sessionId: string) => Promise<SessionHoldResponse>) | undefined {
  const base = dirname(dataDir);
  const settings = readWorkspaceSettings(base);
  const connection = isAttached(settings) ? settings.controlPlane : undefined;
  if (connection === undefined) return undefined;
  const state = readControlPlaneCredentialFile(settingsDirOf(base), connection);
  if (!state.usable) return undefined;
  const client = createRemoteClient({
    endpoint: connection.endpoint,
    apiKey: state.credential.apiKey,
    timeoutMs,
  });
  return (sessionId) => client.getSessionHold(sessionId);
}
