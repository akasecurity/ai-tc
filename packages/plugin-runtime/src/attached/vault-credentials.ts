// The two vault calls an attached machine makes: which credentials it has been
// granted, and the values of the ones a tool call names. Both answer `undefined`
// on a machine that is not attached and on every fault, so a caller only ever
// has to handle "nothing to do". Values are returned to the caller and never
// written anywhere by this module.
import { dirname } from 'node:path';

import {
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type {
  AvailableCredential,
  CredentialSlug,
  ResolveCredentialsRequest,
  ResolveCredentialsResponse,
} from '@akasecurity/schema';
import { CREDENTIAL_RESOLVE_BATCH_MAX, isAttached } from '@akasecurity/schema';

import { withTimeout } from './with-timeout.ts';

/** How long a tool call waits for credential values before running with the handles as written. */
export const CREDENTIAL_RESOLVE_TIMEOUT_MS = 2000;
/** How long SessionStart waits for the list of granted credentials. */
export const AVAILABLE_CREDENTIALS_TIMEOUT_MS = 1500;

export interface VaultCredentialClient {
  listAvailableCredentials(): Promise<{ credentials: AvailableCredential[] }>;
  resolveCredentials(request: ResolveCredentialsRequest): Promise<ResolveCredentialsResponse>;
}

export interface VaultCredentialDeps {
  /** `~/.aka/data`. */
  dataDir: string;
  timeoutMs?: number;
  /** Replaces the attached client, for a test. */
  client?: VaultCredentialClient;
}

/** The attached client for this machine, or undefined when it is not attached with a usable key. */
function attachedClient(dataDir: string, timeoutMs: number): VaultCredentialClient | undefined {
  const base = dirname(dataDir);
  const settings = readWorkspaceSettings(base);
  const connection = isAttached(settings) ? settings.controlPlane : undefined;
  if (connection === undefined) return undefined;
  const state = readControlPlaneCredentialFile(settingsDirOf(base), connection);
  if (!state.usable) return undefined;
  return createRemoteClient({
    endpoint: connection.endpoint,
    apiKey: state.credential.apiKey,
    timeoutMs,
  });
}

/** The credentials granted to this machine, or undefined when not attached or on any fault. */
export async function listAvailableCredentials(
  deps: VaultCredentialDeps,
): Promise<AvailableCredential[] | undefined> {
  try {
    const timeoutMs = deps.timeoutMs ?? AVAILABLE_CREDENTIALS_TIMEOUT_MS;
    const client = deps.client ?? attachedClient(deps.dataDir, timeoutMs);
    if (client === undefined) return undefined;
    const answer = await withTimeout(client.listAvailableCredentials(), timeoutMs);
    return answer.credentials;
  } catch {
    return undefined;
  }
}

/**
 * The values of `slugs`, and why any were refused, or undefined when not
 * attached or on any fault. At most `CREDENTIAL_RESOLVE_BATCH_MAX` slugs are
 * asked for; the rest are left out of both lists.
 */
export async function resolveCredentialValues(
  deps: VaultCredentialDeps & {
    slugs: readonly CredentialSlug[];
    sessionId: string | undefined;
  },
): Promise<ResolveCredentialsResponse | undefined> {
  try {
    const slugs = [...new Set(deps.slugs)].slice(0, CREDENTIAL_RESOLVE_BATCH_MAX);
    if (slugs.length === 0) return undefined;
    const timeoutMs = deps.timeoutMs ?? CREDENTIAL_RESOLVE_TIMEOUT_MS;
    const client = deps.client ?? attachedClient(deps.dataDir, timeoutMs);
    if (client === undefined) return undefined;
    const sessionId =
      deps.sessionId === undefined || deps.sessionId === '' ? null : deps.sessionId.slice(0, 128);
    return await withTimeout(client.resolveCredentials({ slugs, sessionId }), timeoutMs);
  } catch {
    return undefined;
  }
}
