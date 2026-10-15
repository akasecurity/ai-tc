import {
  readBoundAttachedIdentity,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
  writeAttachedIdentity,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type { AttachedCredentialAny } from '@akasecurity/schema';
import { attachmentModeOf, isAttached } from '@akasecurity/schema';

import { SYNC_REQUEST_TIMEOUT_MS } from './policy-sync.ts';
import { withTimeout } from './with-timeout.ts';

/**
 * `skipped`  not attached with a usable scoped credential; nothing was asked.
 * `current`  the identity record already holds for this credential; nothing was asked.
 * `written`  the deployment named the key's owner and the record was written.
 * `raced`    the attachment changed while the deployment was asked; nothing was written.
 * `failed`   the request or the write failed; nothing was changed.
 */
export type IdentityRefreshOutcome = 'skipped' | 'current' | 'written' | 'raced' | 'failed';

interface ScopedAttachment {
  readonly endpoint: string;
  readonly credential: AttachedCredentialAny;
}

function scopedAttachmentOf(paths: {
  base: string;
  settingsDir: string;
}): ScopedAttachment | undefined {
  try {
    const settings = readWorkspaceSettings(paths.base);
    const connection = isAttached(settings) ? settings.controlPlane : undefined;
    if (connection === undefined) return undefined;
    const state = readControlPlaneCredentialFile(paths.settingsDir, connection);
    if (!state.usable || attachmentModeOf(state.credential) !== 'scoped') return undefined;
    return { endpoint: connection.endpoint, credential: state.credential };
  } catch {
    return undefined;
  }
}

/**
 * Ask the deployment which account this machine's scoped key belongs to, and
 * record the answer, when no identity record holds for the key. Runs in the
 * detached sync child only. The record is written only if the settings and the
 * credential, read again inside the record's lock, still name the endpoint and
 * key that were asked about. Never writes the scope record. Never throws.
 */
export async function refreshAttachedIdentity(
  paths: { base: string; settingsDir: string; dataDir: string },
  deps: { createClient?: typeof createRemoteClient | undefined } = {},
): Promise<IdentityRefreshOutcome> {
  try {
    const asked = scopedAttachmentOf(paths);
    if (asked === undefined) return 'skipped';
    if (readBoundAttachedIdentity(paths.dataDir, asked.endpoint, asked.credential) !== undefined) {
      return 'current';
    }

    const client = (deps.createClient ?? createRemoteClient)({
      endpoint: asked.endpoint,
      apiKey: asked.credential.apiKey,
      timeoutMs: SYNC_REQUEST_TIMEOUT_MS,
    });
    const who = await withTimeout(client.whoami(), SYNC_REQUEST_TIMEOUT_MS);

    const lock = { changed: false };
    const written = writeAttachedIdentity(paths.dataDir, {
      endpoint: asked.endpoint,
      apiKey: asked.credential.apiKey,
      tenantName: who.tenantName,
      userEmail: who.userEmail,
      source: 'whoami',
      stillCurrent: () => {
        const now = scopedAttachmentOf(paths);
        lock.changed =
          now?.endpoint !== asked.endpoint || now.credential.apiKey !== asked.credential.apiKey;
        return !lock.changed;
      },
    });
    if (written) return 'written';
    return lock.changed ? 'raced' : 'failed';
  } catch {
    return 'failed';
  }
}
