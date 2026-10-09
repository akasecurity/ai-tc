import type { WebChatWithholding, WorkspaceSettings } from '@akasecurity/schema';
import { attachmentModeOf } from '@akasecurity/schema';

import { readControlPlaneCredentialFile } from './control-plane-credential.ts';

/**
 * Why this machine records nothing from a web chat, or null when it records one
 * as any other machine does.
 *
 * FAILS CLOSED. A chat is recorded only on a machine known not to be a personal
 * device: one that holds no credential and no stored scope (never attached, or
 * half an attachment with nothing to forward with), or one whose credential
 * reads back machine-wide for the connection its settings name. Everything else
 * withholds:
 *
 *   - a stored scope. A scoped attach writes one beside its credential, in
 *     either order, and a detach or a machine-wide attach removes it, so it marks
 *     a personal device even while the credential beside it is still the old one;
 *   - a scoped credential;
 *   - a credential that cannot be used: unreadable, malformed, refused as
 *     untrusted, for an unsafe endpoint, or for another deployment than the one
 *     the settings name. What the machine was attached as is unknown then, and
 *     recording what a later attachment could send is the failure to avoid.
 *
 * What is withheld is never recorded, so no later attachment can send it,
 * including a machine-wide one with history sync granted. Read per call: an
 * attach, a detach and an enrollment all change it. Never throws.
 */
export function webChatWithholding(
  settingsDir: string,
  settings: Pick<WorkspaceSettings, 'controlPlane' | 'attachmentScope'>,
): WebChatWithholding | null {
  try {
    if (settings.attachmentScope !== undefined) return 'personal-device';
    const read = readControlPlaneCredentialFile(settingsDir, settings.controlPlane);
    if (read.usable) {
      return attachmentModeOf(read.credential) === 'scoped' ? 'personal-device' : null;
    }
    return read.reason === 'absent' ? null : 'unreadable-attachment';
  } catch {
    return 'unreadable-attachment';
  }
}
