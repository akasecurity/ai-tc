import type { ManagedSettings, SightingSharing } from '@akasecurity/schema';
import { isAttached, resolveSightingSharing } from '@akasecurity/schema';

import { readControlPlaneAttachmentMode } from './control-plane-credential.ts';
import { defaultDataDir, settingsDir } from './local-layout.ts';
import { overlayManagedSettings, readManagedSettings } from './managed-settings.ts';
import { readUserSettings } from './settings.ts';

/**
 * Whether credential sightings may leave this machine right now, read from the
 * user's settings file, the managed settings file and the attach credential.
 *
 * Every sender of credential sightings MUST call this immediately before
 * sending and send nothing unless `sharing` is true. Read live on every call.
 * Never throws: a failed read resolves to not sharing.
 *
 * `managedOverride` replaces the managed settings file; `null` reads a machine
 * with no administrator. A managed file that does not parse is read as no
 * managed file at all, as everywhere else, so a pinned `false` in a malformed
 * file does not hold and the user's own grant decides.
 */
export function readSightingSharing(
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): SightingSharing {
  try {
    const managed = managedOverride === undefined ? readManagedSettings() : managedOverride;
    const own = readUserSettings(base);
    const effective = overlayManagedSettings(own, managed);
    const attachmentMode = isAttached(effective)
      ? readControlPlaneAttachmentMode(settingsDir(base), effective.controlPlane)
      : undefined;
    return resolveSightingSharing({
      settings: own,
      managed,
      attachmentMode,
      endpoint: effective.controlPlane?.endpoint,
    });
  } catch {
    return {
      mode: 'standalone',
      managed: false,
      sharing: false,
      reason: 'standalone',
      optedIn: false,
      locked: false,
    };
  }
}
