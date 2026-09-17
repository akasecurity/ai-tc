/**
 * Whether an administrator lets this machine's connection move from where it is.
 *
 * TWO MECHANISMS GOVERN THE CONNECTION, AND THE SETTINGS WRITER SEES ONLY ONE. A
 * LOCK on `runMode` makes `applyOnboarding` throw on any change to the pair. A
 * PINNED `runMode` or `controlPlane` with no lock — the shape a fleet overlay
 * ships, so that no save of the user's is ever refused — is written through, and
 * then every read overlays the pin straight back over what was written. A detach
 * under such a pin reports success on a machine that goes on reading as
 * attached, and an attach to another endpoint stores a credential for a
 * deployment the settings never name again.
 *
 * So the verbs that change the connection decide against the EFFECTIVE settings,
 * whichever mechanism produced them, and do it before anything is sent, written
 * or closed. The decision lives here rather than in either surface because there
 * are two — `aka attach` / `aka detach` and the dashboard's Settings actions — and
 * both sit above this package.
 *
 * The overlay is injectable. It lives at ABSOLUTE SYSTEM paths on purpose — a
 * lock inside `~` is removable by the party being locked — so a temp home cannot
 * make a machine look managed, and cannot make a managed one look clean either.
 * `null` means unmanaged; omitted means the overlay this process reads.
 */
import type { ConnectionRefusal, ManagedSettings, WorkspaceSettings } from '@akasecurity/schema';
import { isAttached } from '@akasecurity/schema';

import { defaultDataDir } from './local-layout.ts';
import { readManagedSettings } from './managed-settings.ts';
import { readEffectiveSettings } from './settings.ts';

/** What an administrator has decided about the connection, read once. */
interface GovernedConnection {
  /** Spread into a refusal, so an unnamed administrator leaves no key behind. */
  who: { organization?: string };
  /** The settings every read reports, overlay applied. */
  settings: WorkspaceSettings;
  /** `runMode` is locked: the writer refuses any change to the pair. */
  frozen: boolean;
  /** The overlay supplies `runMode`. */
  modePinned: boolean;
  /** The overlay supplies `controlPlane`. */
  planePinned: boolean;
  /** The name the overlay gives the deployment, when it gives one. */
  pinnedLabel: string | undefined;
}

/**
 * The overlay — raw, for who pinned what — and the settings it produces, from
 * ONE read of the managed file, or null when the connection is the user's own.
 *
 * The lock and the two pins are reported apart because they govern different
 * halves: a descriptor pinned on its own must still let a standalone machine
 * attach to it, which is the managed-enrolment path rather than a conflict, and
 * only a locked or pinned MODE can put an attachment back after a detach.
 *
 * Neither read throws today — both fail open on a damaged file — and if one
 * ever does, this fails the same way: UNMANAGED rather than unusable, because a
 * typo in an administrator's payload must not stop every machine attaching.
 */
function readGovernedConnection(
  base: string,
  managedOverride: ManagedSettings | null | undefined,
): GovernedConnection | null {
  let managed: ManagedSettings | null;
  let settings: WorkspaceSettings;
  try {
    managed = managedOverride === undefined ? readManagedSettings() : managedOverride;
    settings = readEffectiveSettings(base, managed).settings;
  } catch {
    return null;
  }
  if (managed === null) return null;
  const frozen = managed.lockedFields.includes('runMode');
  const modePinned = managed.values.runMode !== undefined;
  const planePinned = managed.values.controlPlane !== undefined;
  if (!frozen && !modePinned && !planePinned) return null;
  return {
    who: managed.organization === undefined ? {} : { organization: managed.organization },
    settings,
    frozen,
    modePinned,
    planePinned,
    pinnedLabel: managed.values.controlPlane?.label,
  };
}

/**
 * The refusal no endpoint or label can get past: a locked or pinned MODE that
 * the next read would put back over whatever this machine does now.
 *
 * Attached, a detach is what would be undone. Standalone, an attach is — it
 * would be written and then read back as standalone. A pinned or locked mode of
 * `attached` with no deployment named anywhere holds neither: the machine does
 * not read as attached, and an attach to any endpoint reads back as written.
 */
function modeHold(governed: GovernedConnection): ConnectionRefusal | null {
  const { who, settings, frozen, modePinned } = governed;
  if (!frozen && !modePinned) return null;
  if (settings.runMode !== 'attached') return { reason: 'held-standalone', ...who };
  // `isAttached`, and the descriptor bound for the message.
  const held = settings.controlPlane;
  if (!isAttached(settings) || held === undefined) return null;
  return { reason: 'held-attached', ...who, endpoint: held.endpoint };
}

/**
 * Why this machine may not be attached to `endpoint`, or null when it may.
 *
 * RUN BEFORE ANY NETWORK CALL OR WRITE. An administrator who froze `runMode`, or
 * pinned a deployment, has already decided; asking a deployment to verify a key
 * or approve a device before saying so leaves a decided grant, or a stored
 * credential, behind for a deployment this machine was never going to keep.
 *
 * Attaching to the endpoint an administrator PINNED is not refused — that is the
 * enrolment path — so long as it keeps whatever name a lock freezes. Under a lock
 * with no pin the descriptor held is the user's own last choice, which is exactly
 * what the lock freezes.
 */
export function managedAttachRefusal(
  request: { endpoint: string; label?: string | undefined },
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): ConnectionRefusal | null {
  const governed = readGovernedConnection(base, managedOverride);
  if (governed === null) return null;
  const { who, settings, frozen, planePinned, pinnedLabel } = governed;

  const held = modeHold(governed);
  if (held?.reason === 'held-standalone') return held;

  const current = settings.controlPlane;
  if (!frozen && !planePinned) return null;
  if (current !== undefined && current.endpoint !== request.endpoint) {
    return { reason: 'pinned-endpoint', ...who, endpoint: current.endpoint };
  }
  // The name. Under a lock the writer refuses any change to the descriptor,
  // measured against the name every read shows — the user's own last choice or
  // the administrator's — so a different label is refused, and so is leaving it
  // off, which trades the name for the endpoint. Both would otherwise be refused
  // only after the key had been sent.
  if (frozen && current !== undefined && request.label !== current.label) {
    return request.label === undefined
      ? { reason: 'label-required', ...who }
      : { reason: 'pinned-label', ...who };
  }
  // Under a pin with no lock, only a name the ADMINISTRATOR gave is put back by
  // the next read. A name the user gave the pinned deployment is theirs, and
  // renaming it is not refused.
  if (
    planePinned &&
    pinnedLabel !== undefined &&
    request.label !== undefined &&
    request.label !== pinnedLabel
  ) {
    return { reason: 'pinned-label', ...who };
  }
  return null;
}

/**
 * Why this machine may not be detached, or null when it may.
 *
 * Refused exactly when the next read would UNDO the detach: the MODE is locked
 * or pinned, and the machine reads as attached. A pin on the descriptor alone
 * leaves `runMode` the user's — a cleared file reads back as standalone — and a
 * governed machine that does not read as attached has nothing to detach.
 *
 * RUN BEFORE ANYTHING A DETACH TOUCHES, the history window included: under a lock
 * the writer's own refusal arrives only after that window has been handed to the
 * live path, and under a pin the writer refuses nothing at all.
 */
export function managedDetachRefusal(
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): ConnectionRefusal | null {
  const governed = readGovernedConnection(base, managedOverride);
  if (governed === null) return null;
  const held = modeHold(governed);
  return held?.reason === 'held-attached' ? held : null;
}

/**
 * What a surface may OFFER: the refusal an attach or a detach from this
 * machine's current state would meet whatever is typed, or null.
 *
 * Attached, that is the detach refusal. Standalone, it is a mode held at
 * standalone. A pinned or locked DESCRIPTOR is not a hold on its own — whether an
 * attach is refused then depends on the endpoint and label typed, which only
 * `managedAttachRefusal` can judge.
 */
export function managedConnectionHold(
  base: string = defaultDataDir(),
  managedOverride?: ManagedSettings | null,
): ConnectionRefusal | null {
  const governed = readGovernedConnection(base, managedOverride);
  return governed === null ? null : modeHold(governed);
}
