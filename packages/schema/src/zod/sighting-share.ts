import * as z from 'zod';

import type { AttachmentMode, RemoteFailureKind } from './control-plane.ts';
import type { WorkspaceSettings } from './local.ts';
import type { ManagedSettings } from './managed.ts';

// The behaviour a user agrees to when they let this machine share credential
// sightings with the organization it is attached to. A grant recorded against
// an older version stops counting, so widening what is shared re-asks.
export const SIGHTING_SHARE_CONSENT_VERSION = 2;

// A recorded grant: when it was given, the version it was given against, and
// the deployment it was given for. Consent to share with one deployment is
// never consent to share with another.
export const SightingShareConsent = z.object({
  acknowledgedAt: z.iso.datetime(),
  version: z.number().int().positive(),
  endpoint: z.string(),
});
export type SightingShareConsent = z.infer<typeof SightingShareConsent>;

/**
 * Whether a recorded grant is in force for the deployment this machine is
 * attached to now. Absent, another version, another deployment, or no
 * deployment at all → no.
 */
export function isSightingShareConsentValid(
  consent: SightingShareConsent | undefined,
  endpoint: string | undefined,
): boolean {
  if (consent === undefined || endpoint === undefined) return false;
  return consent.version === SIGHTING_SHARE_CONSENT_VERSION && consent.endpoint === endpoint;
}

/** What a credential sighting carries. It describes this setting only. */
export const SIGHTING_SHARE_PAYLOAD_NOTE =
  'A credential sighting carries only a hash or ciphertext of the value, never the value itself.';

/** How this machine is connected: not attached, or the credential's attachment mode. */
export type SightingShareMode = 'standalone' | AttachmentMode;

/**
 * Why sharing is on or off.
 *
 *   standalone        no usable attach credential; nothing is shared
 *   managed-required  a machine-wide attachment whose managed settings pin sharing on
 *   managed-denied    the managed settings pin sharing off
 *   opted-in          the user granted the consent
 *   not-opted-in      the user has not granted the consent
 */
export type SightingShareReason =
  'standalone' | 'managed-required' | 'managed-denied' | 'opted-in' | 'not-opted-in';

export interface SightingSharing {
  mode: SightingShareMode;
  /** Sharing is required by the organization rather than chosen by the user. */
  managed: boolean;
  sharing: boolean;
  reason: SightingShareReason;
  /** The user's own grant is on file and current, whatever else applies. */
  optedIn: boolean;
  /** The user cannot change the answer on this machine. */
  locked: boolean;
  /** The organization named in the managed settings file, when it names one. */
  organization?: string;
  /** The deployment a grant must name to count; absent while standalone. */
  endpoint?: string;
}

export interface SightingSharingInput {
  /**
   * The user's OWN settings file, without the managed overlay. The overlay turns
   * a pinned `true` into a grant, which must not count as a user's opt-in on a
   * scoped attachment.
   */
  settings: WorkspaceSettings;
  managed: ManagedSettings | null;
  /** The deployment this machine is attached to, in force after the managed overlay. */
  endpoint: string | undefined;
  /** The attach credential's mode, or undefined when no usable credential is held. */
  attachmentMode: AttachmentMode | undefined;
}

/**
 * Whether credential sightings may leave this machine for the organization it
 * is attached to.
 *
 * Every sender of credential sightings MUST call this (or
 * `readSightingSharing` in @akasecurity/persistence, which reads its inputs)
 * immediately before sending, and send nothing unless `sharing` is true.
 *
 *   standalone                       → never shares
 *   managed pin `false`              → never shares; locked
 *   `machine` AND managed pin `true` → shares without asking; locked
 *   otherwise                        → shares only on the user's own grant,
 *                                      given for this deployment
 *
 * Pure; no I/O. Any throw resolves to not sharing.
 */
export function resolveSightingSharing(input: SightingSharingInput): SightingSharing {
  try {
    const { settings, managed, attachmentMode, endpoint } = input;
    const pin = managed?.values.sightingShareConsent;
    const lockListed = managed?.lockedFields.includes('sightingShareConsent') ?? false;
    const organization =
      managed?.organization === undefined ? {} : { organization: managed.organization };
    const mode: SightingShareMode = attachmentMode ?? 'standalone';
    const isManaged = mode === 'machine' && pin === true;
    const locked = lockListed || pin === false || isManaged;
    const bound = mode === 'standalone' ? undefined : endpoint;
    const optedIn = isSightingShareConsentValid(settings.sightingShareConsent, bound);
    const base = {
      mode,
      locked,
      optedIn,
      ...organization,
      ...(bound === undefined ? {} : { endpoint: bound }),
    };

    if (mode === 'standalone') {
      return { ...base, managed: false, sharing: false, reason: 'standalone' };
    }
    if (pin === false) {
      return { ...base, managed: false, sharing: false, reason: 'managed-denied' };
    }
    if (isManaged) {
      return { ...base, managed: true, sharing: true, reason: 'managed-required' };
    }
    return {
      ...base,
      managed: false,
      sharing: optedIn,
      reason: optedIn ? 'opted-in' : 'not-opted-in',
    };
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

/**
 * Whether the setup wizard asks the user about sharing: only on an attached
 * machine whose managed settings do not decide the answer.
 */
export function shouldAskSightingShare(state: SightingSharing): boolean {
  return state.mode !== 'standalone' && !state.locked;
}

/** The connection, in words. */
export function sightingShareModeLabel(mode: SightingShareMode): string {
  switch (mode) {
    case 'standalone':
      return 'standalone';
    case 'machine':
      return 'attached, machine-wide';
    case 'scoped':
      return 'attached, scoped';
  }
}

/** Why sharing is on or off, as one sentence. */
export function sightingShareReasonText(state: SightingSharing): string {
  const who = state.organization ?? 'your organization';
  switch (state.reason) {
    case 'standalone':
      return 'this machine is not attached to an organization.';
    case 'managed-required':
      return `required by ${who} on this managed machine.`;
    case 'managed-denied':
      return `turned off by ${who}.`;
    case 'opted-in':
      return 'you opted in.';
    case 'not-opted-in':
      return 'you have not opted in.';
  }
}

/**
 * The one-line summary for terminal surfaces, e.g.
 * `Credential sightings: off (standalone) — this machine is not attached to an
 * organization. A credential sighting carries only a hash or ciphertext of the
 * value, never the value itself.`
 */
export function sightingSharingLine(state: SightingSharing): string {
  return (
    `Credential sightings: ${state.sharing ? 'on' : 'off'} ` +
    `(${sightingShareModeLabel(state.mode)}) — ${sightingShareReasonText(state)} ` +
    SIGHTING_SHARE_PAYLOAD_NOTE
  );
}

/**
 * What a scan did with the credential sightings it found.
 *
 *   not-shared  nothing was sent: sharing is off, this run opted out, the
 *               machine holds no sighting key, no usable credential, or the
 *               sightings could not be prepared on this machine (`local-error`)
 *   sent        `shared` were delivered, `keptLocal` stayed on this machine
 *               because a scoped attachment does not enroll their repository or
 *               they lie outside the project, and `unsent` were not delivered
 *               because of `failure`. All three count distinct values per
 *               location class.
 */
export type CredentialSightingsOutcome =
  | { status: 'not-shared'; reason: 'sharing-off'; sharing: SightingSharing }
  | { status: 'not-shared'; reason: 'opt-out' | 'no-key' | 'no-credential' | 'local-error' }
  | {
      status: 'sent';
      shared: number;
      keptLocal: number;
      unsent: number;
      failure?: RemoteFailureKind;
    };

/** One outcome for several scans: the sends summed, else the first refusal. */
export function combineCredentialSightingsOutcomes(
  a: CredentialSightingsOutcome | undefined,
  b: CredentialSightingsOutcome | undefined,
): CredentialSightingsOutcome | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (a.status !== 'sent') return b.status === 'sent' ? b : a;
  if (b.status !== 'sent') return a;
  const failure = a.failure ?? b.failure;
  return {
    status: 'sent',
    shared: a.shared + b.shared,
    keptLocal: a.keptLocal + b.keptLocal,
    unsent: a.unsent + b.unsent,
    ...(failure === undefined ? {} : { failure }),
  };
}

const SIGHTING_FAILURE_TEXT: Record<RemoteFailureKind, string> = {
  unauthorized: 'the deployment rejected this machine’s key; re-attach with `aka attach`',
  forbidden:
    'the key is not permitted to send credential sightings; re-attach, or ask your organization admin',
  'route-absent': 'the deployment does not accept credential sightings yet',
  'invalid-request': 'this build assembled a request the contract refuses; please report it',
  rejected: 'the deployment refused the request; this build and the deployment are out of step',
  unreachable: 'control plane unreachable; the next scan sends them again',
};

function sentText(outcome: Extract<CredentialSightingsOutcome, { status: 'sent' }>): string {
  const { shared, keptLocal, unsent, failure } = outcome;
  const sharedText = `${String(shared)} shared with your organization`;
  if (failure !== undefined) {
    const reason = SIGHTING_FAILURE_TEXT[failure];
    return shared === 0
      ? `not shared — ${reason}`
      : `${sharedText}; ${String(unsent)} not sent — ${reason}`;
  }
  if (shared === 0) {
    return keptLocal === 0
      ? 'none found to share'
      : 'not shared — kept on this machine (not enrolled, or outside the project)';
  }
  return keptLocal === 0
    ? sharedText
    : `${sharedText}; ${String(keptLocal)} kept on this machine (not enrolled, or outside the project)`;
}

/** The scan footer: what this scan shared, or why it shared nothing. */
export function credentialSightingsLine(outcome: CredentialSightingsOutcome): string {
  if (outcome.status === 'sent') {
    return `Credential sightings: ${sentText(outcome)}. ${SIGHTING_SHARE_PAYLOAD_NOTE}`;
  }
  switch (outcome.reason) {
    case 'sharing-off':
      return sightingSharingLine(outcome.sharing);
    case 'opt-out':
      return notShared('forwarding was skipped for this scan');
    case 'no-key':
      return notShared('this machine has no sighting key yet; it is fetched on the next sync');
    case 'no-credential':
      return notShared(
        'no usable credential for the attached deployment; re-attach with `aka attach`',
      );
    case 'local-error':
      return notShared('they could not be prepared on this machine; the next scan tries again');
  }
}

function notShared(reason: string): string {
  return `Credential sightings: not shared — ${reason}. ${SIGHTING_SHARE_PAYLOAD_NOTE}`;
}
