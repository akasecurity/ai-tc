import type { AttachmentMode, ConnectionRefusal, WorkspaceSettings } from '@akasecurity/schema';
import { attachmentModeOf } from '@akasecurity/schema';

import type { CredentialFileRead } from './control-plane-credential.ts';

// Which attachment mode an attach writes, decided from what is known before any
// network call.
//
// PURE. It takes the flag the user typed, the answer of the administrator's
// overlay, the credential file already on the machine and whether there is a
// terminal, and returns one decision: write a scoped or a machine-wide
// credential, ask the user, or refuse. It reads no file and no environment, so
// the same input always gives the same decision.
//
// It refuses for two reasons, both stated on `AttachModeDecision`. One is
// `--scoped` on a machine whose connection an administrator manages. The other
// is a run on a machine nobody manages, with no terminal and no flag, over
// either a credential file that is present but cannot be used or a usable
// SCOPED credential for a DIFFERENT endpoint: a machine-wide credential written
// over either by automation would widen a machine that may be scoped, with
// nobody told.
//
// It also holds the rule for the ORDER of an attach's two writes, the credential and
// the settings (writesSettingsFirst), and the judgement that rule rests on
// (mayBePersonalDevice). Pure too, and exported so every surface that attaches a
// machine can order its writes by the same rule.

/**
 * What an attach does about the mode.
 *
 *   `use`    — write `mode`. `widening` is set when that is machine-wide over a
 *              usable SCOPED credential for the same endpoint, spelled as typed
 *              or otherwise (see holdsScopedForSpelling): this attach would
 *              send what the machine has been keeping local. `why` names what
 *              chose the mode: a flag, the mode already held for this endpoint,
 *              an administrator's management of the connection, or the absence
 *              of a terminal to ask.
 *   `ask`    — nothing known settles it, so the choice is the user's to make.
 *   `refuse` — stop before any network call, for one of two reasons.
 *              `scoped-managed`: `--scoped` was asked for on a machine whose
 *              connection an administrator manages.
 *              `needs-flag`: on a machine nobody manages, there is no terminal
 *              and no flag, and the machine holds EITHER a credential file that
 *              is present but cannot be used OR a usable scoped credential for
 *              a DIFFERENT endpoint. The first may be a scoped credential
 *              written by a newer build, the second is a scoped machine being
 *              pointed elsewhere, and a machine-wide credential written over
 *              either would widen the machine silently. A managed machine with
 *              no terminal and no flag is never refused this way: it gets
 *              `use`, machine-wide, with `why: 'managed'`.
 */
export type AttachModeDecision =
  | {
      kind: 'use';
      mode: AttachmentMode;
      widening: boolean;
      why: 'flag' | 'kept' | 'managed' | 'non-interactive';
    }
  | { kind: 'ask' }
  | { kind: 'refuse'; why: 'scoped-managed' | 'needs-flag' };

/**
 * The attachment mode, by these rules in order; the first that applies decides.
 *
 * First, AN ADMINISTRATOR WHO MANAGES THE CONNECTION makes the machine
 * machine-only. `--scoped` is refused; anything else is machine-wide and nobody
 * is asked. Otherwise a user's first attach could narrow a corporate device to
 * the repositories they chose to enroll.
 *
 * Second, A FLAG decides. `--scoped` is never questioned, since it sends less,
 * and it narrows an earlier machine-wide credential. `--machine` over a scoped
 * credential for THIS endpoint, or for another spelling of it, is a widening,
 * so a caller should confirm it with the user before it goes ahead; over a
 * scoped credential for another endpoint it is never a widening.
 *
 * Third, A USABLE CREDENTIAL FOR THIS ENDPOINT keeps its mode. That is a key
 * rotation: re-attaching to the same deployment changes the key and nothing
 * else. The same endpoint is the same string, the comparison every endpoint
 * binding makes, so another spelling (a trailing slash, a host in another case)
 * reads as another deployment.
 *
 * Fourth, A CREDENTIAL FILE THAT CANNOT BE USED — malformed, unreadable,
 * untrusted, naming an unsafe endpoint, or reported as an `endpoint-mismatch`
 * (a read given a connection says so; the wide read never does, but the answer
 * is total over the type and goes through this same rule) — is asked about on a
 * terminal and refused without one. It may be a scoped credential written by a
 * newer build, and replacing it with a machine-wide one from automation would
 * widen the machine with nobody told.
 *
 * Fifth, A USABLE SCOPED CREDENTIAL FOR ANOTHER ENDPOINT is asked about on a
 * terminal and refused without one, for the same reason: automation must not
 * turn a scoped machine machine-wide by pointing it elsewhere. Only a scoped
 * credential counts here: a machine-wide one for another endpoint falls through
 * to the next rule.
 *
 * Last, otherwise — no file, or a machine-wide credential for another
 * deployment — a terminal is asked, and a run without one attaches
 * machine-wide, as every attach did before attachment modes existed.
 *
 * No I/O; never throws.
 */
export function decideAttachMode(input: {
  /** The mode the user asked for with a flag, or undefined when they gave none. */
  flag: AttachmentMode | undefined;
  /**
   * The answer of `managedScopedRefusal`: non-null exactly when an overlay locks
   * or pins the mode or pins the deployment.
   *
   * A caller MUST report `managedAttachRefusal`'s own refusals before it asks
   * for this decision, because on those machines no attach happens in any mode
   * and this function does not know it. A caller that skips that gets
   * `use` machine-wide with `why: 'managed'` for an attach that cannot go ahead.
   */
  managed: ConnectionRefusal | null;
  /**
   * The WIDE read of the credential file, with no connection passed, so a
   * credential for another endpoint arrives usable and is told apart here, by
   * value.
   */
  previous: CredentialFileRead;
  /**
   * The endpoint being attached to. Compared with the credential's as an exact
   * string, except where `widening` is judged (holdsScopedForSpelling).
   */
  endpoint: string;
  /** Whether a terminal is available to ask. */
  interactive: boolean;
}): AttachModeDecision {
  const { flag, managed, previous, endpoint, interactive } = input;
  // The mode this machine already holds FOR THIS ENDPOINT, spelled exactly, or
  // undefined. `widening` is judged more loosely (see holdsScopedForSpelling), so
  // that another spelling of a personal device's endpoint still counts as one.
  const held: AttachmentMode | undefined =
    previous.usable && previous.credential.endpoint === endpoint
      ? attachmentModeOf(previous.credential)
      : undefined;
  const use = (
    mode: AttachmentMode,
    why: Extract<AttachModeDecision, { kind: 'use' }>['why'],
  ): AttachModeDecision => ({
    kind: 'use',
    mode,
    widening: mode === 'machine' && holdsScopedForSpelling(previous, endpoint),
    why,
  });

  if (managed !== null) {
    return flag === 'scoped'
      ? { kind: 'refuse', why: 'scoped-managed' }
      : use('machine', 'managed');
  }
  if (flag !== undefined) return use(flag, 'flag');
  if (held !== undefined) return use(held, 'kept');
  if (!previous.usable && previous.reason !== 'absent') {
    return interactive ? { kind: 'ask' } : { kind: 'refuse', why: 'needs-flag' };
  }
  // `held` is undefined here, so a usable credential names another endpoint.
  if (previous.usable && attachmentModeOf(previous.credential) === 'scoped') {
    return interactive ? { kind: 'ask' } : { kind: 'refuse', why: 'needs-flag' };
  }
  return interactive ? { kind: 'ask' } : use('machine', 'non-interactive');
}

/**
 * Whether `previous` is a usable SCOPED credential for exactly `endpoint`.
 *
 * `endpoint` is compared as the string it is, the comparison every endpoint
 * binding makes, so another spelling of a deployment (a trailing slash, a host
 * in another case) is another deployment. A credential file that cannot be used,
 * a machine-wide credential, and a scoped one for another endpoint all fail it.
 *
 * It is the question of whether a scoped write replaces a personal device for
 * the same deployment: such a write is a key rotation, which is the one case
 * that may keep the enrolled list already on file instead of starting a fresh
 * one. Whether a machine-wide write is a widening is asked more loosely, by
 * holdsScopedForSpelling, so that another spelling of the endpoint counts too.
 *
 * Pass the credential as it is read just before the write: a read taken earlier
 * answers for the machine as it was then.
 *
 * No I/O; never throws.
 */
export function holdsScopedFor(previous: CredentialFileRead, endpoint: string): boolean {
  return (
    previous.usable &&
    previous.credential.endpoint === endpoint &&
    attachmentModeOf(previous.credential) === 'scoped'
  );
}

/**
 * Whether a credential read is a personal device's, or could be: a usable scoped
 * credential, for this endpoint or any other, or a file that is there but cannot
 * be used, which may be a scoped credential a newer build wrote. No file at all is
 * not, and neither is a usable machine-wide credential.
 *
 * No I/O; never throws.
 */
export function mayBePersonalDevice(read: CredentialFileRead): boolean {
  return read.usable ? attachmentModeOf(read.credential) === 'scoped' : read.reason !== 'absent';
}

/**
 * Whether an attach writes the settings before the credential. Two cases, and
 * nothing else.
 *
 * An attach writes the credential and the settings one after the other, and a
 * stop between the two leaves the first beside whatever the second would have
 * replaced. The credential goes first unless that could leave the new credential
 * beside an enrolled list or a history grant the finished attach replaces.
 *
 * A MACHINE-WIDE attach, when the credential being replaced is, or may be, a
 * personal device's (mayBePersonalDevice), or when there is no credential file
 * but the stored settings still carry an enrolled list or a history grant, which
 * this attach replaces. A deleted credential file leaves the settings so, and so
 * does a rollback that reports a file it could not read as gone.
 *
 * A SCOPED attach, when the settings carry a list or a grant for it to replace
 * and it does not keep the list (`keepsList` answers for the stored one), unless
 * the credential being replaced is a usable machine-wide one.
 *
 * `previous` is the credential file as read just before the writes, and `stored`
 * the settings in force then, overlay applied.
 *
 * No I/O. Throws only if `keepsList` does, and asks it nothing on a machine-wide
 * attach.
 */
export function writesSettingsFirst(
  mode: AttachmentMode,
  previous: CredentialFileRead,
  stored: WorkspaceSettings,
  keepsList: (stored: unknown) => boolean,
): boolean {
  const carries = stored.attachmentScope !== undefined || stored.historySyncConsent !== undefined;
  if (mode === 'machine') {
    return (
      mayBePersonalDevice(previous) || (!previous.usable && previous.reason === 'absent' && carries)
    );
  }
  const overMachineWide = previous.usable && attachmentModeOf(previous.credential) === 'machine';
  return carries && !overMachineWide && !keepsList(stored.attachmentScope);
}

/**
 * Whether `previous` is a usable SCOPED credential for `endpoint` or for another
 * spelling of it, for the widening check alone.
 *
 * LOOSER THAN holdsScopedFor, on purpose and in one direction. Two endpoints are
 * taken for one deployment when they have the same scheme, host and port, and the
 * same path once trailing slashes are trimmed, compared without regard to case,
 * a host's trailing dot ignored. So `--machine` typed with a trailing slash, or
 * with the host in another case, over a personal device attached to that
 * deployment is still a widening: a terminal confirms it, a run without one says
 * it is happening, and the enrolled list it clears is said to be cleared. Calling
 * another deployment a widening by mistake costs a question; missing one would
 * widen a personal device with nobody told. Every other comparison stays exact,
 * the enrolled list's binding included, so a list is kept only for the endpoint
 * spelled exactly as before. An endpoint that does not parse matches only itself.
 *
 * No I/O; never throws.
 */
function holdsScopedForSpelling(previous: CredentialFileRead, endpoint: string): boolean {
  return (
    previous.usable &&
    attachmentModeOf(previous.credential) === 'scoped' &&
    sameDeploymentSpelling(previous.credential.endpoint, endpoint)
  );
}

/** Whether `a` and `b` spell one deployment, by the rules holdsScopedForSpelling gives. */
function sameDeploymentSpelling(a: string, b: string): boolean {
  if (a === b) return true;
  const left = deploymentKey(a);
  return left !== undefined && left === deploymentKey(b);
}

/** `endpoint` as scheme, host, port and trimmed path, lower-cased; undefined when it does not parse. */
function deploymentKey(endpoint: string): string | undefined {
  try {
    const url = new URL(endpoint);
    const port = url.port === '' ? '' : `:${url.port}`;
    const host = url.hostname.replace(/\.$/, '');
    return `${url.protocol}//${host}${port}${url.pathname.replace(/\/+$/, '')}`.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * Whether a decision made earlier still holds against the credential file as it
 * is now.
 *
 * A decision is made from the file as it was read at one moment and acted on
 * later, and the wait between them can be long: a network round trip, and a
 * question put to a person. Something else may attach, re-attach or detach the
 * machine in that time. Writing what was settled over a different state could
 * widen a personal device, narrow a machine-wide attachment, or overwrite a file
 * a newer build wrote, with nobody asked about any of it. So the decision is put
 * again, with the same flag, endpoint and terminal, on the file as it is now
 * (`previous`), and compared with the one that was settled. The administrator's
 * answer is the caller's to pass: the one the decision was made with, so that
 * only the file is measured, or one read again after the wait, so that the
 * decision is also put under the overlay as it is then.
 *
 * It does not hold when the new decision:
 *   - refuses (the file became one that needs a flag this run did not get);
 *   - asks where the settled one did not (a usable file became one that cannot
 *     be read, or a personal device was detached, so a terminal would now be
 *     asked something it was not);
 *   - settles a different mode than `mode`; or
 *   - finds a personal device for this endpoint where no widening was agreed to.
 *
 * A widening that WAS agreed to and has since gone away is not a change. It was
 * agreed to by answering a confirmation, by typing the machine-wide flag where
 * there was no terminal to ask on, or by an administrator's management, which
 * asks nothing; what is written still sends what was agreed to.
 *
 * An agreement only the administrator gave counts only while they still manage
 * the machine when the decision is put again. A machine they have stopped
 * managing is the user's to decide, and a terminal would ask the question that
 * management skipped, so the decision does not hold there. Typing the
 * machine-wide flag with no terminal is still the answer, whoever manages the
 * machine then.
 *
 * `mode` is the mode about to be written: the settled decision's own, or the
 * answer given when the settled decision was to ask. A refusal is never settled,
 * so `settled` excludes it.
 *
 * No I/O; never throws.
 */
export function settledDecisionHolds(
  input: Parameters<typeof decideAttachMode>[0] & {
    /** The decision made before the wait, and not a refusal. */
    settled: Exclude<AttachModeDecision, { kind: 'refuse' }>;
    /** The mode about to be written. */
    mode: AttachmentMode;
  },
): boolean {
  const { settled, mode, ...inputs } = input;
  const now = decideAttachMode(inputs);
  if (now.kind === 'refuse') return false;
  if (now.kind === 'ask') return settled.kind === 'ask';
  return now.mode === mode && (!now.widening || wideningStillAgreed(settled, inputs));
}

/**
 * Whether the settled decision carries an agreement to widen a personal device
 * that still stands when the decision is put again with `now`: the flag, the
 * terminal and the administrator's answer as they are then.
 *
 * What a person agreed to, by answering a confirmation or by typing the flag
 * with no terminal to ask on, stands. What only the administrator agreed to
 * (`why: 'managed'`, which asked nobody) stands while they still manage the
 * machine, and without a terminal where the flag was typed, which answers there
 * as it would on a machine nobody manages.
 */
function wideningStillAgreed(
  settled: Exclude<AttachModeDecision, { kind: 'refuse' }>,
  now: Parameters<typeof decideAttachMode>[0],
): boolean {
  if (settled.kind !== 'use' || !settled.widening) return false;
  if (settled.why !== 'managed') return true;
  return now.managed !== null || (!now.interactive && now.flag === 'machine');
}
