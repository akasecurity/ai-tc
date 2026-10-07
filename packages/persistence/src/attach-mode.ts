import type { AttachmentMode, ConnectionRefusal } from '@akasecurity/schema';
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

/**
 * What an attach does about the mode.
 *
 *   `use`    — write `mode`. `widening` is set when that is machine-wide over a
 *              usable SCOPED credential for the same endpoint: this attach would
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
 * credential for THIS endpoint is a widening, so a caller should confirm it
 * with the user before it goes ahead; over a scoped credential for another
 * endpoint it is never a widening.
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
  /** The endpoint being attached to. Compared with the credential's as an exact string. */
  endpoint: string;
  /** Whether a terminal is available to ask. */
  interactive: boolean;
}): AttachModeDecision {
  const { flag, managed, previous, endpoint, interactive } = input;
  // The mode this machine already holds FOR THIS ENDPOINT, or undefined. It is
  // what makes `widening` true only over a credential for this endpoint: a
  // scoped credential for another endpoint leaves it undefined.
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
    widening: mode === 'machine' && held === 'scoped',
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
