// The reveal decision seam: whether a vaulted value's pointer may be
// de-referenced back to raw FOR THE MODEL.
//
// One interface, one question. This build answers from the grant the user
// created (below): a value reveals exactly when an active reveal-to-model
// exception covers its identity. Any other implementation — one answering from
// centrally managed policy, say — plugs in through the same interface, same
// caller, no change at the crossing site. The decision is separated from the
// vault so no implementation ever holds key material or ciphertext: it sees
// the raw-free identity a grant is keyed on, nothing else.
//
// Every implementation must fail toward the pointer: an error while deciding
// is a deny, never a reveal and never a throw that escapes the caller's
// fail-open boundary.
import type { PointerIdentity } from '@akasecurity/schema';

import type { SqliteExceptionsRepository } from './repositories/exceptions.ts';

export type RevealDecision = { allow: true; grantId: string } | { allow: false };

export interface ExceptionPolicyProvider {
  decideReveal(identity: PointerIdentity): Promise<RevealDecision>;
}

/**
 * The user-driven provider: the grant IS the decision. Matches an active
 * reveal-to-model exception on the exact identity suppression matches on —
 * a suppression-capability grant never satisfies it, an expired/revoked/
 * use-exhausted grant stops matching by predicate, and a grant written under a
 * rotated-away fingerprint key simply no longer matches the value's current
 * identity. Reads live grant state on every call, so a revocation applies to
 * the very next crossing.
 */
export class UserGrantPolicyProvider implements ExceptionPolicyProvider {
  readonly #exceptions: SqliteExceptionsRepository;

  constructor(exceptions: SqliteExceptionsRepository) {
    this.#exceptions = exceptions;
  }

  async decideReveal(identity: PointerIdentity): Promise<RevealDecision> {
    try {
      const grant = await this.#exceptions.activeRevealGrant(
        identity.ruleId,
        identity.valueFingerprint,
        identity.fingerprintKeyVersion,
      );
      return grant === null ? { allow: false } : { allow: true, grantId: grant.id };
    } catch {
      return { allow: false };
    }
  }
}
