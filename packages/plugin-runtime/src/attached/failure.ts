import type { ControlPlaneFailure } from '@akasecurity/persistence';
import { classifyRemoteFailure, statusOf } from '@akasecurity/remote';

/**
 * One classifier for "the control plane said no", shared by both halves of
 * attached mode.
 *
 * Policy sync and event forwarding are different requests against different
 * routes, and they FAIL DIFFERENTLY for the same credential: `GET
 * /v1/policy-bundle` is a read and carries no write-role guard, while the ingest
 * routes do. That divergence is the whole reason this lives in its own module
 * rather than inside either caller — the one thing worse than a wrong
 * remediation is the two paths reaching different ones from the same status.
 *
 * Deliberately COARSE, and deliberately about REMEDIATION rather than about
 * HTTP. Only two statuses earn their own member, because only two of them tell
 * a human something they can act on:
 *
 *   `unauthorized`  401. The credential itself is no longer accepted — revoked,
 *                   expired, or its user row is gone. Re-attaching mints a new
 *                   one and fixes it.
 *   `forbidden`     403. The credential is accepted and NOT PERMITTED: the
 *                   caller's role lost write access, the api-key is scoped away
 *                   from this route, or the account was suspended.
 *                   Re-attaching mints a credential refused identically — only
 *                   whoever administers the organization can lift it.
 *   `unreachable`   Everything else, and NOT a claim about the network: a
 *                   transport failure, a timeout, and a 500 all land here. It is
 *                   the bucket for "no verdict we are willing to name", which is
 *                   why the surfaces that render it say what they observed
 *                   rather than guessing at a cause.
 */
// Defined in @akasecurity/persistence, beside the breaker file that stores it
// and the reader a dashboard uses, for the reason that file's own docblock
// gives. Re-exported here because this is where it is PRODUCED — the classifier
// below is its only writer, and a caller of `classifyFailure` should be able to
// name its result without reaching past this module.
export type { ControlPlaneFailure };

/**
 * The status reader is the transport's own, re-exported: `forward-policy.ts`
 * reads a status for a different question than this module does, and both must
 * agree with the package that threw the error on what counts as one.
 */
export { statusOf };

/**
 * Classify a failed control-plane call. TOTAL — every input maps to a member, because
 * both callers are fail-open paths that must never re-throw.
 *
 * The default is `unreachable`, and that direction is the safe one: it is the
 * outcome that says "try again", so mistaking a refusal for it costs visibility,
 * while mistaking a transient outage for a refusal would tell a user to go and
 * ask their administrator about a control plane that was merely rebooting.
 */
export function classifyFailure(err: unknown): ControlPlaneFailure {
  // The transport's own reading, collapsed onto the three remediations this
  // surface renders: every kind that is not a credential verdict is "try again"
  // here, whatever finer name the transport gave it.
  switch (classifyRemoteFailure(err)) {
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    default:
      return 'unreachable';
  }
}
