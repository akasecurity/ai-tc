import type { RemoteFailureKind } from '@akasecurity/schema';

// Naming what went wrong, for the callers that have to tell a person.
//
// This module holds no policy: it does not decide whether to retry, to warn or
// to stay quiet. It only reads an error this package threw and says which of
// the six remediations it belongs to, so that every surface reaches the same
// answer from the same failure instead of each re-deriving one from a status
// code it half-recognises.

/**
 * The HTTP status a thrown error carries, or `null` when it carries none.
 *
 * Read STRUCTURALLY — off a `status` property, never with `instanceof`. This
 * package is bundled into some callers and resolved as a separate copy by
 * others, so two `RemoteRequestError` constructors can be live at once and a
 * prototype check would answer differently depending on how the caller was
 * built. Never message-parsing either: recovering a status from wording joins
 * two packages by nothing but a string, and a reword would silently change a
 * verdict.
 *
 * Range-checked rather than merely typed as a number. The value can come from a
 * body this deployment did not author — a proxy, a captive portal — and a
 * `status` that is not an HTTP status is not evidence of anything.
 */
export function statusOf(err: unknown): number | null {
  if (typeof err !== 'object' || err === null || !('status' in err)) return null;
  const { status } = err;
  if (typeof status !== 'number' || !Number.isInteger(status)) return null;
  return status >= 100 && status <= 599 ? status : null;
}

/** The `name` a thrown error carries, or null — read structurally, like the status. */
function nameOf(err: unknown): string | null {
  if (typeof err !== 'object' || err === null || !('name' in err)) return null;
  return typeof err.name === 'string' ? err.name : null;
}

/**
 * Classify a failed control-plane call.
 *
 * TOTAL: every input maps to a member, because the callers are fail-open paths
 * that must never re-throw while deciding what to print.
 *
 * The name-carrying classes are checked before any status, because they say
 * something a status cannot. `RemoteRouteAbsent` means the deployment never had
 * the route rather than refusing the request; `RemoteRequestInvalid` was never
 * sent at all — a defect on this machine, and pointing its user at the
 * deployment would send them to look in the wrong place; `RemoteResponseInvalid`
 * is a 2xx whose body this build cannot read, which is the two ends being out of
 * step, not a deployment to try again.
 *
 * A bare 404 is NOT a verdict here. Only a route that knows what a 404 means for
 * it — the deployment predates the route — may say so, and it does that by
 * throwing `RemoteRouteAbsent` itself. Any other 404 is a wrong URL, a proxy or
 * a captive portal answering for a path it never had, and telling that person
 * to upgrade their deployment would send them to fix the wrong thing.
 *
 * `unreachable` is the default, and that direction is the safe one: it is the
 * outcome that says "try again". Mistaking a refusal for it costs a little
 * visibility, while mistaking a rebooting deployment for a refusal would tell
 * someone to go and argue with their administrator about nothing. 429 joins it
 * for the same reason — a rate limit is a "later", not a "no".
 */
export function classifyRemoteFailure(err: unknown): RemoteFailureKind {
  switch (nameOf(err)) {
    case 'RemoteRouteAbsent':
      return 'route-absent';
    case 'RemoteRequestInvalid':
      return 'invalid-request';
    case 'RemoteResponseInvalid':
      return 'rejected';
    default:
      break;
  }
  const status = statusOf(err);
  if (status === null) return 'unreachable';
  switch (status) {
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    case 429:
      return 'unreachable';
    case 404:
      return 'unreachable';
    default:
      return status >= 400 && status <= 499 ? 'rejected' : 'unreachable';
  }
}
