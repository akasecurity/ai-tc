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
export type ControlPlaneFailure = 'unauthorized' | 'forbidden' | 'unreachable';

/**
 * The HTTP status a client error carries, or `null` when it carries none.
 *
 * Read STRUCTURALLY — the same contract, and for the same reason, as
 * a status is read off the error rather than matched on its type. Never
 * `instanceof`: this code is bundled into every hook script while the transport
 * is a separate package, and a prototype identity that survives one bundler
 * configuration is not a thing to hang a security-visible verdict on. Never message-parsing
 * either — which is what this replaced. The sync path used to recover the status
 * with `/\b(401|403)\b/` over the error's text, joined to the client by nothing
 * but wording, and a reword there would have degraded the one outcome a human
 * must act on into the one they are meant to ignore, silently.
 *
 * Range-checked rather than merely typed as a number: the value can come from a
 * thrown response BODY the control plane did not author (a proxy, a captive portal),
 * and a `status` field that is not an HTTP status is not evidence of anything.
 *
 * EXPORTED, unlike `classifyFailure` here it feeds: `forward-policy.ts`'s
 * `isServerRejection` reads the same status for a DIFFERENT question — not
 * "what should a human do", but "did the deployment answer at all" — and must
 * agree with this module on what counts as a status rather than re-deriving it.
 */
export function statusOf(err: unknown): number | null {
  if (typeof err !== 'object' || err === null || !('status' in err)) return null;
  const { status } = err;
  if (typeof status !== 'number' || !Number.isInteger(status)) return null;
  return status >= 100 && status <= 599 ? status : null;
}

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
  switch (statusOf(err)) {
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    default:
      return 'unreachable';
  }
}
