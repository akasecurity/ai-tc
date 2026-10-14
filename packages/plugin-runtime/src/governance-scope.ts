// Where the organization's model policy applies.
//
// An organization can prohibit models, and the model-guard sites in the host
// plugins refuse one: on a prompt turn, a subagent spawn and a model switch.
// This module holds the question such a site asks once it has decided, on the
// organization's list, to refuse: does that refusal apply to the event in hand?
// It is meant to be asked only then, so an allowed call pays nothing for it.
//
// WHAT THIS DOES NOT COVER. Detections, the actions they resolve to, and the
// organization's raise-only policies and keyword rules come from the policy
// bundle, which is the same on every attachment. The port's `getPolicyBundle()`
// takes no event, and the runtime reads the bundle once to build detection, so
// the detections it carries apply to every event on the machine, whatever this
// answers.

/**
 * What a gateway may offer to say whether the organization's governance applies
 * to one event.
 *
 * A CAPABILITY, not a member of the DataGateway port. A gateway that does not
 * offer it is governed, which is what every gateway was before it existed. That
 * covers the local gateway: a standalone machine holds no organization list, so
 * a site there never gets as far as asking. It also covers a gateway another
 * program builds over the same port, and the stubs a test hands a site. The
 * attached gateway offers it, and answers from the attachment it already holds.
 */
export interface GovernanceScope {
  /**
   * Whether the organization's governance (its prohibited models) applies to an
   * event keyed `scopeKey`. The key is the repository key of the directory the
   * event came from, or undefined when that directory is in no repository a key
   * can name.
   *
   * Total, O(1), no I/O: a site asks it on a decision path the user waits on.
   */
  governanceAppliesTo(scopeKey: string | undefined): boolean;
}

/**
 * Whether `gateway` offers GovernanceScope.
 *
 * Typed on any object, unlike the port's own guards, which take a DataGateway. A
 * model-guard site holds a narrowed view of its gateway (a Pick of the members it
 * calls), which a DataGateway parameter would refuse; narrowing keeps that view.
 *
 * It reads the member, so a hostile getter throws out of here.
 * governanceApplies is the total form, and the one a site is meant to call.
 */
export function offersGovernanceScope<G extends object>(
  gateway: G,
): gateway is G & GovernanceScope {
  return typeof (gateway as Partial<GovernanceScope>).governanceAppliesTo === 'function';
}

/**
 * The one question a model-guard site asks once it has decided to refuse: does
 * the organization's governance apply to this event?
 *
 *   no capability           — true. Governed, as every gateway was before the
 *                             capability existed.
 *   the capability answers  — its answer, and only an exact `true` governs.
 *   the capability throws   — false, and so does one whose member cannot be
 *                             read. The model policy refuses on knowledge, never
 *                             on ignorance, and an answer that could not be had
 *                             is not knowledge.
 *
 * THE TWO FAILURES POINT OPPOSITE WAYS, on purpose. A gateway with no
 * capability is governed, so its absence de-enforces nothing. A gateway that
 * offers the capability and cannot answer is not governed, so the prohibited
 * model is allowed: a broken capability de-enforces everything this question
 * covers, at every site that asks it, and nothing at the site records that the
 * question could not be answered. The direction is chosen, not an oversight: an
 * unreadable or empty scope governs nothing, and a refusal needs an answer that
 * was actually had.
 *
 * The `catch` is unreachable with the attached gateway this package ships. Its
 * `governanceAppliesTo` answers through `verdictFor`, whose own guard turns any
 * fault into the not-governed answer, so that gateway returns a boolean and
 * never throws. The path is open to a gateway another program builds over the
 * same port.
 *
 * Total: it never throws.
 */
export function governanceApplies(gateway: object, scopeKey: string | undefined): boolean {
  try {
    if (!offersGovernanceScope(gateway)) return true;
    // Read as `unknown`, so only an exact `true` governs. The compiler holds a
    // TypeScript implementation to a boolean; nothing holds every one to it.
    const answer: unknown = gateway.governanceAppliesTo(scopeKey);
    return answer === true;
  } catch {
    // Not governed, and unrecorded: the asymmetry the docblock names.
    return false;
  }
}
