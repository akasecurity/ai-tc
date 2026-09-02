import { DETECTION_STAYS_ON_REASON, policyFloorReason } from '@akasecurity/dashboard-ui';
import type { PolicyFloorError } from '@akasecurity/persistence';
import { BuiltinPolicyId } from '@akasecurity/schema';

// The wording a user reads when a per-detection write — the enforcement policy,
// or the enable/disable toggle — does not land.
//
// Here rather than inside the `'use server'` module for the same reason the
// settings copy is (see action-refusals.ts): every export of that module must be
// an async Server Action, so a formatter defined there is reachable only by
// performing the whole write it describes — and the refusals these exist for
// need an attached machine with a cached control-plane bundle behind it.
//
// Every one of them is kept distinguishable on purpose. They have different
// remedies — pick something stronger, raise it instead of switching it off, ask
// your administrator, reload, or the store is broken — and a reader who cannot
// tell them apart takes the wrong one.

/**
 * The organization's policy forbids the assignment that was attempted.
 *
 * The constraint itself is worded once, by the Detections views, and reused
 * here: the picker greys the option out with that sentence BEFORE the click,
 * and this is what a user sees when a write gets through anyway (a stale page,
 * a second tab, a sync that landed between render and click). Two wordings of
 * one rule is how the two moments start describing different products.
 *
 * The lead sentence is the fact the constraint alone does not carry: nothing
 * was written. Without it the reader is left to guess whether a partial change
 * landed.
 */
export function policyFloorRefusal(error: Pick<PolicyFloorError, 'floor' | 'refusal'>): string {
  return `That change was not saved. ${policyFloorReason({
    floor: error.floor,
    locked: error.refusal === 'lock',
  })}`;
}

/**
 * The organization requires the detection to keep running, so it was not
 * switched off.
 *
 * Built from the same sentence the toggle already withholds the choice with,
 * behind the same lead as the assignment refusal above — one rule, one wording,
 * and the reader learns first that nothing changed.
 *
 * A constant rather than a formatter because nothing about it varies: the
 * constraint is "the organization named this detection at all", which carries
 * no archetype to quote.
 */
export const DETECTION_STAYS_ON_REFUSAL = `That change was not saved. ${DETECTION_STAYS_ON_REASON}`;

/**
 * Whether a thrown value is the store's control-plane refusal at all.
 *
 * Read STRUCTURALLY — by `name`, never by `instanceof`. The store's error class
 * reaches this page across a bundle boundary, and a prototype identity that
 * survives one bundler configuration is not what should decide which sentence a
 * user reads: were it ever to miss, the organization's decision would be
 * reported as DETECTION_WRITE_ERROR — sending someone to fix a permission on
 * `~/.aka` they do not have, and never telling them their organization set the
 * policy.
 *
 * The name is the WHOLE test here, and that is the difference from
 * asPolicyFloorRefusal below. Its sentence quotes the archetype the
 * organization requires, so it has to validate the fields it is about to
 * format; the enable refusal quotes none of them, because a detection the
 * organization speaks for stays on whichever archetype it asked for. Demanding
 * a discriminator the sentence has no opinion about would make the refusal turn
 * on a value it never reads.
 */
export function isControlPlaneRefusal(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  return (error as Record<string, unknown>).name === 'PolicyFloorError';
}

/**
 * The two facts a floor refusal carries, or null for a failure that is not one.
 *
 * Structural for the reason isControlPlaneRefusal is, and strict on top of it:
 * the fields are validated as well as the name, because that is the half a name
 * check alone cannot do. A shape carrying the name without a usable floor would
 * otherwise format `undefined` into the sentence, and falling through to the
 * write error is the honest answer for something this cannot read.
 */
export function asPolicyFloorRefusal(
  error: unknown,
): Pick<PolicyFloorError, 'floor' | 'refusal'> | null {
  if (!isControlPlaneRefusal(error)) return null;
  const { floor, refusal } = error as Record<string, unknown>;
  if (refusal !== 'floor' && refusal !== 'lock') return null;
  // The floor is stated in the archetype vocabulary the picker offers, so it is
  // checked against that same canonical enum rather than for any string.
  const parsed = BuiltinPolicyId.safeParse(floor);
  return parsed.success ? { floor: parsed.data, refusal } : null;
}

/**
 * The request named something that is not an enforcement archetype.
 *
 * Only a stale or hand-made client produces this, so it points at a reload —
 * and it names nothing the caller sent. The value arrives as untrusted input to
 * an HTTP POST, and echoing it back would put whatever was posted on screen.
 */
export const DETECTION_POLICY_INVALID =
  'That enforcement policy is not one this machine recognises, so nothing was changed. Reload the page and try again.';

/**
 * The request named something that is not a detection.
 *
 * Its own sentence rather than the one above: a toggle carries no archetype, so
 * a message about enforcement policies would describe a control the user never
 * touched. Same shape otherwise — only a stale or hand-made client gets here,
 * the remedy is a reload, and nothing that was sent is quoted back.
 */
export const DETECTION_ID_INVALID =
  'That detection is not one this machine recognises, so nothing was changed. Reload the page and try again.';

/** The detection named by the request is not installed on this machine. */
export const DETECTION_MISSING =
  'That detection is not installed on this machine any more, so nothing was changed. Reload the page to see what is.';

/** The store could not be written at all — a fault, unlike every answer above. */
export const DETECTION_WRITE_ERROR =
  'Could not save this change to the local store. Try again, and check that ~/.aka is writable.';
