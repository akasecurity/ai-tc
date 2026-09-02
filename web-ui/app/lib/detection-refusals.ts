import { policyFloorReason } from '@akasecurity/dashboard-ui';
import type { PolicyFloorError } from '@akasecurity/persistence';

// The wording a user reads when a per-detection enforcement-policy write does
// not land.
//
// Here rather than inside the `'use server'` module for the same reason the
// settings copy is (see action-refusals.ts): every export of that module must be
// an async Server Action, so a formatter defined there is reachable only by
// performing the whole write it describes — and the refusal these exist for
// needs an attached machine with a cached control-plane bundle behind it.
//
// The four are kept distinguishable on purpose. They have different remedies —
// pick something stronger, ask your administrator, reload, or the store is
// broken — and a reader who cannot tell them apart takes the wrong one.

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
 * The request named something that is not an enforcement archetype.
 *
 * Only a stale or hand-made client produces this, so it points at a reload —
 * and it names nothing the caller sent. The value arrives as untrusted input to
 * an HTTP POST, and echoing it back would put whatever was posted on screen.
 */
export const DETECTION_POLICY_INVALID =
  'That enforcement policy is not one this machine recognises, so nothing was changed. Reload the page and try again.';

/** The detection named by the request is not installed on this machine. */
export const DETECTION_POLICY_MISSING =
  'That detection is not installed on this machine any more, so nothing was changed. Reload the page to see what is.';

/** The store could not be written at all — a fault, unlike the three above. */
export const DETECTION_POLICY_WRITE_ERROR =
  'Could not save this change to the local store. Try again, and check that ~/.aka is writable.';
