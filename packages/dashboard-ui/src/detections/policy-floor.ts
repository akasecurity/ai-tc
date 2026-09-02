// What a connected control plane forbids this machine to undo, expressed in the
// vocabulary the Detections page renders.
//
// A machine attached to an organization's deployment is not the sole authority
// over its own detections any more: the organization's policy is a FLOOR the
// device may raise but never lower, and a detection the organization has
// written an explicit policy for cannot be re-assigned here at all. Enforcement
// already worked that way — a weaker local choice was quietly overridden — so
// the defect this module exists to close was a picker that accepted the weaker
// choice, showed it as selected, and left the user believing it.
//
// Everything here is a PURE function of a serializable descriptor. The floor is
// computed on the server (it needs the local store and the machine's settings),
// so the only thing that crosses into the browser is the two facts below, and
// the decisions that follow from them are made in one place for both the picker
// and the list.
import {
  BuiltinPolicyId,
  builtinPolicyToAction,
  isActionAtLeast,
  KNOWN_BUILTIN_IDS,
} from '@akasecurity/schema';

import { PLACEHOLDER_POLICY, policyMeta } from './meta.ts';

/**
 * The constraint one detection is under, or the absence of one.
 *
 * Structurally what the local store reports for an installed pack, restated
 * here because these views may not import the store: they take props and
 * nothing else. Keeping the two shapes identical is what lets a host forward
 * the store's answer verbatim rather than translating it.
 */
export interface DetectionPolicyFloor {
  /** The weakest archetype the organization permits for this detection. */
  readonly floor: BuiltinPolicyId;
  /**
   * True when the organization has written a policy for this detection rather
   * than a minimum — it stated the answer, so there is nothing to choose.
   */
  readonly locked: boolean;
}

/**
 * The sentence a user reads when a choice is not theirs to make.
 *
 * Two sentences, because the two constraints have different remedies: under a
 * floor there is still a decision to take (a stronger one), under a lock there
 * is none. Collapsing them into one hedged line would leave the reader unsure
 * which of the two they are in, and the whole point of showing the restricted
 * option is that the reason reaches the person who wanted it.
 */
export function policyFloorReason(floor: DetectionPolicyFloor): string {
  if (floor.locked) {
    return (
      'Your organization sets the enforcement policy for this detection, ' +
      'so it cannot be changed on this machine.'
    );
  }
  return (
    `Your organization requires at least ${policyMeta(floor.floor).label} for this detection. ` +
    'You can choose a stronger action here, but not a weaker one.'
  );
}

/**
 * The archetypes this machine may NOT assign, each mapped to why — the shape
 * PolicyPicker's `unavailable` prop takes.
 *
 * The membership test is the same comparison the store applies when it refuses
 * the write, sourced from the same schema ladder, so what the picker greys out
 * and what the write path rejects cannot disagree. The store stays the
 * authority: this only decides what to OFFER, and a refusal that still arrives
 * is reported rather than swallowed.
 *
 * Undefined — not an empty object — when nothing is restricted, so a detection
 * under no constraint renders exactly the control it rendered before any of
 * this existed. A floor of Monitor is that case: it forbids nothing.
 */
export function unavailableUnderFloor(
  floor: DetectionPolicyFloor | null | undefined,
): Readonly<Record<string, string>> | undefined {
  if (!floor) return undefined;
  // A lock takes every option, including the one currently selected: the
  // organization owns this detection's answer, so re-picking what is already
  // there is no more available than picking anything else.
  const restricted = floor.locked
    ? KNOWN_BUILTIN_IDS
    : KNOWN_BUILTIN_IDS.filter(
        (id) => !isActionAtLeast(builtinPolicyToAction(id), builtinPolicyToAction(floor.floor)),
      );
  if (restricted.length === 0) return undefined;
  const reason = policyFloorReason(floor);
  return Object.fromEntries(restricted.map((id) => [id, reason]));
}

/**
 * What is actually enforced for a detection: the stored assignment, or the
 * floor when the stored assignment is below it.
 *
 * A store written before the floor existed can hold a weaker choice than the
 * organization requires — the write path refuses new ones, but it cannot
 * rewrite history — and enforcement raises such a pack at evaluation time.
 * Rendering the stored value there would put a Monitor pill on a row whose
 * matches are being warned about, which is the same untruth as the picker's,
 * one level out.
 *
 * An id no archetype claims (a custom policy) is treated as below the floor:
 * `actionRank` ranks an unknown below everything, so that is what enforcement
 * does with it too.
 */
export function effectivePolicyId(
  assigned: string | undefined,
  floor: DetectionPolicyFloor | null | undefined,
): string {
  const id = assigned ?? PLACEHOLDER_POLICY;
  if (!floor) return id;
  const parsed = BuiltinPolicyId.safeParse(id);
  if (!parsed.success) return floor.floor;
  return isActionAtLeast(builtinPolicyToAction(parsed.data), builtinPolicyToAction(floor.floor))
    ? id
    : floor.floor;
}

/**
 * Whether the organization — rather than this machine — decided what the tag
 * beside a detection says.
 *
 * True when the floor raised the stored assignment, and true for a lock even
 * when the two agree: a locked detection whose local value happens to match is
 * still not the user's to change, and a row that looked ordinary would send
 * them to the picker to find that out.
 */
export function isPolicyGoverned(
  assigned: string | undefined,
  floor: DetectionPolicyFloor | null | undefined,
): boolean {
  if (!floor) return false;
  return floor.locked || effectivePolicyId(assigned, floor) !== (assigned ?? PLACEHOLDER_POLICY);
}
