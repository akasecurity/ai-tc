/**
 * Pure tighten-only guard: a repo-aware recommended posture may deviate from
 * the severity-floor defaults only by tightening (raising enforcement), never
 * loosening. severityFloorPosture() is both the floor a proposal is checked
 * against and the fallback for any category the proposal leaves untouched.
 * No IO, no consent, no historical read — this takes a proposed map and
 * reasons over it, nothing else.
 */
import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { BUILTIN_ORDER } from '@akasecurity/schema';

// Least -> most restrictive rank, from the one built-in policy ordering
// (monitor -> warn -> redact -> block). Do not hand-roll a second ordering.
function rank(id: BuiltinPolicyId): number {
  return BUILTIN_ORDER.indexOf(id);
}

// Thrown when a proposed category's level ranks strictly below its floor —
// a loosening. Carries the offending category and both levels so a caller
// can report specifically what was rejected without string-matching the
// message.
export class PostureLooseningError extends Error {
  constructor(
    public readonly category: DetectionCategory,
    public readonly floor: BuiltinPolicyId,
    public readonly proposed: BuiltinPolicyId,
  ) {
    super(
      `posture reasoning may only tighten "${category}": floor is "${floor}", proposed "${proposed}" is looser`,
    );
    this.name = 'PostureLooseningError';
  }
}

// Validates a proposed per-category posture against the severity floor and
// returns the accepted, floor-clamped posture: every category the proposal
// raises above (or leaves equal to) its floor takes the proposed level;
// every category the proposal does not touch takes the floor level. Throws
// PostureLooseningError on the first category that would lower enforcement
// below its floor.
export function validateTightenOnly(
  proposed: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  floor: Record<DetectionCategory, BuiltinPolicyId> = severityFloorPosture(),
): Record<DetectionCategory, BuiltinPolicyId> {
  const accepted = { ...floor };
  for (const category of Object.keys(proposed) as DetectionCategory[]) {
    const level = proposed[category];
    if (!level) continue;
    const floorLevel = floor[category];
    if (rank(level) < rank(floorLevel)) {
      throw new PostureLooseningError(category, floorLevel, level);
    }
    accepted[category] = level;
  }
  return accepted;
}
