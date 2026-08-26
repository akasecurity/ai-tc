// A per-action tally pre-filled with zeros for EVERY ActionTaken member.
//
// One definition rather than three: the same
// `Object.fromEntries(ACTION_TAKEN_KEYS.map(...)) as Record<ActionTaken, number>`
// expression had grown copies in attached-gateway.ts (health summary) and twice
// in posture-snapshot.ts (empty readout + policy tally). Each carried its own
// `as` assertion papering over Object.fromEntries's loose return type, so an
// ActionTaken change had to be reasoned about in three places and every
// assertion hid any mismatch independently.
import type { ActionTaken } from '@akasecurity/schema';
import { ACTION_TAKEN_KEYS } from '@akasecurity/schema';

/** A fresh, mutable `{ [action]: 0 }` covering every ActionTaken member. */
export function emptyActionCounts(): Record<ActionTaken, number> {
  return Object.fromEntries(ACTION_TAKEN_KEYS.map((a) => [a, 0])) as Record<ActionTaken, number>;
}

/** Whether `value` is one of the ActionTaken members — narrows for tallying. */
export function isActionTaken(value: string): value is ActionTaken {
  return (ACTION_TAKEN_KEYS as readonly string[]).includes(value);
}
