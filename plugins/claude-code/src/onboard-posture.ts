/**
 * Parse + validate the wizard's per-category posture JSON (--posture flag on
 * onboard.ts) and the store's existing per-category action JSON (--current flag
 * on start-light.ts). Pure module — no top-level side effects — so it can be
 * unit-tested and imported without running the onboard script's main flow.
 */
import type {
  ActionTaken as ActionTakenT,
  BuiltinPolicyId as BuiltinPolicyIdT,
  DetectionCategory,
} from '@akasecurity/schema';
import {
  ActionTaken,
  BuiltinPolicyId,
  DetectionCategory as DetectionCategorySchema,
} from '@akasecurity/schema';

// Every key must be a real DetectionCategory and every value a palette id
// (monitor/warn/redact/block) — 'log'/'allow' are ActionTaken values, not
// palette ids, and are rejected here. Throws on any violation so onboard
// fails loudly rather than writing garbage.
export function parsePosture(json: string): Partial<Record<DetectionCategory, BuiltinPolicyIdT>> {
  const raw: unknown = JSON.parse(json); // throws on malformed JSON
  if (typeof raw !== 'object' || raw === null) throw new Error('posture must be a JSON object');
  const out: Partial<Record<DetectionCategory, BuiltinPolicyIdT>> = {};
  for (const [key, value] of Object.entries(raw)) {
    const cat = DetectionCategorySchema.safeParse(key);
    if (!cat.success) throw new Error(`unknown category "${key}"`);
    const act = BuiltinPolicyId.safeParse(value);
    if (!act.success)
      throw new Error(
        `invalid action "${String(value)}" for ${key} (expected monitor/warn/redact/block)`,
      );
    out[cat.data] = act.data;
  }
  // Reject an empty result — {} and [] both yield no category keys. An empty
  // posture is nothing to write, so fail loudly rather than silently no-op.
  if (Object.keys(out).length === 0) throw new Error('posture is empty - nothing to write');
  return out;
}

// The store's existing per-category action, as the plan file records it. Values
// are ActionTaken (log/warn/redact/block/allow), not palette ids — this is what
// the store holds, not what the wizard is about to write. Unlike parsePosture an
// empty map is valid: a fresh store has no rows, so there is nothing to compare
// a downgrade against.
export function parseCurrent(json: string): Partial<Record<DetectionCategory, ActionTakenT>> {
  const raw: unknown = JSON.parse(json); // throws on malformed JSON
  if (typeof raw !== 'object' || raw === null) throw new Error('current must be a JSON object');
  const out: Partial<Record<DetectionCategory, ActionTakenT>> = {};
  for (const [key, value] of Object.entries(raw)) {
    const cat = DetectionCategorySchema.safeParse(key);
    if (!cat.success) throw new Error(`unknown category "${key}"`);
    const act = ActionTaken.safeParse(value);
    if (!act.success)
      throw new Error(
        `invalid action "${String(value)}" for ${key} (expected log/warn/redact/block/allow)`,
      );
    out[cat.data] = act.data;
  }
  return out;
}
