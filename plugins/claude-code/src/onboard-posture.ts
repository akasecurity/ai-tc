/**
 * Parse + validate the wizard's per-category posture JSON (--posture flag on
 * onboard.ts). Pure module — no top-level side effects — so it can be
 * unit-tested and imported without running the onboard script's main flow.
 */
import type { BuiltinPolicyId as BuiltinPolicyIdT, DetectionCategory } from '@akasecurity/schema';
import { BuiltinPolicyId, DetectionCategory as DetectionCategorySchema } from '@akasecurity/schema';

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
