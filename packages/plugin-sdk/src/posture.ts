import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { actionRank, builtinPolicyToAction, severityFloorPosture } from '@akasecurity/schema';

export { severityFloorPosture };

interface PolicyWriter {
  getCategoryAction(category: DetectionCategory): ActionTaken | undefined;
  upsertCategoryAction(category: DetectionCategory, action: ActionTaken): void;
}

// Persists a per-category posture into the policies table, mapping the
// {monitor,warn,redact,block} palette to ActionTaken before writing.
// 'fill-gaps' (default) skips any category that already has a policy row.
// 'overwrite' replaces the row regardless.
export function applyCategoryPosture(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  repo: PolicyWriter,
  mode: 'fill-gaps' | 'overwrite' = 'fill-gaps',
): void {
  for (const category of Object.keys(posture) as DetectionCategory[]) {
    const policyId = posture[category];
    if (!policyId) continue;
    if (mode === 'fill-gaps' && repo.getCategoryAction(category) !== undefined) continue;
    repo.upsertCategoryAction(category, builtinPolicyToAction(policyId));
  }
}

// What `actionRank` returns for an action outside the ladder.
const UNRANKED = -1;

export interface PostureChange {
  category: DetectionCategory;
  from: ActionTaken;
  to: ActionTaken;
  kind: 'downgrade' | 're-enable';
}

// Returns every change a proposed posture would make that weakens
// enforcement: lowering an existing category's action, or re-enabling a
// disabled category. A category whose stored action this build cannot rank at
// all is reported too, as a 'downgrade' — see below. A category that is both is
// reported once, as 'downgrade'. Writes nothing.
export function detectPostureChanges(
  posture: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  existing: Partial<Record<DetectionCategory, { action: ActionTaken; enabled: boolean }>>,
): PostureChange[] {
  const changes: PostureChange[] = [];
  for (const category of Object.keys(posture) as DetectionCategory[]) {
    const policyId = posture[category];
    if (!policyId) continue;
    const current = existing[category];
    if (!current) continue;
    const to = builtinPolicyToAction(policyId);
    const currentRank = actionRank(current.action);
    // Weaker than what is already stored — the one enforcement-strength ladder
    // decides that, so this differ and the runtime's collapse can never come to
    // disagree about which of two actions enforces more.
    //
    // `current.action` comes from a store column with no enum constraint, so it
    // can be an action this build does not know. The ladder ranks such a value
    // BELOW every real action, because the places that GATE enforcement on a
    // rank must never let an unknown license something it never asked for. This
    // is not one of those places: nothing here enforces, it tells a person that
    // the posture they are about to apply lowers enforcement — so it reads the
    // unknown the other way round. "This build cannot tell what was stored" is
    // not the same answer as "the weakest thing on the ladder was stored", and
    // the only honest thing to do with a comparison that cannot be made is to
    // surface the change rather than pass over it in silence.
    if (currentRank === UNRANKED || actionRank(to) < currentRank) {
      changes.push({ category, from: current.action, to, kind: 'downgrade' });
    } else if (!current.enabled) {
      changes.push({ category, from: current.action, to, kind: 're-enable' });
    }
  }
  return changes;
}
