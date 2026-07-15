import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { builtinPolicyToAction, severityFloorPosture } from '@akasecurity/schema';

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

// Worst-to-best action rank (index 0 = strongest).
const ACTION_RANK: ActionTaken[] = ['block', 'redact', 'warn', 'log', 'allow'];

export interface PostureChange {
  category: DetectionCategory;
  from: ActionTaken;
  to: ActionTaken;
  kind: 'downgrade' | 're-enable';
}

// Returns every change a proposed posture would make that weakens
// enforcement: lowering an existing category's action, or re-enabling a
// disabled category. A category that is both is reported once, as
// 'downgrade'. Writes nothing.
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
    if (ACTION_RANK.indexOf(to) > ACTION_RANK.indexOf(current.action)) {
      changes.push({ category, from: current.action, to, kind: 'downgrade' });
    } else if (!current.enabled) {
      changes.push({ category, from: current.action, to, kind: 're-enable' });
    }
  }
  return changes;
}
