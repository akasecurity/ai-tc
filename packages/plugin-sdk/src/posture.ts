import type { ActionTaken, BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { builtinPolicyToAction, severityFloorPosture } from '@akasecurity/schema';

export { severityFloorPosture };

interface PolicyWriter {
  getCategoryAction(category: DetectionCategory): ActionTaken | undefined;
  upsertCategoryAction(category: DetectionCategory, action: ActionTaken): void;
}

// Persist a per-category posture (the wizard's model calibration, or
// severityFloorPosture() on a thin backfill) into the policies table, mapping
// the {monitor,warn,redact,block} palette to ActionTaken before writing.
// 'fill-gaps' (default) never replaces a category that already has a policy
// row, so a re-run with the severity floor can never downgrade a calibrated
// posture. 'overwrite' is the explicit path (a confirmed --posture
// calibration, or --recalibrate) — callers that use it are expected to have
// already run detectPostureChanges and surfaced any downgrade/re-enable.
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

// Worst-to-best action rank (index 0 = strongest). Mirrors runtime.ts's
// ACTION_PRIORITY sense, kept as its own local copy so posture.ts has no
// dependency on runtime.ts.
const ACTION_RANK: ActionTaken[] = ['block', 'redact', 'warn', 'log', 'allow'];

export interface PostureChange {
  category: DetectionCategory;
  from: ActionTaken;
  to: ActionTaken;
  kind: 'downgrade' | 're-enable';
}

// Given a proposed posture and each affected category's current (action,
// enabled) state, return every change that WEAKENS enforcement: lowering the
// action, and/or flipping a disabled category back to enabled. A caller uses
// this to decide whether to prompt before calling
// applyCategoryPosture(mode='overwrite') — it never writes anything itself.
// A category that is both a downgrade AND a re-enable is reported once, as
// 'downgrade' (the caller only needs one reason to prompt).
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
