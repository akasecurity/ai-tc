/**
 * Pure calibration count-framing for the /aka:setup wizard's calibrated-result
 * screen. Turns the backfill + apply-suppressions preview breakdown into the
 * CalibrationFrame emitted for downstream consumers and the human-facing copy:
 * 'Calibrated. N notifications, M important. (N−M) routine, M that matter (KIND)'.
 * Surfaced (genuine, non-suppressed) findings are 'important'; suppressed findings
 * are 'routine'; the total is their sum. No IO; no fixed counts — every number
 * follows the preview input.
 */
import type {
  CalibrationFrame,
  CalibrationPreview,
  CalibrationResult,
  DetectionCategory,
} from '@akasecurity/schema';

// Plain-English kind of a surfaced category, for the 'M that matter (…)'
// parenthetical. Presentation-only — not a persisted contract.
const SURFACED_KIND_LABEL: Record<DetectionCategory, string> = {
  secret: 'live keys',
  pii: 'personal data',
  financial: 'financial records',
  phi: 'health records',
  code_context: 'source context',
  code_flaw: 'code flaws',
  custom: 'custom matches',
  config: 'configuration secrets',
};

export function frameCalibration(preview: CalibrationPreview): CalibrationResult {
  const important = preview.categories.reduce((n, c) => n + c.genuineCount, 0);
  const routine = preview.categories.reduce((n, c) => n + c.fpCount, 0);
  const total = important + routine;

  const surfacedCategories = preview.categories
    .filter((c) => c.genuineCount > 0)
    .map((c) => c.category);
  const routineCategories = preview.categories.filter((c) => c.fpCount > 0).map((c) => c.category);

  const findingKinds = preview.categories
    .filter((c) => c.genuineCount + c.fpCount > 0)
    .map((c) => ({ category: c.category, count: c.genuineCount + c.fpCount, egress: c.egress }));

  const frame: CalibrationFrame = {
    counts: { total, important, routine },
    routineCategories,
    surfacedCategories,
    findingKinds,
    posture: preview.posture,
  };

  const kind = surfacedCategories.map((c) => SURFACED_KIND_LABEL[c]).join(', ');
  const copy =
    `Calibrated. ${String(total)} notifications, ${String(important)} important. ` +
    `${String(routine)} routine, ${String(important)} that matter (${kind})`;

  return { frame, copy };
}
