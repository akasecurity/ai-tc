/**
 * Pure calibration count-framing for the /aka:setup wizard's calibrated-result
 * screen. frameCalibration turns the backfill + apply-suppressions preview
 * breakdown into the CalibrationFrame emitted for downstream consumers and the
 * human-facing copy 'Calibrated. N notifications, M important. (N−M) routine,
 * M that matter (KIND)' — every count follows the preview input. frameEmptyState
 * produces the honest empty-state copy over a zero-count frame for a scan that
 * found nothing or a machine with no history. Surfaced (genuine, non-suppressed)
 * findings are 'important'; suppressed findings are 'routine'; the total is their
 * sum. No IO.
 */
import type {
  CalibrationFrame,
  CalibrationPreview,
  CalibrationResult,
  DetectionCategory,
  MaskedSecretFinding,
} from '@akasecurity/schema';

import { renderPostureGrid, renderRecommendedPosture } from './render.ts';

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

export function frameCalibration(
  preview: CalibrationPreview,
  maskedFindings: readonly MaskedSecretFinding[] = [],
): CalibrationResult {
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

  // The masked per-finding summaries ride ALONGSIDE the counts additively: the
  // optional `maskedFindings` field is populated only when a secret finding
  // surfaced, so an empty set omits it entirely and a pre-existing frame without
  // it still validates. The finding table and the narration read these fields.
  const frame: CalibrationFrame = {
    counts: { total, important, routine },
    routineCategories,
    surfacedCategories,
    findingKinds,
    posture: preview.posture,
    ...(maskedFindings.length > 0 ? { maskedFindings: [...maskedFindings] } : {}),
  };

  const kind = surfacedCategories.map((c) => SURFACED_KIND_LABEL[c]).join(', ');
  // Omit the kind parenthetical entirely when nothing surfaced, so an
  // all-suppressed run reads 'M that matter' rather than 'M that matter ()'.
  const parenthetical = kind ? ` (${kind})` : '';
  const headline =
    `Calibrated. ${String(total)} notifications, ${String(important)} important. ` +
    `${String(routine)} routine, ${String(important)} that matter${parenthetical}`;

  // The frame carries the finding kinds (incl. the egress axis) for downstream
  // consumers; the calibrated headline is the copy. A positive observation over
  // these findings is an evidence-grounded intelligence-layer output, not a
  // static line here — it renders only when the evidence honestly supports it.
  const copy = headline;

  return { frame, copy };
}

// Which cause left the calibration empty: a scan ran and surfaced nothing
// ('scan-clean') or there is no history on this machine to scan ('no-history').
// Selects which honest empty-state copy renders. Presentation-only — not a
// persisted contract.
export type EmptyCause = 'scan-clean' | 'no-history';

// The scan-ran-clean headline: a scan looked at recent activity and found
// nothing worth surfacing, so the user starts from the recommended posture.
const SCAN_CLEAN_HEADLINE =
  "Calibrated. I looked at Claude's recent activity — nothing needs your attention. " +
  "You're starting clean; here's the posture I'd recommend:";

// The no-history headline: there is nothing on this machine to calibrate from,
// so each pack starts at its conservative default (the start-light 0.3b table).
const NO_HISTORY_HEADLINE =
  "Nothing to calibrate from yet — Claude hasn't left activity on this machine. " +
  'Each pack starts at a conservative default:';

// The empty-state framing: two distinct honest copies, one per cause, each
// stating why it is empty — never '0 notifications' theater. A scan-clean state
// renders the recommended posture; a no-history state renders the start-light
// table. Both carry a valid zero-count CalibrationFrame. This is the
// found-nothing/empty-store copy only; an unreadable store is the separate
// STORE_UNAVAILABLE_NOTE path, not framed here.
export function frameEmptyState(
  cause: EmptyCause,
  posture: CalibrationFrame['posture'],
): CalibrationResult {
  const frame: CalibrationFrame = {
    counts: { total: 0, important: 0, routine: 0 },
    routineCategories: [],
    surfacedCategories: [],
    findingKinds: [],
    posture,
  };
  const copy =
    cause === 'scan-clean'
      ? `${SCAN_CLEAN_HEADLINE}\n${renderRecommendedPosture(posture)}`
      : `${NO_HISTORY_HEADLINE}\n${renderPostureGrid(posture)}`;
  return { frame, copy };
}
