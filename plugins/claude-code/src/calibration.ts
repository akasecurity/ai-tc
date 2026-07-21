/**
 * Pure calibration count-framing for the /aka:setup wizard's calibrated-result
 * screen. frameCalibration turns the backfill + apply-suppressions preview
 * breakdown into the CalibrationFrame emitted for downstream consumers and the
 * human-facing copy "I went through Claude's recent work — N detections, M
 * result(s) worth a look. (KIND)" — every count follows the preview input.
 * frameEmptyState produces the honest empty-state copy over a zero-count frame
 * for a scan that found nothing or a machine with no history. Surfaced
 * (genuine, non-suppressed) findings are 'important'; suppressed findings are
 * 'routine'; the total is their sum. No IO.
 */
import type {
  CalibrationFrame,
  CalibrationPreview,
  CalibrationResult,
  DetectionCategory,
  FalsePositivePatternGroup,
  MaskedSecretFinding,
} from '@akasecurity/schema';

import { renderPostureGrid, renderRecommendedPosture } from './render.ts';

// Plain-English kind of a surfaced category, for the 'M result(s) worth a
// look. (…)' parenthetical. Presentation-only — not a persisted contract.
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
  falsePositivePatterns: readonly FalsePositivePatternGroup[] = [],
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
  // `falsePositivePatterns` follows the same additive discipline: populated only
  // when a hit was marked a false positive, so a clean run's frame still omits
  // it entirely — the fixture/exception offer's grounded pattern×count signal.
  const frame: CalibrationFrame = {
    counts: { total, important, routine },
    routineCategories,
    surfacedCategories,
    findingKinds,
    posture: preview.posture,
    ...(maskedFindings.length > 0 ? { maskedFindings: [...maskedFindings] } : {}),
    ...(falsePositivePatterns.length > 0
      ? { falsePositivePatterns: [...falsePositivePatterns] }
      : {}),
  };

  const kind = surfacedCategories.map((c) => SURFACED_KIND_LABEL[c]).join(', ');
  // Omit the kind parenthetical entirely when nothing surfaced, so an
  // all-suppressed run reads 'worth a look.' with no dangling ' ()'.
  const parenthetical = kind ? ` (${kind})` : '';
  const headline =
    `I went through Claude's recent work — ${String(total)} detection${total === 1 ? '' : 's'}, ` +
    `${String(important)} result${important === 1 ? '' : 's'} worth a look.${parenthetical}`;

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

// The scan-ran-clean headline: a scan looked at recent work and found
// nothing worth surfacing, so the user starts from the recommended posture.
const SCAN_CLEAN_HEADLINE =
  "I looked over Claude's recent work — nothing needs your attention right now. " +
  "You're starting clean; here's what I'd recommend:";

// The no-history headline: there is nothing on this machine to learn from,
// so each detection category starts at its careful default (the start-light
// 0.3b table).
const NO_HISTORY_HEADLINE =
  "Nothing to learn from yet — Claude hasn't left any work on this machine. " +
  "I'll start each detection category at a careful default:";

// The empty-state framing: two distinct honest copies, one per cause, each
// stating why it is empty — never '0 detections' theater. A scan-clean state
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
