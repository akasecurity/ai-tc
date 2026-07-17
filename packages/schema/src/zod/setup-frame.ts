import { z } from 'zod';

import { DetectionCategory } from './finding.ts';
import { BuiltinPolicyId } from './policy.ts';
import { TriageCategoryRec } from './triage.ts';

// The calibration counts shown at the calibrated-result frame ('Calibrated. N
// notifications, M important. (N−M) routine, M that matter'). `important` counts
// the surfaced findings, `routine` the suppressed ones, `total` their sum; the
// sum equality is enforced by the emitter, not this schema.
export const CalibrationCounts = z.object({
  total: z.number().int().nonnegative(),
  important: z.number().int().nonnegative(),
  routine: z.number().int().nonnegative(),
});
export type CalibrationCounts = z.infer<typeof CalibrationCounts>;

// One kind of finding present in the scanned history, counted and tagged on the
// egress-kind axis: `egress` marks an outbound-leak kind, distinct from an
// at-rest exposure (e.g. a live key sitting in a transcript). The honest-positive
// line is gated on the absence of any egress-kind finding across a frame's
// `findingKinds`.
export const CalibrationFindingKind = z.object({
  category: DetectionCategory,
  count: z.number().int().nonnegative(),
  egress: z.boolean(),
});
export type CalibrationFindingKind = z.infer<typeof CalibrationFindingKind>;

// The structured frame data the wizard scripts emit and the rendered copy
// templates over: the calibration counts, the routine (suppressed) and surfaced
// (important) category lists, the finding kinds with their egress axis, and the
// recommended per-category posture map.
//
// This shape is extended additively — existing fields are never reshaped, later
// consumers only add fields. Two known extension points: masked per-finding
// summaries are added here as an optional field by the finding-table consumer,
// and an egress predicate is computed over `findingKinds` (its `egress` axis) by
// the honest-positive-line consumer.
//
// No `.meta({ id })` — no API route references this shape, matching the
// TriageHit/TriageRecommendation convention (an unrouted id would still register
// in Zod's global registry and leak an orphan component into the generated
// OpenAPI client).
export const CalibrationFrame = z.object({
  counts: CalibrationCounts,
  routineCategories: z.array(DetectionCategory),
  surfacedCategories: z.array(DetectionCategory),
  findingKinds: z.array(CalibrationFindingKind),
  posture: z.record(DetectionCategory, BuiltinPolicyId),
});
export type CalibrationFrame = z.infer<typeof CalibrationFrame>;

// One category slice of the backfill + apply-suppressions preview the calibration
// frame is derived from: the triage genuine/FP split (`genuineCount` are the
// surfaced/'important' findings, `fpCount` the suppressed/'routine' ones, reused
// from TriageCategoryRec) plus the egress-kind axis carried through into the
// frame's findingKinds.
export const CalibrationPreviewCategory = TriageCategoryRec.pick({
  category: true,
  genuineCount: true,
  fpCount: true,
}).extend({
  egress: z.boolean(),
});
export type CalibrationPreviewCategory = z.infer<typeof CalibrationPreviewCategory>;

// The preview the calibration frame is derived from: the per-category triage
// breakdown plus the recommended per-category posture map, emitted unchanged in
// the frame.
export const CalibrationPreview = z.object({
  categories: z.array(CalibrationPreviewCategory),
  posture: z.record(DetectionCategory, BuiltinPolicyId),
});
export type CalibrationPreview = z.infer<typeof CalibrationPreview>;

// The calibration module's output: the structured frame plus the copy that
// templates over it ('Calibrated. N notifications, M important. …').
export const CalibrationResult = z.object({
  frame: CalibrationFrame,
  copy: z.string(),
});
export type CalibrationResult = z.infer<typeof CalibrationResult>;

// One option of the installed-summary dashboard handoff: a stable id
// the prompt layer routes on and the label it shows.
export const SetupHandoffOption = z.object({
  id: z.enum(['open-dashboard', 'not-now']),
  label: z.string(),
});
export type SetupHandoffOption = z.infer<typeof SetupHandoffOption>;

// The handoff-offer payload: the 'M worth a look' count the installed
// summary templates into its dashboard handoff question, and the two offer
// options. `worthALook` is the surfaced/important count from the calibration
// preview — a real store-derived value, never fabricated. The
// AskUserQuestion issuance itself lives in the prompt layer; this is the
// structured payload a harness reads to assert the offer without observing the
// interactive picker. No `.meta({ id })`, matching the CalibrationFrame
// convention above (no API route references it).
//
// `options` is a fixed two-entry tuple — Open dashboard then Not now — so the
// contract matches the producer exactly: a dropped, reordered, or extra option
// fails validation, not just a non-array.
export const SetupHandoffOffer = z.object({
  worthALook: z.number().int().nonnegative(),
  options: z.tuple([
    SetupHandoffOption.extend({ id: z.literal('open-dashboard') }),
    SetupHandoffOption.extend({ id: z.literal('not-now') }),
  ]),
});
export type SetupHandoffOffer = z.infer<typeof SetupHandoffOffer>;
