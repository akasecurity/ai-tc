import { z } from 'zod';

import { DetectionCategory, Severity } from './finding.ts';
import { BuiltinPolicyId } from './policy.ts';

// One detected hit as streamed by `backfill --triage`: the raw match plus a
// surrounding text window, for a downstream judge's FP/severity read.
// `rawMatch`/`context` carry unmasked secret text and exist ONLY for that
// isolated judge process to read — they must never reach a persisted row, a
// log, or a UI surface as-is. Before this shape crosses back out to the
// interactive session or a stored exceptions row, a consumer must run it
// through the `@akasecurity/plugin-sdk` raw-egress guardrails
// (`assertRawFree` / `maskContextSlice` in `raw-egress.ts`) — the same
// boundary check already used for other isolated-process output.
// `maskContextSlice` takes its span/offset coordinates as call arguments, not
// from this type — a consumer derives them itself (e.g. by locating a raw
// value's position within `context` directly) rather than reading them off a
// `TriageHit`. This schema intentionally omits `.meta({ id })`: no API route references it, and an
// unrouted id would still register in Zod's global registry and leak an
// orphan component into the generated OpenAPI client.
// id/valueFingerprint/keyVersion are set by the --triage sink
// for a later suppression writeback and stay optional so a hit built before
// fingerprinting still validates.
export const TriageHit = z.object({
  ruleId: z.string(),
  category: DetectionCategory,
  severity: Severity,
  maskedMatch: z.string(),
  rawMatch: z.string(),
  context: z.string(),
  filePath: z.string().optional(),
  confidence: z.number().min(0).max(1),
  id: z.string().optional(),
  valueFingerprint: z.string().optional(),
  keyVersion: z.number().int().nonnegative().optional(),
});
export type TriageHit = z.infer<typeof TriageHit>;

// The triage palette is exactly the built-in policy id set
// (monitor/warn/redact/block); allow/log are runtime-internal, never a value a
// triage judge assigns.
export const TriagePolicy = BuiltinPolicyId;
export type TriagePolicy = z.infer<typeof TriagePolicy>;

// No `.meta({ id })` — no API route references this shape yet (see the
// TriageHit comment above for why an orphan id must wait for a real route).
export const TriageCategoryRec = z.object({
  category: DetectionCategory,
  action: TriagePolicy,
  reasoning: z.string(),
  genuineCount: z.number().int().nonnegative(),
  fpCount: z.number().int().nonnegative(),
  // TriageHit ids judged false-positive in this category. fpCount must equal
  // this array's length — enforced by the consumer, not this schema.
  fpIds: z.array(z.string()),
});
export type TriageCategoryRec = z.infer<typeof TriageCategoryRec>;

// No `.meta({ id })` for the same not-yet-routed reason as TriageCategoryRec.
export const TriageRecommendation = z.object({
  perCategory: z.array(TriageCategoryRec),
  notes: z.string(),
});
export type TriageRecommendation = z.infer<typeof TriageRecommendation>;
