/**
 * Derives the masked false-positive pattern signal the calibration frame
 * carries into the fixture/exception offer — the marked (model-dismissed)
 * hits grouped by their re-derived masked token, so the offer names a real
 * pattern and count instead of inventing either. Pure: it reads the parsed
 * hits, the model verdict, and the writeback plan, and produces masked/enum/
 * fingerprint data only.
 *
 * RAW SAFETY: the masked token is re-derived from the raw value with
 * safeMaskedMatch (never the streamed maskedMatch), mirroring
 * surfaced-secrets.ts's raw-safety convention.
 */
import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type {
  DetectionCategory,
  FalsePositivePatternGroup,
  FalsePositivePatternValue,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

import type { TriageWritebackPlan } from './writeback.ts';

// Project the marked false-positive hits into FalsePositivePatternGroup[],
// grouped by their re-derived masked token. Markedness is the MODEL's per-hit
// verdict: a hit is marked when its id is listed in a surviving category's
// `fpIds` — the same ids the writeback plan resolves suppressions from. A
// category the plan distrusted (its reasoning echoed a raw value, so it
// carries no posture) contributes nothing, staying consistent with the
// frame's routineCategories/surfacedCategories.
//
// A masked token can collide across DetectionCategories (notably the common
// '***' safeMaskedMatch fallback), so one group can carry values from
// different categories; each value denormalizes its own hit's `category` so a
// downstream exception grant is never stamped with a sibling's category.
//
// Each group's `count` reflects every marked hit sharing the token, even one
// missing its exact value identity (valueFingerprint/keyVersion — ruleId is
// always present) — it still contributes to the display count. Its identity
// is omitted from `values`, since an incomplete identity cannot back a
// written exception; a consumer reads the count/values mismatch to detect an
// unkeyable mark and fall back safely on it. A group left with no keyable
// value at all (every marked hit sharing its token lacks full identity) is
// dropped from the output entirely — FalsePositivePatternGroup's `values`
// requires at least one entry, and a group offering nothing keyable is nothing
// a consumer could act on, so omitting it is the fail-open choice rather than
// emitting a dead group.
export function deriveFalsePositivePatterns(
  hits: readonly TriageHit[],
  rec: TriageRecommendation,
  plan: TriageWritebackPlan,
): FalsePositivePatternGroup[] {
  const hitById = new Map(hits.filter((h) => h.id !== undefined).map((h) => [h.id, h]));

  // Markedness follows the SAME ids the writeback plan resolves suppressions
  // from: for each surviving category (one carrying a posture — a distrusted
  // category whose reasoning echoed a raw value carries none) take the model's
  // `fpIds`. Replicate the writeback's first-occurrence-wins dedup
  // (writeback.ts's `seen` guard): a category is consumed on its first
  // occurrence regardless of posture, so a duplicate/poisoned verdict marks only
  // the ids the writeback actually resolved, never a dropped duplicate's.
  const seenCategory = new Set<DetectionCategory>();
  const markedIds = new Set<string>();
  for (const c of rec.perCategory) {
    if (seenCategory.has(c.category)) continue;
    seenCategory.add(c.category);
    if (plan.posture[c.category] === undefined) continue;
    for (const id of c.fpIds) markedIds.add(id);
  }

  const groups = new Map<string, { count: number; values: FalsePositivePatternValue[] }>();
  for (const id of markedIds) {
    const h = hitById.get(id);
    if (h === undefined) continue;

    const pattern = safeMaskedMatch(h.rawMatch);
    const group = groups.get(pattern) ?? { count: 0, values: [] };
    group.count += 1;
    if (h.valueFingerprint !== undefined && h.keyVersion !== undefined) {
      group.values.push({
        ruleId: h.ruleId,
        category: h.category,
        valueFingerprint: h.valueFingerprint,
        keyVersion: h.keyVersion,
      });
    }
    groups.set(pattern, group);
  }

  return [...groups.entries()]
    .filter(([, g]) => g.values.length > 0)
    .map(([pattern, g]) => ({ pattern, count: g.count, values: g.values }));
}
