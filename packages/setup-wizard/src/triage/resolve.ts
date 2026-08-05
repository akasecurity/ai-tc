import type { SuppressionEntry } from '@akasecurity/plugin-sdk';
import type { TriageRecommendation } from '@akasecurity/schema';

import type { JoinEntry } from './join-file.ts';

export interface ResolveResult {
  entries: SuppressionEntry[];
  skipped: { category: string; reason: string }[];
}

// Resolve the model's per-category FP verdict into concrete SuppressionEntry
// rows by joining each fpId back to its raw-free JoinEntry.
// Fail-secure at the ID level (an unkeyable id never silences a detection), but
// the fail-secure GATE for the category as a whole is now the binding HUMAN
// confirmation: the preview shows the operator exactly which masked
// values will be suppressed, so a count discrepancy no longer has to void the
// category — it is surfaced, not silently swallowed.
//   - fpCount !== fpIds.length -> the model miscounted. Do NOT drop the category;
//     resolve the ids that DO map to a keyable join entry and record the
//     discrepancy so the human sees "model reported N FPs, M resolved".
//   - fpId absent from the join -> dropped and noted (never a crash).
//   - JoinEntry without a valueFingerprint/keyVersion -> dropped and noted: an
//     exception is keyed by fingerprint+version, so one can't be written without.
export function resolveSuppressions(rec: TriageRecommendation, join: JoinEntry[]): ResolveResult {
  const byId = new Map(join.map((e) => [e.id, e]));
  const entries: SuppressionEntry[] = [];
  const skipped: { category: string; reason: string }[] = [];

  for (const cat of rec.perCategory) {
    let resolved = 0;
    for (const id of cat.fpIds) {
      const entry = byId.get(id);
      if (!entry) {
        skipped.push({ category: cat.category, reason: `fpId ${id} not found in join` });
        continue;
      }
      if (!entry.valueFingerprint || entry.keyVersion === undefined) {
        skipped.push({
          category: cat.category,
          reason: `fpId ${id} has no valueFingerprint; cannot key an exception`,
        });
        continue;
      }
      entries.push({
        ruleId: entry.ruleId,
        category: entry.category,
        valueFingerprint: entry.valueFingerprint,
        keyVersion: entry.keyVersion,
        maskedValue: entry.maskedMatch,
        justification: cat.reasoning,
      });
      resolved++;
    }

    // Surface a miscount to the human gate instead of voiding the category: the
    // operator confirms exactly the `resolved` masked values shown in the preview.
    if (cat.fpCount !== cat.fpIds.length) {
      skipped.push({
        category: cat.category,
        reason: `count discrepancy: model reported ${String(cat.fpCount)} FPs, listed ${String(cat.fpIds.length)} ids, ${String(resolved)} resolved (human confirms the resolved set)`,
      });
    }
  }

  return { entries, skipped };
}
