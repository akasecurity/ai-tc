import { assertRawFree, maskContextSlice, safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type { DetectionCategory, TriageHit } from '@akasecurity/schema';

export interface JoinEntry {
  id: string;
  ruleId: string;
  category: DetectionCategory;
  valueFingerprint?: string;
  keyVersion?: number;
  maskedMatch: string;
  maskedContext: string;
}

// Project the raw --triage stream into raw-free join entries the interactive
// wizard can safely read: fingerprint + masked value + a context window with
// every detected value masked, all routed through the raw-egress gate so no raw
// value can reach the interactive transcript or a persisted row.
export function buildJoinEntries(hits: readonly TriageHit[]): JoinEntry[] {
  const rawValues = hits.map((h) => h.rawMatch);
  return hits.map((h) => {
    // Mask THIS hit's match plus any other hit value that lands in this window.
    // Every OCCURRENCE of each value is spanned, not just the first: `indexOf`
    // alone leaves a doubled value's later copies unmasked, which trips the
    // assertRawFree backstop in maskContextSlice and would abort the whole preview
    // to the floor. Non-overlapping scan (advance past each hit) so a value that
    // appears twice in one window is fully masked.
    const egressHits: { rawMatch: string; span: { start: number; end: number } }[] = [];
    for (const o of hits) {
      if (o.rawMatch.length === 0) continue;
      let at = h.context.indexOf(o.rawMatch);
      while (at >= 0) {
        egressHits.push({ rawMatch: o.rawMatch, span: { start: at, end: at + o.rawMatch.length } });
        at = h.context.indexOf(o.rawMatch, at + o.rawMatch.length);
      }
    }
    const maskedContext = maskContextSlice(h.context, 0, egressHits);
    const entry: JoinEntry = {
      id: h.id ?? '',
      ruleId: h.ruleId,
      category: h.category,
      maskedMatch: safeMaskedMatch(h.rawMatch),
      maskedContext: assertRawFree(maskedContext, rawValues),
      ...(h.valueFingerprint ? { valueFingerprint: h.valueFingerprint } : {}),
      ...(h.keyVersion !== undefined ? { keyVersion: h.keyVersion } : {}),
    };
    return entry;
  });
}
