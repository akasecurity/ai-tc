/**
 * Value-identity collapse for the setup-triage judge. Repeated occurrences of
 * the same detected value under the same rule are ONE judgment, not many: the
 * judge reasons over distinct values, and value-scoped suppression carries that
 * one verdict back to every occurrence.
 *
 * SCOPE — read before choosing which list to hand a consumer. The key is
 * deliberately file-independent (`valueFingerprint` is an HMAC of the raw value
 * alone; see backfill.ts), so the collapsed set is:
 *   - the RIGHT input for a VALUE-scoped consumer — the judge, and the
 *     suppression writeback whose exceptions key on
 *     (ruleId, valueFingerprint, keyVersion);
 *   - the WRONG input for a LOCATION-scoped one — a `MaskedSecretFinding`
 *     carries a single `where.filePath` and the redaction pass only ever opens
 *     files a finding names, so a collapsed set would strike one file, leave
 *     the key live in the others, and still satisfy the complete-redaction
 *     honesty gate (which counts those same findings).
 * A location-scoped consumer therefore takes the FULL hit list and expands the
 * judge's per-representative verdict back over the class with `dedupeKey`.
 */
import type { TriageHit } from '@akasecurity/schema';

// The value identity a hit collapses on. `undefined` for a hit the sink could
// not fingerprint — it has no value identity to share, so it is never collapsed
// into another hit and never inherits another hit's verdict.
export function dedupeKey(hit: TriageHit): string | undefined {
  if (hit.valueFingerprint === undefined) return undefined;
  return `${hit.ruleId}█${hit.valueFingerprint}`;
}

export function dedupeForJudge(hits: readonly TriageHit[]): TriageHit[] {
  const seen = new Set<string>();
  const out: TriageHit[] = [];
  for (const h of hits) {
    const key = dedupeKey(h);
    if (key === undefined) {
      out.push(h);
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(h);
  }
  return out;
}
