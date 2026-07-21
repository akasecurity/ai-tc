import type { TriageHit } from '@akasecurity/schema';

export function dedupeForJudge(hits: readonly TriageHit[]): TriageHit[] {
  const seen = new Set<string>();
  const out: TriageHit[] = [];
  for (const h of hits) {
    if (h.valueFingerprint === undefined) {
      out.push(h);
      continue;
    }
    const key = `${h.ruleId}█${h.valueFingerprint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(h);
  }
  return out;
}
