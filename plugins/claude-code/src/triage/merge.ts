import type {
  BuiltinPolicyId,
  TriageCategoryRec,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

const RANK: Record<BuiltinPolicyId, number> = { monitor: 0, warn: 1, redact: 2, block: 3 };

export function chunkForJudge(hits: readonly TriageHit[], maxBytes = 262_144): TriageHit[][] {
  const chunks: TriageHit[][] = [];
  let current: TriageHit[] = [];
  let size = 0;
  for (const h of hits) {
    const b = Buffer.byteLength(JSON.stringify(h)) + 1;
    if (size + b > maxBytes && current.length > 0) {
      chunks.push(current);
      current = [];
      size = 0;
    }
    current.push(h);
    size += b;
  }
  chunks.push(current);
  return chunks;
}

export function mergeRecommendations(recs: readonly TriageRecommendation[]): TriageRecommendation {
  if (recs.length === 1) {
    const [sole] = recs;
    if (sole === undefined) throw new Error('mergeRecommendations: empty recommendation');
    return sole;
  }
  const byCat = new Map<string, TriageCategoryRec>();
  for (const rec of recs) {
    for (const c of rec.perCategory) {
      const prev = byCat.get(c.category);
      if (!prev) {
        byCat.set(c.category, { ...c, fpIds: [...c.fpIds] });
        continue;
      }
      prev.genuineCount += c.genuineCount;
      prev.fpCount += c.fpCount;
      prev.fpIds = [...new Set([...prev.fpIds, ...c.fpIds])];
      if (RANK[c.action] > RANK[prev.action]) {
        prev.action = c.action;
        prev.reasoning = c.reasoning;
      }
    }
  }
  return {
    perCategory: [...byCat.values()],
    notes: recs
      .map((r) => r.notes)
      .filter(Boolean)
      .join('\n'),
  };
}
