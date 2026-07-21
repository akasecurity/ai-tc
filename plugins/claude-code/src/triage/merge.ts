/**
 * Batch-and-merge fallback for the setup-triage judge. When the distinct-value
 * set is too large for one judgment, `chunkForJudge` splits it by serialized
 * byte budget and `mergeRecommendations` folds the per-chunk verdicts back into
 * the single `TriageRecommendation` the rest of the pipeline consumes.
 *
 * Chunking costs two invariants that a single judgment gave for free, and both
 * are restored here rather than downstream:
 *
 *  1. GROUNDED IDS. A verdict's `fpIds` are resolved against the join built
 *     from the FULL representative set (writeback.ts), so an id a chunk's judge
 *     invented — or renumbered locally, which lands squarely in a sibling
 *     chunk's id space, since backfill.ts numbers hits with one monotonic
 *     stream ordinal — would suppress, and silently un-surface, a hit that
 *     judge never read. Each chunk's ids are therefore filtered to the hits
 *     that chunk actually contained, and anything dropped is reported.
 *
 *  2. CATEGORY DISTRUST. writeback.ts rejects a whole category whose
 *     `reasoning` echoes a raw detected value, explicitly so that "a poisoned
 *     first occurrence [is not] 'rescued' by a later duplicate — once a
 *     category leaked raw we distrust it for the whole run". Keeping only one
 *     chunk's reasoning would discard the poisoned sibling before that check
 *     ever runs. Every chunk's reasoning is therefore carried into the merged
 *     text, so `assertRawFree` sees all of it and one poisoned chunk still
 *     distrusts the category.
 */
import type {
  BuiltinPolicyId,
  DetectionCategory,
  TriageCategoryRec,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

const RANK: Record<BuiltinPolicyId, number> = { monitor: 0, warn: 1, redact: 2, block: 3 };

// One chunk's judgment, paired with the ids of the hits that chunk's judge
// actually saw. The pairing is the point: an `fpId` is only grounded in
// evidence when it names a hit that was in the batch the verdict describes.
export interface ChunkVerdict {
  readonly rec: TriageRecommendation;
  readonly ids: ReadonlySet<string>;
}

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

// The ids a chunk's judge saw, for pairing with its verdict. A hit the sink
// could not id contributes nothing — a verdict can't reference what has no id.
export function chunkIds(hits: readonly TriageHit[]): Set<string> {
  return new Set(hits.map((h) => h.id).filter((id): id is string => id !== undefined));
}

// Accumulator: a category's merged row plus every chunk's reasoning, kept with
// the rank of the action it argued for so the strictest one can lead.
interface CategoryAccumulator extends TriageCategoryRec {
  reasonings: { rank: number; text: string }[];
}

// The strictest chunk's reasoning first (it argues for the action that won), then
// the rest in chunk order — Array.sort is stable, so equal ranks keep their
// order. Identical texts collapse. Every chunk's text survives, which is what
// keeps writeback's raw-echo distrust honest across a merge.
function joinReasonings(reasonings: readonly { rank: number; text: string }[]): string {
  const ordered = [...reasonings].sort((a, b) => b.rank - a.rank);
  return [...new Set(ordered.map((r) => r.text.trim()).filter((t) => t !== ''))].join(' ');
}

// Drop every fpId that names a hit the judge behind this verdict did not see,
// and disclose each drop in `notes` — silence would look identical to a clean
// verdict at the human gate.
//
// This runs on EVERY judging path, not only the chunked one. Dedupe alone is
// enough to need it: the judge is shown the representative set while downstream
// consumers hold the full hit list, so an id naming a collapsed duplicate is an
// id the judge never read. Left ungrounded it is not merely inert — a
// value-scoped consumer expands one such id across the whole value class and
// silently buries a key the judge called genuine.
export function groundVerdict(
  rec: TriageRecommendation,
  ids: ReadonlySet<string>,
): TriageRecommendation {
  const perCategory: TriageCategoryRec[] = [];
  const strayNotes: string[] = [];
  for (const c of rec.perCategory) {
    const grounded = c.fpIds.filter((id) => ids.has(id));
    const strayCount = c.fpIds.length - grounded.length;
    if (strayCount > 0) {
      strayNotes.push(
        `${c.category}: dropped ${String(strayCount)} false-positive id(s) naming hits outside the batch they were judged in`,
      );
    }
    // fpCount keeps the model's CLAIMED count, deliberately NOT recomputed from
    // the grounded ids. resolve.ts compares the two and surfaces any divergence
    // to the human gate ('model reported N FPs, M resolved') — exactly the
    // signal a dropped stray id should raise; recomputing would erase it.
    perCategory.push({ ...c, fpIds: grounded });
  }
  return { perCategory, notes: [rec.notes, ...strayNotes].filter(Boolean).join('\n') };
}

export function mergeRecommendations(verdicts: readonly ChunkVerdict[]): TriageRecommendation {
  const byCat = new Map<DetectionCategory, CategoryAccumulator>();
  const grounded = verdicts.map((v) => groundVerdict(v.rec, v.ids));

  for (const rec of grounded) {
    for (const c of rec.perCategory) {
      const entry = { rank: RANK[c.action], text: c.reasoning };
      const prev = byCat.get(c.category);
      if (!prev) {
        byCat.set(c.category, { ...c, fpIds: [...c.fpIds], reasonings: [entry] });
        continue;
      }
      prev.genuineCount += c.genuineCount;
      prev.fpCount += c.fpCount;
      prev.fpIds = [...new Set([...prev.fpIds, ...c.fpIds])];
      prev.reasonings.push(entry);
      // Strictest action wins, so a merge can only ever tighten.
      if (RANK[c.action] > RANK[prev.action]) prev.action = c.action;
    }
  }

  const perCategory = [...byCat.values()].map(({ reasonings, ...cat }): TriageCategoryRec => ({
    ...cat,
    reasoning: joinReasonings(reasonings),
  }));
  return {
    perCategory,
    notes: grounded
      .map((r) => r.notes)
      .filter(Boolean)
      .join('\n'),
  };
}
