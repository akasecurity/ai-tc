import type { TriageCategoryRec, TriageHit, TriageRecommendation } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  chunkForJudge,
  chunkIds,
  type ChunkVerdict,
  groundVerdict,
  mergeRecommendations,
} from '../../src/triage/merge.ts';

const hit = (o: Partial<TriageHit> = {}): TriageHit => ({
  ruleId: 'r',
  category: 'secret',
  severity: 'high',
  maskedMatch: 'm',
  rawMatch: 'raw',
  context: 'c',
  confidence: 0.9,
  ...o,
});

const cat = (o: Partial<TriageCategoryRec> = {}): TriageCategoryRec => ({
  category: 'secret',
  action: 'warn',
  reasoning: 'r',
  genuineCount: 0,
  fpCount: 0,
  fpIds: [],
  ...o,
});

const chunk = (rec: TriageRecommendation, ids: string[]): ChunkVerdict => ({
  rec,
  ids: new Set(ids),
});

const secretOf = (m: TriageRecommendation): TriageCategoryRec => {
  const c = m.perCategory.find((x) => x.category === 'secret');
  if (c === undefined) throw new Error('expected a merged secret category');
  return c;
};

describe('mergeRecommendations', () => {
  it('merges per category: sums, unions ids, strictest action wins', () => {
    const m = mergeRecommendations([
      chunk(
        {
          perCategory: [
            cat({ action: 'warn', reasoning: 'a', genuineCount: 1, fpCount: 1, fpIds: ['1'] }),
          ],
          notes: 'n1',
        },
        ['1'],
      ),
      chunk(
        {
          perCategory: [
            cat({ action: 'redact', reasoning: 'b', genuineCount: 2, fpCount: 0, fpIds: [] }),
            cat({ category: 'pii', action: 'warn', reasoning: 'c', genuineCount: 1 }),
          ],
          notes: 'n2',
        },
        ['2'],
      ),
    ]);
    const sec = secretOf(m);
    expect([sec.genuineCount, sec.fpCount, sec.action, sec.fpIds]).toEqual([3, 1, 'redact', ['1']]);
    expect(m.notes).toBe('n1\nn2');
  });

  // The grounding invariant a single judgment gave for free: ids are global
  // stream ordinals, so a chunk that renumbers locally names a sibling chunk's
  // hits. Such an id must never reach the join, or it suppresses — and
  // un-surfaces — a genuine finding its judge never read.
  it('drops fpIds naming hits outside the chunk they were judged in, and says so', () => {
    const m = mergeRecommendations([
      chunk({ perCategory: [cat({ fpCount: 1, fpIds: ['0'] })], notes: '' }, ['0', '1']),
      // This judge only saw ids '2'/'3' but returned '0' — chunk 1's genuine hit.
      chunk({ perCategory: [cat({ fpCount: 2, fpIds: ['2', '0'] })], notes: '' }, ['2', '3']),
    ]);
    const sec = secretOf(m);
    expect(sec.fpIds).toEqual(['0', '2']);
    expect(m.notes).toContain('dropped 1 false-positive id(s)');
    // The model's CLAIMED count is summed unchanged, so resolve.ts still raises
    // the count-vs-resolved discrepancy at the human gate rather than the drop
    // passing as a clean verdict.
    expect(sec.fpCount).toBe(3);
  });

  it('keeps every chunk id when each verdict stays inside its own batch', () => {
    const m = mergeRecommendations([
      chunk({ perCategory: [cat({ fpCount: 1, fpIds: ['0'] })], notes: '' }, ['0', '1']),
      chunk({ perCategory: [cat({ fpCount: 1, fpIds: ['2'] })], notes: '' }, ['2', '3']),
    ]);
    expect(secretOf(m).fpIds).toEqual(['0', '2']);
  });

  it('folds an empty verdict list to an empty recommendation', () => {
    expect(mergeRecommendations([])).toEqual({ perCategory: [], notes: '' });
  });

  // writeback.ts rejects a category whose reasoning echoes a raw value, and says
  // why: "once a category leaked raw we distrust it for the whole run". Keeping
  // only the winning chunk's reasoning would throw the poisoned sibling away
  // before assertRawFree ever saw it.
  it('carries every chunk reasoning into the merged text so a poisoned chunk cannot be dropped', () => {
    const m = mergeRecommendations([
      chunk(
        {
          perCategory: [cat({ action: 'warn', reasoning: 'the key AKIAIOSFODNN7EXAMPLE is real' })],
          notes: '',
        },
        ['0'],
      ),
      chunk({ perCategory: [cat({ action: 'redact', reasoning: 'clean prose' })], notes: '' }, [
        '1',
      ]),
    ]);
    const sec = secretOf(m);
    expect(sec.action).toBe('redact');
    // Strictest first (it argued for the winning action), poisoned text retained.
    expect(sec.reasoning).toBe('clean prose the key AKIAIOSFODNN7EXAMPLE is real');
  });

  it('collapses identical reasonings instead of repeating them', () => {
    const m = mergeRecommendations([
      chunk({ perCategory: [cat({ reasoning: 'same' })], notes: '' }, ['0']),
      chunk({ perCategory: [cat({ reasoning: 'same' })], notes: '' }, ['1']),
    ]);
    expect(secretOf(m).reasoning).toBe('same');
  });
});

describe('chunkForJudge', () => {
  it('chunkForJudge returns a single chunk under the cap', () => {
    expect(chunkForJudge([hit()], 262_144)).toHaveLength(1);
  });

  it('splits once the serialized budget is exceeded, losing no hit and keeping order', () => {
    const hits = Array.from({ length: 20 }, (_, i) => hit({ id: String(i) }));
    const [first] = hits;
    if (first === undefined) throw new Error('unreachable: fixed-length array');
    const oneHit = Buffer.byteLength(JSON.stringify(first)) + 1;
    const chunks = chunkForJudge(hits, oneHit * 5);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks.flat()).toHaveLength(20);
    expect(chunks.flatMap((c) => c.map((h) => h.id))).toEqual(hits.map((h) => h.id));
  });

  it('gives a single over-budget hit its own chunk rather than dropping it', () => {
    const chunks = chunkForJudge([hit({ id: '0' }), hit({ id: '1' })], 1);
    expect(chunks.map((c) => c.map((h) => h.id))).toEqual([['0'], ['1']]);
  });
});

describe('chunkIds', () => {
  it('collects the ids a judge saw and ignores un-idd hits', () => {
    expect([...chunkIds([hit({ id: '7' }), hit({ id: undefined }), hit({ id: '9' })])]).toEqual([
      '7',
      '9',
    ]);
  });
});

describe('groundVerdict', () => {
  // Runs on every judging path, not only the chunked one: dedupe alone makes the
  // judged set a strict subset of the hits downstream consumers hold.
  it('drops ids outside the judged set, discloses the drop, and keeps the claimed fpCount', () => {
    const g = groundVerdict(
      { perCategory: [cat({ fpCount: 2, fpIds: ['0', '9'] })], notes: 'n' },
      new Set(['0']),
    );
    expect(g.perCategory[0]?.fpIds).toEqual(['0']);
    // The claimed count is untouched so resolve.ts still raises the discrepancy.
    expect(g.perCategory[0]?.fpCount).toBe(2);
    expect(g.notes).toBe(
      'n\nsecret: dropped 1 false-positive id(s) naming hits outside the batch they were judged in',
    );
  });

  it('is a no-op when every id was judged', () => {
    const rec = { perCategory: [cat({ fpCount: 1, fpIds: ['0'] })], notes: '' };
    expect(groundVerdict(rec, new Set(['0', '1']))).toEqual(rec);
  });
});
