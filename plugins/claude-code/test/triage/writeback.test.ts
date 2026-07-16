import type { ActionTaken, DetectionCategory, TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  parseTriageStream,
  performTriageWriteback,
  planTriageWriteback,
  SCRUBBED_NOTES,
} from '../../src/triage/writeback.ts';

const RAW = 'AKIAIOSFODNN7EXAMPLE';
const FP = 'ab'.repeat(32);

const hit = (over: Partial<TriageHit> = {}): TriageHit => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW,
  context: `export KEY=${RAW} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: FP,
  keyVersion: 1,
  ...over,
});

const rec = (
  cats: {
    category?: DetectionCategory;
    action?: 'monitor' | 'warn' | 'redact' | 'block';
    reasoning?: string;
    genuineCount?: number;
    fpCount?: number;
    fpIds?: string[];
  }[],
  notes = '',
) => ({
  perCategory: cats.map((c) => ({
    category: c.category ?? 'secret',
    action: c.action ?? ('warn' as const),
    reasoning: c.reasoning ?? 'canonical fake AWS example key',
    genuineCount: c.genuineCount ?? 0,
    fpCount: c.fpCount ?? 1,
    fpIds: c.fpIds ?? ['0'],
  })),
  notes,
});

// ----------------------------------------------------------------------------
// parseTriageStream
// ----------------------------------------------------------------------------

describe('parseTriageStream', () => {
  it('parses a complete stream of hit lines terminated by the sentinel', () => {
    const stream =
      JSON.stringify(hit({ id: '0' })) +
      '\n' +
      JSON.stringify(hit({ id: '1' })) +
      '\n' +
      JSON.stringify({ done: true, count: 2, status: 'complete' }) +
      '\n';
    const { hits, status } = parseTriageStream(stream);
    expect(status).toBe('complete');
    expect(hits.map((h) => h.id)).toEqual(['0', '1']);
  });

  it('returns no hits for a skipped:no-consent sentinel', () => {
    const stream = JSON.stringify({ done: true, count: 0, status: 'skipped:no-consent' }) + '\n';
    const { hits, status } = parseTriageStream(stream);
    expect(hits).toEqual([]);
    expect(status).toBe('skipped:no-consent');
  });

  it('fails LOUD on an unrecognized sentinel status instead of silently skipping', () => {
    // A version-skewed / corrupted producer emits a status this consumer does not
    // know. It must NOT be treated as a clean zero-hit skip (which would tell the
    // user their history was cleanly triaged when the outcome was never understood).
    const stream = JSON.stringify({ done: true, count: 0, status: 'skipped:new-reason' }) + '\n';
    expect(() => parseTriageStream(stream)).toThrow(/unrecognized status/i);
  });

  it('throws on a truncated stream (no sentinel) rather than treating it as empty', () => {
    const stream = JSON.stringify(hit()) + '\n';
    expect(() => parseTriageStream(stream)).toThrow(/truncat|sentinel/i);
  });

  it('throws when the sentinel count disagrees with the hit lines seen', () => {
    const stream =
      JSON.stringify(hit()) +
      '\n' +
      JSON.stringify({ done: true, count: 5, status: 'complete' }) +
      '\n';
    expect(() => parseTriageStream(stream)).toThrow(/count/i);
  });

  it('never leaks the raw value when the final (sentinel) line is truncated JSON', () => {
    // A crash mid-write leaves a partial last line carrying raw context. JSON.parse
    // would echo it in a SyntaxError — assert the thrown message stays raw-free.
    const stream = `{"rawMatch":"${RAW}","context":"export KEY=${RAW}`; // truncated, no newline/sentinel
    try {
      parseTriageStream(stream);
      throw new Error('expected parseTriageStream to throw');
    } catch (err) {
      expect((err as Error).message).not.toContain(RAW);
    }
  });

  it('never leaks the raw value when a hit line fails JSON/TriageHit validation', () => {
    const badHit = `{"ruleId":"x","rawMatch":"${RAW}","context":"${RAW}","severity":"NOT_A_SEVERITY"}`;
    const stream =
      badHit + '\n' + JSON.stringify({ done: true, count: 1, status: 'complete' }) + '\n';
    try {
      parseTriageStream(stream);
      throw new Error('expected parseTriageStream to throw');
    } catch (err) {
      expect((err as Error).message).not.toContain(RAW);
      expect((err as Error).message).toMatch(/hit line 0/);
    }
  });
});

// ----------------------------------------------------------------------------
// planTriageWriteback
// ----------------------------------------------------------------------------

describe('planTriageWriteback', () => {
  it('resolves a clean verdict into suppression entries, posture, and raw-free notes', () => {
    const plan = planTriageWriteback([hit()], rec([{ action: 'warn' }], 'looks routine'));
    expect(plan.entries).toHaveLength(1);
    expect(plan.entries[0]).toMatchObject({
      ruleId: 'core-secret/aws',
      category: 'secret',
      valueFingerprint: FP,
      keyVersion: 1,
      justification: 'canonical fake AWS example key',
    });
    expect(plan.posture).toEqual({ secret: 'warn' });
    expect(plan.notes).toBe('looks routine');
    expect(plan.skipped).toEqual([]);
    // masked value never equals the raw value
    expect(plan.entries[0]?.maskedValue).not.toContain(RAW);
  });

  it('rejects a category whose reasoning echoes a raw value (req 1: model-text raw-reject)', () => {
    const planted = rec([{ reasoning: `this ${RAW} is obviously fake` }]);
    const plan = planTriageWriteback([hit()], planted);
    // no suppression written for the poisoned category — fail secure
    expect(plan.entries).toEqual([]);
    // and its posture is NOT applied either (the whole category is distrusted)
    expect(plan.posture).toEqual({});
    expect(plan.skipped).toEqual([expect.objectContaining({ category: 'secret' })]);
    expect(plan.skipped[0]?.reason).toMatch(/raw/i);
  });

  it('keeps a clean category while rejecting a sibling that leaked raw', () => {
    const hits = [hit({ id: '0' }), hit({ id: '1', category: 'pii', ruleId: 'core-pii/email' })];
    const planted = rec([
      { category: 'secret', fpIds: ['0'], reasoning: 'canonical example key' },
      { category: 'pii', fpIds: ['1'], reasoning: `leaked ${RAW} here`, action: 'block' },
    ]);
    const plan = planTriageWriteback(hits, planted);
    expect(plan.entries.map((e) => e.category)).toEqual(['secret']);
    expect(plan.posture).toEqual({ secret: 'warn' });
    expect(plan.skipped).toEqual([expect.objectContaining({ category: 'pii' })]);
  });

  it('scrubs model notes that echo a raw value (req 1: notes raw-reject)', () => {
    const plan = planTriageWriteback([hit()], rec([{}], `note mentioning ${RAW}`));
    expect(plan.notes).toBe(SCRUBBED_NOTES);
    // a clean category is unaffected by a poisoned notes field
    expect(plan.entries).toHaveLength(1);
  });

  it('RELAX: an fpCount mismatch resolves the mappable ids and surfaces the discrepancy', () => {
    // fpCount 2 but a single listed+resolvable id: the category is NOT dropped
    // wholesale anymore (the human gate is the fail-secure guard). The one id
    // resolves and the count discrepancy is recorded for the preview.
    const plan = planTriageWriteback([hit()], rec([{ fpCount: 2, fpIds: ['0'] }]));
    expect(plan.entries).toHaveLength(1);
    expect(plan.skipped.some((s) => /discrepancy/i.test(s.reason))).toBe(true);
  });

  it('builds a per-category showcase for EVERY surviving category, incl. one with no FPs', () => {
    const hits = [hit({ id: '0' }), hit({ id: '1', category: 'pii', ruleId: 'core-pii/email' })];
    const plan = planTriageWriteback(
      hits,
      rec([
        { category: 'secret', action: 'warn', fpIds: ['0'], genuineCount: 3, fpCount: 1 },
        // A genuine-hit category with zero false positives — still shown.
        {
          category: 'pii',
          action: 'block',
          fpIds: [],
          fpCount: 0,
          genuineCount: 2,
          reasoning: 'real customer emails',
        },
      ]),
    );
    expect(plan.showcase).toEqual([
      {
        category: 'secret',
        action: 'warn',
        genuineCount: 3,
        fpCount: 1,
        reasoning: 'canonical fake AWS example key',
      },
      {
        category: 'pii',
        action: 'block',
        genuineCount: 2,
        fpCount: 0,
        reasoning: 'real customer emails',
      },
    ]);
    // the no-FP category produced no suppression entry but still appears above
    expect(plan.entries.map((e) => e.category)).toEqual(['secret']);
  });

  it('omits a raw-poisoned category from the showcase (fail-secure)', () => {
    const plan = planTriageWriteback([hit()], rec([{ reasoning: `leaked ${RAW}` }]));
    expect(plan.showcase).toEqual([]);
  });
});

// ----------------------------------------------------------------------------
// performTriageWriteback
// ----------------------------------------------------------------------------

describe('performTriageWriteback', () => {
  function fakeWriters() {
    const posture: Record<string, ActionTaken> = {};
    const created: unknown[] = [];
    return {
      posture,
      created,
      writers: {
        policies: {
          getCategoryAction: (c: DetectionCategory) => posture[c],
          upsertCategoryAction: (c: DetectionCategory, a: ActionTaken) => {
            posture[c] = a;
          },
        },
        exceptions: {
          create: (input: unknown) => {
            created.push(input);
            return Promise.resolve();
          },
        },
      },
    };
  }

  it('writes posture (overwrite) and one suppression per entry', async () => {
    const plan = planTriageWriteback([hit()], rec([{ action: 'redact' }]));
    const fake = fakeWriters();
    const res = await performTriageWriteback(plan, fake.writers, { createdBy: 'me', now: 0 });
    expect(res.written).toBe(1);
    expect(res.categoriesWritten).toBe(1);
    expect(fake.posture).toEqual({ secret: 'redact' }); // redact palette -> redact action
    expect(fake.created).toHaveLength(1);
    expect(fake.created[0]).toMatchObject({ createdVia: 'setup-triage', createdBy: 'me' });
  });

  it('does not write any suppression when the plan resolved none', async () => {
    // fpIds point at an id absent from the join, so nothing resolves regardless
    // of the relaxed count check.
    const plan = planTriageWriteback([hit()], rec([{ fpCount: 0, fpIds: ['404'] }]));
    const fake = fakeWriters();
    const res = await performTriageWriteback(plan, fake.writers, { createdBy: 'me', now: 0 });
    expect(res.written).toBe(0);
    expect(fake.created).toEqual([]);
  });

  it('rolls back everything when a suppression write fails mid-batch (all-or-nothing)', async () => {
    // Two entries; the second create throws a non-duplicate fault. With a real
    // transaction the posture overwrite and the first insert must both roll back.
    const hits = [hit({ id: '0' }), hit({ id: '1', valueFingerprint: 'cd'.repeat(32) })];
    const plan = planTriageWriteback(
      hits,
      rec([{ action: 'redact', fpCount: 2, fpIds: ['0', '1'] }]),
    );

    // A fake store with snapshot/restore transaction semantics: on a throw it
    // restores the posture map, mimicking a SQLite ROLLBACK across both writes.
    const posture: Record<string, ActionTaken> = {};
    const created: unknown[] = [];
    let calls = 0;
    const writers = {
      policies: {
        getCategoryAction: (c: DetectionCategory) => posture[c],
        upsertCategoryAction: (c: DetectionCategory, a: ActionTaken) => {
          posture[c] = a;
        },
      },
      exceptions: {
        create: () => {
          calls++;
          if (calls === 2) return Promise.reject(new Error('disk full'));
          created.push('row');
          return Promise.resolve();
        },
      },
      transaction: async <T>(fn: () => Promise<T>): Promise<T> => {
        const snapshot = { ...posture };
        try {
          return await fn();
        } catch (err) {
          for (const k of Object.keys(posture)) Reflect.deleteProperty(posture, k);
          Object.assign(posture, snapshot);
          created.length = 0; // the inserts roll back too
          throw err;
        }
      },
    };

    await expect(
      performTriageWriteback(plan, writers, { createdBy: 'me', now: 0 }),
    ).rejects.toThrow(/disk full/);
    // nothing persisted: posture NOT overwritten, no exception row survived
    expect(posture).toEqual({});
    expect(created).toEqual([]);
  });
});
