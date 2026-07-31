import type { checkRuleTiming as CheckRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { filterUnsafeRules, ruleProbeKey } from '../src/rule-quarantine.ts';

// Wrap the real `checkRuleTiming` in a spy so most tests exercise the actual
// probe battery unchanged, while the measurement-error test below can force
// a single call to throw via `mockImplementationOnce` (which reverts to this
// real implementation for every subsequent call).
vi.mock('@akasecurity/detections', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, checkRuleTiming: vi.fn(actual.checkRuleTiming as typeof CheckRuleTiming) };
});

const { checkRuleTiming } = await import('@akasecurity/detections');
const checkRuleTimingMock = vi.mocked(checkRuleTiming);

function regexRule(id: string, pattern: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  };
}

function keywordRule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['x'], caseSensitive: false },
  };
}

function fakeCacheGateway() {
  const store = new Map<string, { verdict: 'safe' | 'quarantined'; worstProbeMs: number }>();
  const getRuleProbeVerdict = vi.fn((key: string) => Promise.resolve(store.get(key)));
  const setRuleProbeVerdict = vi.fn(
    (key: string, verdict: 'safe' | 'quarantined', worstProbeMs: number) => {
      store.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
  );
  return { getRuleProbeVerdict, setRuleProbeVerdict, store };
}

describe('filterUnsafeRules', () => {
  it('passes a benign regex rule through and caches it as safe', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/benign', 'AKIA[A-Z0-9]{16}');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('excludes a catastrophic regex rule and caches it as quarantined', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('passes non-regex rules through unchecked', async () => {
    const gateway = fakeCacheGateway();
    const rule = keywordRule('pack/keyword');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.getRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('reuses a cached verdict instead of re-measuring', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');
    const key = ruleProbeKey(rule);
    if (key === undefined) throw new Error('expected a rule key for a regex rule');
    gateway.store.set(key, { verdict: 'quarantined', worstProbeMs: 150 });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('reuses a cached safe verdict instead of re-measuring', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/cached-safe', 'AKIA[A-Z0-9]{16}');
    const key = ruleProbeKey(rule);
    if (key === undefined) throw new Error('expected a rule key for a regex rule');
    gateway.store.set(key, { verdict: 'safe', worstProbeMs: 75 });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('excludes remaining unchecked rules once the pass budget is exhausted, without caching a verdict for them', async () => {
    const gateway = fakeCacheGateway();
    const ruleA = regexRule('pack/a', 'AKIA[A-Z0-9]{16}');
    const ruleB = regexRule('pack/b', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([ruleA, ruleB], gateway, { passBudgetMs: -1 });

    expect(result).toEqual([]);
    // Neither rule was ever actually measured (the budget was exhausted
    // before reaching either), so no verdict should be persisted for
    // either — persisting 'quarantined' here would permanently and
    // silently exclude a rule that might be perfectly safe.
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
    expect(gateway.store.size).toBe(0);
  });

  it('treats a cache-read failure as a cache miss and still measures the rule', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/benign-read-error', 'AKIA[A-Z0-9]{16}');
    gateway.getRuleProbeVerdict.mockImplementationOnce(() =>
      Promise.reject(new Error('transient store read error')),
    );

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('quarantines a rule whose timing measurement itself throws, and persists the verdict', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/measurement-blows-up', 'AKIA[A-Z0-9]{16}');
    checkRuleTimingMock.mockImplementationOnce(() => {
      throw new Error('probe battery exploded');
    });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('keeps the rule when the store refuses the verdict, and does not lose the pass', async () => {
    // The verdict is a cache, not a decision: the decision for THIS pass is
    // already in hand. A store that will not take the write costs one
    // re-measurement next process and nothing else — it must never abort the
    // pass and take the rest of the pack down with it.
    const gateway = fakeCacheGateway();
    gateway.setRuleProbeVerdict.mockImplementationOnce(() =>
      Promise.reject(new Error('SQLITE_READONLY')),
    );
    const first = regexRule('pack/write-fails', 'AKIA[A-Z0-9]{16}');
    const second = regexRule('pack/after', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([first, second], gateway);

    expect(result).toEqual([first, second]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(2);
  });
});

// The battery decides whether a pattern is safe by driving it into
// backtracking, so measuring a rule is a way to hang on it. When the caller
// supplies somewhere killable to run the measurement, the filter must use it —
// and must treat "could not measure" and "measured, and it never returned" as
// the opposite verdicts they are.
describe('filterUnsafeRules with a prober', () => {
  const rule = regexRule('pulled/needs-measuring', 'AKIA[A-Z0-9]{16}');

  // The spy is module-scoped, so its call log carries over from the suite
  // above. These cases assert it was NOT called, which is vacuously false
  // without this.
  beforeEach(() => {
    checkRuleTimingMock.mockClear();
  });

  it('takes the prober verdict instead of measuring on this thread', async () => {
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() => Promise.resolve({ status: 'ok' as const, safe: true, worstMs: 1.5 }));

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([rule]);
    expect(probe).toHaveBeenCalledWith(rule);
    // The unbounded in-process call is exactly what the prober replaces.
    expect(checkRuleTimingMock).not.toHaveBeenCalled();
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('persists a quarantine when the measurement had to be terminated', async () => {
    // Stronger evidence than an over-budget probe, not weaker: the pattern did
    // not merely run long, it never came back. Caching it is what stops the
    // next process paying the same deadline to learn the same thing.
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() =>
      Promise.resolve({ status: 'timeout' as const, culpritIndex: undefined, elapsedMs: 1_000 }),
    );

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('excludes without persisting when there is nowhere safe to measure', async () => {
    // No worker means no measurement. Falling back to this thread would restore
    // the unbounded call, and caching a verdict would condemn a rule that was
    // never actually timed — so the rule sits out this pass and is measured
    // again next process.
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() =>
      Promise.resolve({ status: 'unavailable' as const, reason: 'no worker script' }),
    );

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([]);
    expect(checkRuleTimingMock).not.toHaveBeenCalled();
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('never reaches the prober for a rule whose verdict is already cached', async () => {
    // The steady state on any machine that has loaded its packs once. A worker
    // started here would be a thread per hook invocation, for nothing.
    const gateway = fakeCacheGateway();
    const key = ruleProbeKey(rule);
    gateway.store.set(key ?? '', { verdict: 'safe', worstProbeMs: 1 });
    const probe = vi.fn(() => Promise.resolve({ status: 'ok' as const, safe: true, worstMs: 0 }));

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([rule]);
    expect(probe).not.toHaveBeenCalled();
  });
});
