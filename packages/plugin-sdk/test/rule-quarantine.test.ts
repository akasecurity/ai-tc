import type { Rule } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { filterUnsafeRules, ruleProbeKey } from '../src/rule-quarantine.ts';

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

  it('quarantines remaining unchecked rules once the pass budget is exhausted', async () => {
    const gateway = fakeCacheGateway();
    const ruleA = regexRule('pack/a', 'AKIA[A-Z0-9]{16}');
    const ruleB = regexRule('pack/b', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([ruleA, ruleB], gateway, { passBudgetMs: -1 });

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(2);
    for (const call of gateway.setRuleProbeVerdict.mock.results) {
      expect(call).toBeDefined();
    }
    for (const call of gateway.setRuleProbeVerdict.mock.calls) {
      expect(call[1]).toBe('quarantined');
    }
  });
});
