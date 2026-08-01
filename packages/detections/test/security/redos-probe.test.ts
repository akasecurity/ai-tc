import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { BUDGET_MS, checkRuleTiming } from '../../src/security/redos-probe.ts';

function regexRule(pattern: string): Rule {
  return Rule.parse({
    specVersion: 1,
    id: 'test-pack/evil',
    name: 'evil',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  });
}

describe('checkRuleTiming', () => {
  it('flags a catastrophic pattern as unsafe', () => {
    const result = checkRuleTiming(regexRule('^(a+)+$'));
    expect(result.safe).toBe(false);
    expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
  });

  it('passes a benign pattern as safe', () => {
    const result = checkRuleTiming(regexRule('AKIA[A-Z0-9]{16}'));
    expect(result.safe).toBe(true);
    expect(result.worstMs).toBeLessThan(BUDGET_MS);
  });

  it('flags a rule whose interpreted-tier cost alone blows the budget', () => {
    // `^(a+)+bc` sits in the gap that separates a correct gate from a bypassed
    // one: on the battery's first probe it costs ~120ms in V8's Irregexp
    // bytecode interpreter and ~15ms once V8 tiers it up to native code. The
    // interpreted number is the one production pays, because a plugin hook is a
    // fresh short-lived process that scans each rule once.
    //
    // So this rule must come back unsafe. It does only while each probe is
    // timed exactly once. Any scheme that re-runs a probe and keeps the lower
    // sample reads the native tier instead and admits the rule — and because
    // V8 caches the compiled form against source+flags, rebuilding the matcher
    // between samples does not restore the interpreted cost.
    //
    // Deliberately no `performance.now` spy: a synthetic spike differs only in
    // an injected number, which is precisely the case a lower-of-two sample
    // handles correctly. Only a real pattern in this gap tells the two apart.
    const result = checkRuleTiming(regexRule('^(a+)+bc'));
    expect(
      result.safe,
      `expected ^(a+)+bc to be unsafe, got worstMs=${result.worstMs.toFixed(1)} on a ` +
        `${String(result.probe.length)}-char probe. If this rule now reads as safe, the gate is ` +
        `measuring V8's native tier rather than the interpreted cost a fresh hook process pays.`,
    ).toBe(false);
  });
});
