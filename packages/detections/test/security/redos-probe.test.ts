import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import { BUDGET_MS, checkRuleTiming, worstProbeMs } from '../../src/security/redos-probe.ts';

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
    // This assertion is machine-speed-dependent, and its margin is thin: the
    // verdict rests entirely on probe #0, because once that probe has run the
    // pattern is tiered up and every later probe is native — the 25-char one
    // costs ~70ms here, already inside the budget. So the margin is exactly
    // probe #0's interpreted cost over BUDGET_MS: ~1.29x on the machine this
    // was written on, 1.41x on another. Hardware around a third faster flips it
    // red. CI runners are generally slower than a dev machine, which is the
    // safe direction, and it did not flake in 9 runs including 4 under full CPU
    // load — but read the failure message before believing a regression.
    const result = checkRuleTiming(regexRule('^(a+)+bc'));
    expect(
      result.safe,
      `expected ^(a+)+bc to be unsafe, got worstMs=${result.worstMs.toFixed(1)} on a ` +
        `${String(result.probe.length)}-char probe (budget ${String(BUDGET_MS)}ms). Check the ` +
        `scale-free test below FIRST: if it still passes, the gate is measuring the interpreted ` +
        `tier correctly and this machine is simply fast enough that ^(a+)+bc no longer clears ` +
        `the budget interpreted — retune the pattern, do not touch the timing loop. Both red ` +
        `means the gate really has started reading V8's native tier.`,
    ).toBe(false);
  });
});

describe('worstProbeMs attributes a probe to its interpreted tier', () => {
  // The verdict test above buys its directness with a ~1.3x margin. This one
  // carries no absolute millisecond threshold at all: both quantities are
  // measured on the machine running them, so hardware speed and CPU contention
  // move them together and cancel — the same reason `backtrackRatio` and
  // CATASTROPHIC_RATIO exist rather than a fixed ms bound.
  it('reports the first probe at its interpreted cost, not its native cost', () => {
    const rule = regexRule('^(a+)+bd');
    const result = worstProbeMs(rule);

    // Timed once, the walk's worst probe is its FIRST one — the only probe that
    // runs before V8 tiers the pattern up. Interpreted, that probe costs ~7.4x
    // what it costs native; the next probe up is 2 chars longer, so ~4x, and it
    // runs after tier-up. 7.4x beats 4x on any clock, so probe #0 wins on any
    // machine. Keep the lower of two samples at probe #0 and it drops to ~1x,
    // handing the title to the 25-char probe — measured 24 vs 26 chars here.
    expect(
      result.probe.length,
      `expected the 23-char-fuel probe (24 chars) to be the worst, got ` +
        `${String(result.probe.length)} chars at ${result.ms.toFixed(1)}ms. A longer probe winning ` +
        `means the first probe's interpreted cost was discarded — a second sample of it was taken ` +
        `and the cheaper, tiered-up one kept.`,
    ).toBe(24);

    // And the cost carried forward is the interpreted one. Re-scanning that
    // same probe now measures the native tier, so a correct gate reports
    // several times what this second sample costs; a gate that kept a second
    // sample reports the same thing twice, and the ratio collapses to ~1.
    const start = performance.now();
    scan(result.probe, [rule]);
    const nativeMs = performance.now() - start;
    const ratio = result.ms / nativeMs;
    expect(
      ratio,
      `gate reported ${result.ms.toFixed(1)}ms for a probe that re-scans in ${nativeMs.toFixed(1)}ms ` +
        `(ratio ${ratio.toFixed(2)}x). Measured 6.9-7.7x when each probe is timed once and ` +
        `0.95-1.16x with a lower-of-two-samples bypass in place, so a ratio near 1 means the ` +
        `interpreted tier is no longer what the gate reports.`,
    ).toBeGreaterThan(3);
  });
});
