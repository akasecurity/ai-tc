import { Rule } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { scan } from '../../src/index.ts';
import type { ProbeClock } from '../../src/security/redos-probe.ts';
import {
  BUDGET_MS,
  checkRuleTiming,
  CORROBORATION_FLOOR_MS,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';

// The corroborating clock the PRODUCT supplies, standing in for the per-thread
// CPU reading `@akasecurity/plugin-sdk` passes in. This package takes no
// Node-API dependency, so the real one cannot live here — but `process` exists
// under vitest, and what these cases need is a clock that reads WORK rather
// than elapsed time.
const workClock: ProbeClock = () => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

// A corroborating clock that reports no work at all, whatever really ran. This
// is a scheduler stall expressed at the seam that represents one: the thread
// accrued wall time having executed nothing.
const noWork: ProbeClock = () => 0;

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

// A fixed CPU-bound workload used only to ask whether this machine ran at the
// same speed either side of a measurement. It touches no Rule and calls no
// scan(): running the rule under test even once before `worstProbeMs` would tier
// its pattern up, and the interpreted reading — the property the ratio case
// exists to check — only exists on the first run.
//
// `sink` escapes the loop so the whole thing cannot be optimised away.
//
// The ITERATION COUNT and the sample count are both load-bearing, and getting
// them wrong fails silently in the dangerous direction. This reading is a proxy
// for what contention does to the native loop below, so it has to be about as
// susceptible to contention AS that loop — same order of duration, same min-of-N
// shape. Sized at ~4ms against a ~18ms scan it is strictly HARDER to disturb,
// because `min` finds a quiet slot inside a short workload far more easily than
// inside a long one: driven with load arriving on the native loop, a 4ms probe
// moved 1.44x while the thing it was standing in for moved 5.3x, so the guard
// sat under its budget and the false failure went through anyway. Keep this
// it near the native scan's own duration, and re-check it if either moves.
let sink = 0;
function calibrationMs(samples = 5): number {
  let ms = Infinity;
  for (let i = 0; i < samples; i++) {
    const start = performance.now();
    let acc = 0;
    for (let j = 0; j < 9_000_000; j++) acc = (acc + j) % 9973;
    sink = (sink + acc) % 2_147_483_647;
    ms = Math.min(ms, performance.now() - start);
  }
  // Reading `sink` is what makes the accumulation above observable. Written and
  // never read, the whole loop is dead code — free for V8 to drop and for the
  // unused-var rule to flag — and a calibration that measures an empty loop
  // reports a machine that is never busy, so the guard below would never fire.
  if (!Number.isFinite(sink)) throw new Error('calibration workload collapsed');
  return ms;
}

// How far the two calibration readings may diverge before the ratio below is
// treated as unmeasurable rather than failed. Contention that is present for the
// WHOLE test is the safe direction and does not trip this: it inflates the
// ~135ms numerator and the ~18ms denominator alike, and the ratio rises. What
// this catches is contention that differs ACROSS the two windows — the numerator
// is timed inside `worstProbeMs`, the denominator ~135ms later — because that is
// the only thing that can inflate the denominator alone.
const MAX_CALIBRATION_DRIFT = 1.5;

describe('checkRuleTiming', () => {
  it('flags a catastrophic pattern as unsafe', () => {
    const result = checkRuleTiming(regexRule('^(a+)+$'), workClock);
    expect(result.verdict).toBe('over-budget');
    expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
  });

  it('passes a benign pattern as safe', () => {
    const result = checkRuleTiming(regexRule('AKIA[A-Z0-9]{16}'), workClock);
    expect(result.verdict).toBe('safe');
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
    const result = checkRuleTiming(regexRule('^(a+)+bc'), workClock);
    expect(
      result.verdict,
      `expected ^(a+)+bc to be unsafe, got worstMs=${result.worstMs.toFixed(1)} on a ` +
        `${String(result.probe.length)}-char probe (budget ${String(BUDGET_MS)}ms). Check the ` +
        `scale-free test below FIRST: if it still passes, the gate is measuring the interpreted ` +
        `tier correctly and this machine is simply fast enough that ^(a+)+bc no longer clears ` +
        `the budget interpreted — retune the pattern, do not touch the timing loop. Both red ` +
        `means the gate really has started reading V8's native tier.`,
    ).toBe('over-budget');
  });

  // `worstProbeMs` takes its clock as a parameter so the bundled-rule CI gate
  // can charge CPU time instead (see security/redos.test.ts, which explains
  // why). What must NOT move is which clock DECIDES: `checkRuleTiming` excludes
  // a rule on wall time, because what a slow rule would spend is the hook's
  // harness timeout and a harness timeout is wall-clock.
  //
  // The corroborating clock decides something else and only something else —
  // whether the breach may be REMEMBERED. Keeping the two apart is the whole
  // design: swap them and a rule that genuinely stalls the hook stops being
  // excluded, because a pattern can spend a harness timeout without burning CPU.
  //
  // Nothing else in this workspace pins the deciding clock. Flipped to CPU time
  // it changes which rules get disabled on user machines and leaves every OTHER
  // timing suite here and in plugin-sdk green, because a catastrophic pattern is
  // over budget on either resource — the two clocks disagree only on a stalled
  // machine. So this asserts the binding directly.
  it('decides exclusion on wall time, the resource the harness timeout is measured in', () => {
    // Benign and unique to this file: the walk finishes in microseconds, and a
    // pattern no other case here compiles cannot disturb their tier-up.
    const rule = regexRule('ZZQ[0-9]{6}');
    const wall = vi.spyOn(performance, 'now');
    try {
      const reads: number[] = [];
      checkRuleTiming(rule, () => {
        reads.push(1);
        return 0;
      });
      expect(
        wall,
        'the deciding probe clock must read wall time — the pre-flight excludes a rule for what ' +
          'it would spend against a wall-clock harness timeout.',
      ).toHaveBeenCalled();
      expect(
        reads.length,
        'the corroborating clock must actually be read, or every breach is uncorroborated and ' +
          'no rule is ever quarantined again.',
      ).toBeGreaterThan(0);
    } finally {
      wall.mockRestore();
    }
  });

  // The corroborating clock may only ever REMOVE a reason to cache, never add
  // one. Without this, a clock that over-reports (a process-wide fallback
  // charging another thread's work, say) could push a rule that is comfortably
  // inside the budget into a quarantine.
  it('cannot make an under-budget rule unsafe, however much work it reports', () => {
    let t = 0;
    const wildlyOverReporting: ProbeClock = () => (t += 10 * BUDGET_MS);
    const result = checkRuleTiming(regexRule('AKIA[A-Z0-9]{16}'), wildlyOverReporting);
    expect(result.verdict).toBe('safe');
    expect(result.worstMs).toBeLessThan(BUDGET_MS);
  });

  // The defect this whole split exists for, reproduced at the seam that
  // represents it. A perfectly ordinary pattern, a wall clock that reports a
  // stall, and a work clock reporting the truth: the rule is over the wall
  // budget and it did no work, so it must NOT be cacheable.
  //
  // A benign rule rather than a catastrophic one is the point — this is the
  // false accusation, and it has to be a rule that would have been fine.
  it('reports a wall breach with no work behind it as uncorroborated, not over budget', () => {
    const rule = regexRule('ZZQSTALL[0-9]{6}');
    // Each read jumps a whole budget, so the FIRST probe is over budget however
    // fast the machine really is. Nothing here depends on this host's speed.
    let reads = 0;
    const stalled = vi.spyOn(performance, 'now').mockImplementation(() => reads++ * BUDGET_MS * 2);
    try {
      const result = checkRuleTiming(rule, workClock);
      expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
      expect(
        result.verdict,
        'a wall breach that burned no CPU is a busy machine, not a slow pattern. Caching it ' +
          'disables a rule the user installed, permanently, and nothing ever re-measures.',
      ).toBe('uncorroborated');
      expect(result.corroboratedMs).toBeLessThan(CORROBORATION_FLOOR_MS);
    } finally {
      stalled.mockRestore();
    }
  });

  // …and the other side of the same seam, so the case above is not passing
  // because corroboration never succeeds. Same stalled wall clock, same
  // breach — only the work reading differs, and that alone flips the verdict.
  it('reports the same wall breach as over budget when the work clock corroborates it', () => {
    const rule = regexRule('ZZQWORK[0-9]{6}');
    let reads = 0;
    const stalled = vi.spyOn(performance, 'now').mockImplementation(() => reads++ * BUDGET_MS * 2);
    try {
      let work = 0;
      const busy: ProbeClock = () => (work += CORROBORATION_FLOOR_MS);
      const result = checkRuleTiming(rule, busy);
      expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
      expect(result.verdict).toBe('over-budget');
    } finally {
      stalled.mockRestore();
    }
  });

  // The gate on an entirely UNMOCKED path: a real catastrophic pattern really
  // does blow the wall budget here, and the only injected thing is a work clock
  // reporting nothing. The cases above reach `uncorroborated` by mocking
  // `performance.now`, which is the heavier intervention; this one shows the
  // corroboration alone decides whether a genuine wall breach may be cached.
  it('withholds a real wall breach from the cache when no work is reported', () => {
    const result = checkRuleTiming(regexRule('^(a+)+$'), noWork);
    expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
    expect(result.verdict).toBe('uncorroborated');
  });

  // A genuinely catastrophic pattern must still be quarantinable on a real
  // clock — the control for every case above. If corroboration ever stopped
  // succeeding on real work, the two stalled-clock cases would still pass and
  // the product would simply never quarantine anything again.
  it('corroborates a real catastrophic pattern, which is what keeps quarantine reachable', () => {
    const result = checkRuleTiming(regexRule('(x+x+)+y'), workClock);
    expect(result.verdict).toBe('over-budget');
    expect(
      result.corroboratedMs,
      `a catastrophic pattern is CPU-bound by construction; measured ${result.corroboratedMs.toFixed(1)}ms ` +
        `of work against a ${String(CORROBORATION_FLOOR_MS)}ms floor. Below the floor means the floor ` +
        `is too high for this machine, not that the pattern is fine.`,
    ).toBeGreaterThanOrEqual(CORROBORATION_FLOOR_MS);
  });
});

describe('worstProbeMs attributes a probe to its interpreted tier', () => {
  // The verdict test above buys its directness with a ~1.3x margin. This one
  // carries no absolute millisecond threshold at all: both quantities are
  // measured on the machine running them, so hardware speed and CPU contention
  // move them together and cancel — the same reason `backtrackRatio` and
  // CATASTROPHIC_RATIO exist rather than a fixed ms bound.
  it('reports the first probe at its interpreted cost, not its native cost', (ctx) => {
    // Read the machine's speed before anything is measured against it, and again
    // after. Neither reading touches `rule`.
    const calibrationBefore = calibrationMs();
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
    //
    // The two sides are sampled differently ON PURPOSE, and the asymmetry is
    // the point rather than an inconsistency. `result.ms` is probe #0 timed
    // exactly once — that lone sample IS the property under test, so it must
    // stay unreplicated. The denominator is the opposite case: it only has to
    // name this probe's native-tier floor, and a single sample of a ~18ms scan
    // is dominated by any scheduler preemption that lands inside it. Because
    // contention can only push a sample above the floor, never below it, `min`
    // recovers the tier while a lone sample tracks the noise — the same reason
    // benignBaselineMs takes a min over several samples.
    //
    // Be precise about what that does and does not buy, because the obvious
    // reading of it is wrong. Contention present for the WHOLE test does not
    // collapse this ratio; it RAISES it, and uniformly more load is uniformly
    // safer. Measured on a 10-core box: 7.05-8.15x idle, 9.69-19.79x at 2x
    // oversubscription, 6.97-17.83x at 8x. The reason is that the numerator is
    // one sample of a ~135ms scan and absorbs the contention in full, while the
    // denominator is a min over seven ~18ms scans and recovers whenever any one
    // of the seven catches a quiet slot.
    //
    // So `min` widens the margin against the common case, and the single sample
    // it replaced was the weaker estimator there (4.21x worst against min-of-7's
    // 6.97x, at 8x oversubscription). What neither form survives is load that
    // differs ACROSS the two windows: the numerator is timed inside
    // `worstProbeMs`, the denominator ~135ms later, so a burst arriving in that
    // gap inflates the denominator alone and nothing cancels. Driven that way
    // this ratio reaches 0.84x with the gate working perfectly. `min` cannot fix
    // that — it needs a quiet slot to find, and there is none — which is why the
    // drift guard below exists rather than a wider threshold.
    let nativeMs = Infinity;
    for (let i = 0; i < 7; i++) {
      const start = performance.now();
      scan(result.probe, [rule]);
      nativeMs = Math.min(nativeMs, performance.now() - start);
    }
    const ratio = result.ms / nativeMs;

    // `min` bounds noise only where a quiet slot exists to be found. Sustained
    // load arriving between the two windows leaves all seven samples inflated,
    // and then the ratio reports the machine rather than the tier — measured
    // down to 0.84x that way, on a gate that was working perfectly. That is
    // unmeasurable, not failed, so abstain rather than reporting either verdict.
    // `ctx.skip` and not an early return, which reports as a pass.
    //
    // This is what lets the threshold below stay a regression detector and stop
    // doubling as the flake tolerance: the two duties now sit in different
    // places, and neither has to be loosened to buy room for the other.
    //
    // The probe-length assertion above has already run, and it is the robust
    // half — scale-free because it compares probes against each other inside one
    // process, so contention hits every candidate alike and cancels exactly. It
    // held across every load condition measured. Skipping here therefore gives
    // up the backstop, never the primary detector.
    const calibrationAfter = calibrationMs();
    const drift =
      Math.max(calibrationBefore, calibrationAfter) / Math.min(calibrationBefore, calibrationAfter);
    if (drift > MAX_CALIBRATION_DRIFT) {
      ctx.skip(
        `machine speed moved ${drift.toFixed(2)}x across the measurement ` +
          `(${calibrationBefore.toFixed(1)}ms before, ${calibrationAfter.toFixed(1)}ms after, ` +
          `budget ${String(MAX_CALIBRATION_DRIFT)}x), so the ${ratio.toFixed(2)}x ratio times the ` +
          `runner rather than the tier. The probe-length verdict above still ran.`,
      );
    }

    expect(
      ratio,
      `gate reported ${result.ms.toFixed(1)}ms interpreted against a min-of-7 native floor of ` +
        `${nativeMs.toFixed(1)}ms (ratio ${ratio.toFixed(2)}x), with machine speed steady to ` +
        `${drift.toFixed(2)}x across the measurement. Measured 7.05-8.15x idle, 9.69-19.79x at 2x ` +
        `CPU oversubscription and 6.97-17.83x at 8x — uniform load RAISES this ratio, so a low one ` +
        `is not a busy runner. A ratio near 1 means the interpreted tier is no longer what the gate ` +
        `reports. Note an actual lower-of-two-samples bypass trips the probe-length assertion above ` +
        `before reaching this one — discarding probe #0's interpreted cost hands the title to the ` +
        `25-char probe. This assertion is the backstop for a bypass that leaves the length verdict ` +
        `intact, so read it as "which tier", not "which probe".`,
    ).toBeGreaterThan(3);
  });
});
