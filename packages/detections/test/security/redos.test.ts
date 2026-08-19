import { isMainThread } from 'node:worker_threads';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import type { ProbeClock } from '../../src/security/redos-probe.ts';
import {
  backtrackRatio,
  BUDGET_MS,
  CATASTROPHIC_RATIO,
  EXPONENTIAL_PROBES,
  POLYNOMIAL_PROBES,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';
import { discoverBundledRuleFiles, loadRule } from '../helpers/rules.ts';

// CPU time consumed by this process, in ms, as a monotonic clock for the probe
// walk. `process.cpuUsage()` reports user+system microseconds since the process
// started, so successive reads difference into the CPU a probe actually burned.
//
// This is the instrument the per-rule gate below measures with, and the reason
// is that the gate's question is "does this pattern backtrack", which is a
// statement about WORK, while wall time measures ELAPSED — and on a contended
// runner the two are not the same number. A regex that backtracks is CPU-bound
// by construction: measured here, the catastrophic patterns in the meta-tests
// below run at 0.82-0.98 CPU-ms per wall-ms. A thread the scheduler took the
// core away from accumulates wall time at ~0.001-0.06, having executed nothing.
// So a wall-clock verdict is satisfiable by a stall that the rule under test had
// no part in, and it names whichever rule was unlucky enough to be running: over
// twelve walks of the full ruleset under 7x CPU oversubscription, five crossed
// the 100ms budget and all five were DIFFERENT rules, none of them slower than
// 3.6ms when measured quiet. CPU time discards exactly that and keeps the
// signal, so this is a correction to the instrument rather than a concession to
// CI — the gate can no longer be tripped by, or satisfied by, time this process
// did not spend.
//
// Vitest's default pool gives each test file its own process and the walk is
// synchronous, so no other TEST shares a measured window. Be precise about what
// that leaves, because it is not nothing: `process.cpuUsage()` sums every
// thread in the process, and V8's background GC and compilation threads are in
// it. Measured on a quiet machine, pairing each probe with its own window, a
// 0.86ms probe was charged 3.69ms — 2.83ms of CPU the scanning thread did not
// spend, attributed to whichever probe was resident.
//
// That residual runs in the INFLATING direction, which is the same
// false-accusation shape wall time had, so it is bounded by margin rather than
// removed: single-digit ms against a 100ms budget, with the fleet's own worst
// under 7ms under load. What CPU time does remove is descheduling, and that is
// the part with no bound at all — a thread the scheduler took the core away
// from accumulates wall time without limit, which is what produced the
// 105-185ms readings on rules costing under 7ms of work.
//
// A CPU clock's granularity is the platform's, not this process's, and it is
// coarser on some than others — a short probe can quantize to a whole tick or to
// zero. That costs sensitivity only within one tick of the threshold, which this
// margin absorbs: under 7x oversubscription the worst rule measured 6.6ms of CPU
// against a 100ms budget, so the fleet sits ~15x clear rather than one tick
// clear. It is the direction that matters — a coarse clock rounds a benign rule
// toward a tick it can afford, and the catastrophic-pattern case below is what
// keeps the clock proven live rather than merely quiet.
const cpuMs: ProbeClock = () => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

// scan() is synchronous and runs on the hook path. A rule that backtracks
// catastrophically cannot be interrupted — the fail-open catch in the plugin
// runtime only catches throws, and a hook killed at its 10s timeout fails open,
// letting the call through UNSCANNED. So a slow rule is a detection bypass, not
// just a stall.
//
// SCOPE. This gate binds the rules in this repository only, and within them it
// proves "no bundled rule backtracks on the inputs the battery constructs" —
// not "no bundled rule can ReDoS at all". The probe battery
// (packages/detections/src/security/redos-probe.ts) mixes a FIXED
// lowercase-and-digit alphabet with per-rule DERIVED probes built from each
// pattern's own literal prefix and character classes, so a rule gated behind a
// literal like `ghp_(...)+$` is actually exercised past its prefix on its own
// alphabet. Residual gaps, all documented rather than silently covered:
// backtracking that needs a literal (non-class) character the pattern
// repeats; polynomial blowup reachable only on a non-lowercase alphabet (the
// fixed polynomial tier is lowercase-and-digit); and any rule that arrives at
// runtime from a pulled or custom pack, which this suite never sees — that
// path has its own runtime gate, built on this same battery.

const bundled = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

describe('bundled rules survive adversarial input', () => {
  it('discovers every bundled rule', () => {
    // Guards against the suite silently shrinking to zero if discovery breaks.
    expect(bundled.length).toBeGreaterThan(90);
  });

  // The premise `cpuMs` rests on, pinned rather than remembered. Charging CPU
  // time is only a per-rule measurement while this file has the process to
  // itself: `process.cpuUsage()` sums the whole process, so if vitest ran test
  // FILES as threads of one process, every other suite's CPU would land inside
  // these probe windows and the gate would start accusing rules of work another
  // file did. Nothing above would fail — the readings would simply drift up.
  //
  // Under the default `forks` pool each file gets its own child process and is
  // its main thread; under `pool: 'threads'` it is a worker and this reads
  // false. That one config line is the whole failure mode, no package in this
  // workspace sets `pool` today, and this is what would notice if one did.
  it('runs as its own process, which is what makes a process-wide CPU clock a per-rule measurement', () => {
    expect(
      isMainThread,
      'this suite is running as a worker thread, so process.cpuUsage() now sums every test file ' +
        'sharing this process and the per-rule budget above is measuring other suites too. Revert ' +
        "the pool back to per-process isolation rather than widening the budget — vitest's default " +
        '`forks` pool is what this gate assumes.',
    ).toBe(true);
  });

  it.each(bundled.map((rule) => [rule.id, rule] as const))(
    '%s stays within the scan budget',
    (id, rule) => {
      // CPU time, not wall time — see `cpuMs`. The budget is unchanged and so is
      // the walk; only the resource being charged for is.
      const { ms, probe } = worstProbeMs(rule, cpuMs);
      expect(
        ms,
        `Rule "${id}" burned ${ms.toFixed(1)}ms of CPU on a ${String(probe.length)}-char probe ` +
          `(budget ${String(BUDGET_MS)}ms). A rule this slow can exhaust the hook's 10s timeout, ` +
          `which fails open and lets the call through unscanned. Rewrite the pattern to ` +
          `remove the ambiguity — usually a quantified group whose body can match the same ` +
          `text more than one way, e.g. (a+)+ or (\\s*\\w+)*. This is CPU time, so a busy ` +
          `runner cannot inflate it: the pattern really did this much work.`,
      ).toBeLessThan(BUDGET_MS);
    },
  );
});

function parseRegexRule(pattern: string) {
  return Rule.safeParse({
    specVersion: 1,
    id: 'test-pack/evil',
    name: 'evil',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  });
}

// Catastrophic patterns meet two defences, and which one fires is not obvious.
describe('the schema rejects catastrophic patterns that can match empty', () => {
  // `matchesEmptyString` exists to stop an empty-match rule spinning the
  // matcher, but it also turns away a whole class of ReDoS: an outer `*`
  // quantifier means the pattern matches '' and never reaches the engine.
  // These never make it to the probe battery, so do not "fix" them by adding
  // probes — assert the earlier defence instead.
  it.each([
    ['nested star', '(a*)*$'],
    ['nested class quantifier', '([a-zA-Z]+)*$'],
    ['whitespace/word ambiguity', '(\\s*\\w+)*$'],
    ['identical alternation', '(a|a)*$'],
    ['overlapping alternation', '(a|ab)*$'],
  ])('rejects %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    expect(parsed.success).toBe(false);
  });

  it('but a captureGroup re-opens every one of them', () => {
    // The refine is `captureGroup !== undefined || !matchesEmptyString(...)`,
    // so setting a captureGroup skips the empty-string check entirely — and the
    // schema comment explicitly invites `*`/`?` around a capture. So the "assert
    // the schema, not a probe" note above holds ONLY while captureGroup is
    // absent; with one, these shapes parse and the probe battery becomes the
    // only defence again.
    const parsed = Rule.safeParse({
      specVersion: 1,
      id: 'test-pack/evil',
      name: 'evil',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: '(a*)*$', flags: 'g', captureGroup: 1 },
    });
    expect(parsed.success).toBe(true);
  });
});

describe('the probe battery itself', () => {
  // Without this, the suite above passes trivially if the probes stop being
  // adversarial (a refactor drops the terminator, shrinks the lengths, …) —
  // 101 green tests that check nothing.
  //
  // Each case proves the battery drives a catastrophic pattern to backtrack far
  // past ordinary input by asserting a RATIO — worst probe time over a
  // same-length benign baseline on the same machine — not an absolute
  // millisecond threshold. Wall-clock ms shifts with hardware and CPU load, and
  // which pattern sits closest to a fixed line shifts with it; the ratio does
  // not, because both measurements move together.
  //
  // A pattern belongs here only if `worstProbeMs` crosses BUDGET_MS on an early
  // SHORT probe. That first over-budget probe runs to completion, so its cost
  // must stay well under the vitest timeout: `(.*a){20}$` costs ~1.2s on one
  // machine and over 5s on the Windows runner, where it exceeded the timeout. It
  // proved nothing the cases below do not, so it is not worth a multi-second
  // probe. Add a pattern here only after checking what its first matching probe
  // costs.
  it.each([
    ['nested quantifier', '^(a+)+$'],
    ['adjacent quantifiers in a quantified group', '(x+x+)+y'],
  ])('catches a catastrophic pattern the schema admits: %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    // Both require at least one character, so `matchesEmptyString` lets them
    // through. Nothing analyses pattern complexity — this suite is the only
    // thing standing between one of these and `rules/`.
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const { ratio, ms, benignMs } = backtrackRatio(parsed.data);
    expect(
      ratio,
      `worst probe ran ${ms.toFixed(1)}ms vs a ${benignMs.toFixed(3)}ms same-length ` +
        `baseline (ratio ${ratio.toFixed(0)}×); the probe battery should drive this ` +
        `pattern to backtrack orders of magnitude past ordinary input.`,
    ).toBeGreaterThan(CATASTROPHIC_RATIO);
  });

  // The fixed lowercase-and-digit alphabet cannot see these: a literal prefix
  // (`ghp_`, `eyJ`) gates the catastrophic tail, or the vulnerable class is
  // uppercase-only (`[B-Z]`). They are the exact shape the real secret rules in
  // this repo use, and each one runs for seconds on a tailored input — past the
  // hook's 10s timeout for the JWT case. `derivedProbes` is what closes them.
  it.each([
    ['github-PAT-shaped literal prefix', 'ghp_([A-Za-z0-9]+)+$'],
    ['AWS-key-shaped literal prefix', 'AKIA([A-Z0-9]+)+$'],
    ['uppercase-only class, no prefix', '\\b([B-Z]+)+#'],
    ['JWT-shaped literal prefix', 'eyJ([A-Za-z0-9_-]+)+\\.'],
  ])('catches an alphabet-specific catastrophic pattern: %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const { ratio, ms, benignMs } = backtrackRatio(parsed.data);
    expect(
      ratio,
      `worst probe ran ${ms.toFixed(1)}ms vs a ${benignMs.toFixed(3)}ms same-length ` +
        `baseline (ratio ${ratio.toFixed(0)}×); the probe battery should drive this ` +
        `pattern to backtrack orders of magnitude past ordinary input.`,
    ).toBeGreaterThan(CATASTROPHIC_RATIO);
  });

  // The per-rule gate reads CPU time, and a clock that reads zero would report
  // 0ms for all 101 rules and pass forever — the same "green tests that check
  // nothing" this whole block exists to prevent, one instrument lower down.
  // These two cases pin the clock from both sides: it must still condemn a
  // pattern that really backtracks, and it must not be fooled by elapsed time
  // that bought no work. Only the first of the two catches a DEAD clock; see
  // the liveness assertion inside it for why that is not an oversight.
  it('the CPU clock still condemns a catastrophic pattern', () => {
    const parsed = parseRegexRule('^(a+)+$');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const { ms, probe } = worstProbeMs(parsed.data, cpuMs);

    // Liveness, asserted on its own and first, because this is the half that
    // decides whether the 101 assertions above mean anything — and it is the
    // only half machine speed cannot flip. `worstProbeMs` records a probe when
    // its window beats the running maximum, so a clock stuck at ANY constant
    // leaves this empty: `elapsed > ms` is `0 > 0`. No threshold, no budget, no
    // comparison that gets easier on faster hardware.
    //
    // This matters because the two cases here are not redundant the way they
    // look. Under a clock stubbed to return 0 the sibling below stays GREEN —
    // its CPU half asserts a benign pattern is UNDER budget, which 0 satisfies —
    // so the whole gate's non-vacuity rests on this file having one assertion
    // that a dead clock cannot satisfy. That is this line.
    //
    // It also has a kill nothing else here has. Drop the `probe = text` line in
    // `worstProbeMs` and the 101 assertions above stay green while every
    // failure message they can emit reports a 0-char probe: the verdict still
    // crosses the budget, so only an assertion that reads the ATTRIBUTION
    // notices. Hence both causes in the message — a stuck clock and a lost
    // attribution are the same symptom here and want telling apart.
    expect(
      probe,
      'no probe was ever attributed a cost. Either the CPU clock is not advancing — in which ' +
        'case every rule assertion in the gate above is passing vacuously against a constant 0 — ' +
        'or worstProbeMs stopped recording which probe won, which silently empties the probe ' +
        'length every one of those failure messages reports.',
    ).not.toBe('');

    // And the verdict itself. THIS half is machine-speed-dependent and its
    // margin is thin, in the same way and for the same reason as the
    // interpreted-tier case in redos-probe.test.ts. The battery's longest
    // all-`a` probe is 25 chars and no polynomial probe is all-`a`, so there is
    // no longer probe to escalate to when a fast machine brings the 25-char one
    // inside the budget. Measured 151-155ms against the 100ms budget in THIS
    // file's ordering — the ratio case above has already tiered the pattern up,
    // so the verdict lands on the 25-char probe at its native cost — i.e. ~1.5x,
    // and hardware around 1.5x faster flips it red. CI runners are slower than a
    // dev machine, which is the safe direction; a bigger pattern would buy
    // margin here and spend it on the Windows runner, where this file's
    // neighbours put backtracking at 4-5x slower and the per-test timeout is the
    // other cliff. Read the failure message before believing a regression.
    expect(
      ms,
      `a catastrophic pattern must still blow the budget when the walk is charged CPU time ` +
        `rather than wall time; it burned ${ms.toFixed(1)}ms of CPU on a ` +
        `${String(probe.length)}-char probe. If the assertion above PASSED and this one failed, ` +
        `the clock is reading fine and this machine is simply fast enough that the 25-char ` +
        `probe no longer costs 100ms of CPU — retune the pattern, do not touch the clock.`,
    ).toBeGreaterThanOrEqual(BUDGET_MS);
  });

  it('a clock that advances without work would trip the gate, which is why the gate reads CPU', () => {
    // The failure mode this instrument replaced, made deterministic. A
    // descheduled thread's wall clock advances while the thread executes
    // nothing, and the walk cannot tell that from backtracking: it charges the
    // elapsed time to whichever rule was resident. Here that is a rule with no
    // ambiguity at all — a fixed-length AWS key matcher — and a clock that jumps
    // 120ms per read condemns it on its first probe.
    const parsed = parseRegexRule('AKIA[A-Z0-9]{16}');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    let reads = 0;
    const stalled: ProbeClock = () => reads++ * 120;
    expect(
      worstProbeMs(parsed.data, stalled).ms,
      'a clock that advances without work should condemn even a benign pattern — ' +
        'this is the wall-clock failure mode, reproduced without needing a loaded runner.',
    ).toBeGreaterThanOrEqual(BUDGET_MS);
    // The same rule and the same walk, charged CPU: nowhere near the budget.
    expect(
      worstProbeMs(parsed.data, cpuMs).ms,
      'the same benign pattern must stay far inside the budget on CPU time',
    ).toBeLessThan(BUDGET_MS);
  });

  it('the fixed alphabet alone would miss the alphabet-specific patterns', () => {
    // Pins WHY the per-rule derivation is load-bearing: without it, a
    // github-PAT-shaped rule sails through in microseconds. If a refactor makes
    // the fixed probes somehow cover these, this test fails loudly and the
    // derivation can be reconsidered — it should not silently become redundant.
    const parsed = parseRegexRule('ghp_([A-Za-z0-9]+)+$');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    let worstFixed = 0;
    for (const text of [...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES]) {
      const start = performance.now();
      scan(text, [parsed.data]);
      worstFixed = Math.max(worstFixed, performance.now() - start);
    }
    expect(worstFixed).toBeLessThan(BUDGET_MS);
  });
});
