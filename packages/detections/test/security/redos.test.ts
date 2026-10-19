import { isMainThread } from 'node:worker_threads';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import { MAX_REGEX_INPUT_LENGTH } from '../../src/matchers/limits.ts';
import type { GrowthBreach, ProbeClock } from '../../src/security/redos-probe.ts';
import {
  backtrackRatio,
  BUDGET_MS,
  CATASTROPHIC_RATIO,
  EXPONENTIAL_PROBES,
  GROWTH_CONFIRM_SAMPLES,
  GROWTH_CORPORA,
  GROWTH_CORROBORATION_FLOOR_MS,
  GROWTH_MAX_CHARS,
  GROWTH_SAMPLES,
  GROWTH_START_CHARS,
  MAX_GROWTH_RATIO,
  OVER_BUDGET_READINGS,
  POLYNOMIAL_PROBES,
  superlinearGrowth,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';
import {
  clockResolutionMs,
  processCpuMs,
  RATIO_CLOCK,
  RATIO_RESOLUTION_MS,
  THREAD_CPU_RESOLUTION_MS,
  threadCpuMs,
} from '../helpers/clocks.ts';
import { walkInIsolation } from '../helpers/isolated-walk.ts';
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
const cpuMs: ProbeClock = processCpuMs;

// The per-rule budget, judged so that only a breach that reproduces fails.
//
// The in-process walk above is the screen. A walk that crosses the budget is
// measured again on a fresh worker thread (`walkInIsolation`): a new isolate,
// so every pattern runs interpreted again exactly as it did the first time,
// charged with that thread's own CPU, so neither the GC and compiler threads
// nor anything else in this process is in the reading. Only that second
// reading decides. A rule that really backtracks burns the same CPU on any
// thread and fails both. A first reading that was inflated by work the rule
// did not do is cleared by the second; benign rules have crossed the budget
// in-process on the loaded Windows runner, where that clock also advances in
// whole 16ms ticks.
//
// Measuring again on the SAME thread is not an option and is not what this
// does: the regex would run natively compiled the second time, at a fraction
// of the interpreted cost a hook process pays (see `worstProbeMs`).
async function probeBudgetBreach(
  rule: Rule,
): Promise<{ firstMs: number; isolatedMs: number; probeLength: number } | undefined> {
  const first = worstProbeMs(rule, cpuMs);
  if (first.ms < BUDGET_MS) return undefined;
  const isolated = await walkInIsolation(rule);
  if (isolated.ms < BUDGET_MS) return undefined;
  return { firstMs: first.ms, isolatedMs: isolated.ms, probeLength: isolated.probeLength };
}

function describeProbeBreach(
  id: string,
  breach: { firstMs: number; isolatedMs: number; probeLength: number },
): string {
  return (
    `Rule "${id}" burned ${breach.firstMs.toFixed(1)}ms of CPU on its worst probe here, and ` +
    `${breach.isolatedMs.toFixed(1)}ms on a ${String(breach.probeLength)}-char probe measured ` +
    `again on a fresh thread (budget ${String(BUDGET_MS)}ms). A rule this slow can exhaust the ` +
    `hook's 10s timeout, which fails open and lets the call through unscanned. Rewrite the ` +
    `pattern to remove the ambiguity — usually a quantified group whose body can match the same ` +
    `text more than one way, e.g. (a+)+ or (\\s*\\w+)*. Both readings are CPU time on a cold ` +
    `regex, so a busy runner cannot produce them: the pattern really did this much work.`
  );
}

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
    async (id, rule) => {
      // CPU time, not wall time — see `cpuMs` — and a breach must reproduce on
      // a fresh thread — see `probeBudgetBreach`. The budget is unchanged and
      // so is the walk.
      const breach = await probeBudgetBreach(rule);
      expect(breach, breach && describeProbeBreach(id, breach)).toBeUndefined();
    },
  );

  it('measures a breach again on a fresh thread at its interpreted cost', async () => {
    // The re-measurement is only worth having if it still pays what a hook
    // pays. `^(a+)+bc` is the pattern that separates the two tiers: measured on
    // an arm64 Mac, its walk burns 130-136ms on a cold isolate and 74ms once
    // this thread has compiled it natively, so a re-measurement taken on this
    // thread would clear it and one taken on a fresh thread condemns it. It is
    // walked here first, which is the state every rule is in when its
    // in-process walk has just breached. Slower hardware widens the gap, so a
    // CI runner is the safe direction; a machine ~1.3x faster than that Mac
    // would bring the cold walk inside the budget and fail the first assertion
    // with the second still holding, which reads as hardware, not as a defect.
    const parsed = parseRegexRule('^(a+)+bc');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    worstProbeMs(parsed.data, threadCpuMs);
    const warm = worstProbeMs(parsed.data, threadCpuMs);
    const isolated = await walkInIsolation(parsed.data);
    expect(
      isolated.ms,
      `the fresh-thread walk read ${isolated.ms.toFixed(1)}ms of CPU on a ` +
        `${String(isolated.probeLength)}-char probe (${warm.ms.toFixed(1)}ms on this thread, ` +
        `compiled); a pattern that backtracks must cross the budget there, or every breach the ` +
        `in-process walk finds is cleared by it.`,
    ).toBeGreaterThanOrEqual(BUDGET_MS);
    expect(
      isolated.ms,
      'the fresh-thread walk cost no more than the compiled walk on this thread, so it is not ' +
        'measuring a cold regex',
    ).toBeGreaterThan(warm.ms);
  });
});

function describeBreach(breach: GrowthBreach): string {
  const ratio = (largerMs: number, smallerMs: number): string =>
    `${(largerMs / Math.max(smallerMs, 1e-6)).toFixed(1)}x for 2x the input`;
  const next =
    breach.nextMs === undefined || breach.nextChars === undefined
      ? ''
      : `, then ${breach.nextMs.toFixed(1)}ms at ${String(breach.nextChars)} chars ` +
        `(${ratio(breach.nextMs, breach.largeMs)})`;
  return (
    `on the ${breach.corpus} corpus it took ${breach.smallMs.toFixed(1)}ms at ` +
    `${String(breach.smallChars)} chars and ${breach.largeMs.toFixed(1)}ms at ` +
    `${String(breach.largeChars)} chars (${ratio(breach.largeMs, breach.smallMs)})${next}; ` +
    `${breach.reason}, each reading the fastest of several`
  );
}

// The growth tier: how each rule's cost scales with input on structured
// corpora, which the absolute-budget walk above cannot see. A pattern that is
// quadratic with a small constant passes every 40KB probe and still costs
// seconds at the engine's 200,000-char input cap.
//
// The readings are this thread's CPU time wherever that clock is fine enough
// to give a ratio, and wall time where it is not (the Windows runner credits
// CPU in whole 16ms ticks, which would quantize a 5-30ms reading into a
// meaningless ratio). The choice is made by measuring the clock, not by
// naming a platform; see `RATIO_CLOCK`.
//
// Wall time alone cannot keep a busy runner out of the verdict, and that was
// measured rather than assumed. The tier takes the FASTEST of several readings
// on each side, in the same rounds, which survives a stall that misses one
// reading; it does not survive a machine with no free core for the length of
// a whole pass. Under 30 CPU burners on 10 cores, the quadratic control
// `"[^"\n]*"\s+[^\n]*?\.` read its pair at 8.7ms / 23.5ms on the wall (2.7x)
// and was cleared, against 5.1ms / 20.4ms quiet. The same load runs the other
// way on a linear rule: it put `secrets-infra/jwt-token` over the ratio on two
// doublings, and loaded CI runners have read benign rules at 104-142ms on the
// wall for a scan that burns under 10ms of CPU. On the thread's CPU clock the
// control read 5.1-5.2ms / 20.3-21.7ms / 82-108ms in all sixteen runs under
// the same burners, because a thread waiting for a core accrues none of it.
//
// One doubling over the ratio is not a breach by itself: the growth has to
// persist over the next doubling, which is what separates a quadratic curve
// from a linear one with a step in it. The scripted-clock suites below pin
// each of these.
//
// Where the readings are wall time, the over-budget breach is corroborated by
// the thread's CPU clock, which a 16ms tick does not stop from telling a scan
// that did 100ms of work from one that did 6; see
// GROWTH_CORROBORATION_FLOOR_MS. And on every clock, a breach fails the run
// only if it reproduces: the tier is run again from the start, and a rule
// fails only if every run breaches (`GROWTH_RUNS`). A real superlinear or
// over-budget pattern breaches on every run, because its readings are its
// cost; a reading that was the machine's does not come back three times.

// What a failing bundled rule is told. An `over-budget` breach is a statement
// about cost at one size and says nothing about the shape of the curve; a
// `superlinear` one is a statement about shape over two doublings.
function describeFailure(id: string, breach: GrowthBreach): string {
  const consequence =
    `scan() runs each rule on up to ${String(MAX_REGEX_INPUT_LENGTH)} chars per field, and a ` +
    `hook that outlives its timeout fails open.`;
  if (breach.reason === 'over-budget') {
    const work =
      breach.largeWorkMs === undefined
        ? ''
        : ` (${breach.largeWorkMs.toFixed(1)}ms of it on this thread's CPU)`;
    return (
      `Rule "${id}" takes ${breach.largeMs.toFixed(1)}ms${work} to scan ` +
      `${String(breach.largeChars)} chars of one corpus, over the ${String(BUDGET_MS)}ms budget ` +
      `for a single scan. ` +
      `${consequence} Make the pattern cheaper on this text; a rule this expensive usually ` +
      `starts a long scan at every position of a run.`
    );
  }
  const top = breach.nextChars ?? breach.largeChars;
  return (
    `Rule "${id}" costs more than linear time in its input on every doubling measured, up to ` +
    `${String(top)} chars. At these sizes that is cheap, but a quadratic pattern costs seconds ` +
    `at the input cap and a cubic one minutes: ${consequence} The usual cause is a quantified ` +
    `scan (\\s+, [^\\n]*?) that can start at every position of a run and rescans the rest of ` +
    `it each time; confine it so each start position is consumed once.`
  );
}

// The clock the growth tier's readings are taken on, chosen by measuring it.
const GROWTH_CLOCK = RATIO_CLOCK;

// How many times the tier is run before a verdict that fails the run stands:
// a breach for a rule that must be linear, a miss for a pattern that must be
// caught. A verdict that does not fail the run stops it at once.
const GROWTH_RUNS = 3;

// Every run's verdict, up to and including the first that would not fail the
// run. The run fails only if all GROWTH_RUNS of them would have.
function repeatedVerdicts(
  run: () => GrowthBreach | undefined,
  fails: (breach: GrowthBreach | undefined) => boolean,
): { verdicts: (GrowthBreach | undefined)[]; failed: boolean } {
  const verdicts: (GrowthBreach | undefined)[] = [];
  for (let attempt = 0; attempt < GROWTH_RUNS; attempt++) {
    const breach = run();
    verdicts.push(breach);
    if (!fails(breach)) break;
  }
  return { verdicts, failed: verdicts.length === GROWTH_RUNS && verdicts.every(fails) };
}

function growthRuns(rule: Rule, fails: (breach: GrowthBreach | undefined) => boolean) {
  return repeatedVerdicts(
    () => superlinearGrowth(rule, GROWTH_CLOCK.now, GROWTH_CLOCK.corroborate),
    fails,
  );
}

// The breach a rule that must grow linearly is reported for: undefined unless
// every run breached, in which case the last run's breach.
function reproducedBreach(rule: Rule): GrowthBreach | undefined {
  const { verdicts, failed } = growthRuns(rule, (breach) => breach !== undefined);
  return failed ? verdicts.at(-1) : undefined;
}

describe('bundled rules scale linearly on adversarial corpora', () => {
  it.each(bundled.map((rule) => [rule.id, rule] as const))(
    '%s grows linearly with its input',
    async (id, rule) => {
      // The growth tier scans thousands of characters per reading, so a pattern
      // that backtracks exponentially would never return from it. The short
      // probes catch that case cheaply, and must pass first.
      const probeBreach = await probeBudgetBreach(rule);
      expect(
        probeBreach,
        probeBreach && `${describeProbeBreach(id, probeBreach)} The growth tier is not run on it.`,
      ).toBeUndefined();
      const breach = reproducedBreach(rule);
      expect(
        breach &&
          `${describeBreach(breach)}, on ${GROWTH_CLOCK.name}, in each of ${String(GROWTH_RUNS)} runs`,
        breach && describeFailure(id, breach),
      ).toBeUndefined();
    },
  );
});

// A shape the probe battery cannot judge, pinned for the one rule that has it.
// `ssh-private-key` matches a header and then, optionally, scans forward for
// its END marker. Input made of nothing but headers starts that scan at every
// header and never finds an END; a tail that may cross other text pays its whole
// bound each time. That is linear with a large constant rather than
// catastrophic, so at the battery's probe lengths it stays inside the budget,
// and at the engine's input cap benign rules cost too much for an absolute
// budget to separate them. Comparing the rule against its own header alone does
// separate them: a tail that stops at the next `--` costs about what the header
// costs, and the `[\s\S]{0,8000}?` tail it replaced cost over an order of
// magnitude more. Wall time with a warm-up and a min over samples, because both
// sides are measured the same way and only the ratio is asserted.
describe('ssh-private-key pays its END-marker tail once per header', () => {
  it('costs about what the header alone costs on input made of repeated headers', () => {
    const rule = bundled.find((r) => r.id === 'secrets-infra/ssh-private-key');
    expect(rule).toBeDefined();
    if (rule?.matcher.type !== 'regex') return;
    const headerOnly: Rule = {
      ...rule,
      matcher: {
        ...rule.matcher,
        pattern: '-----BEGIN (?:RSA |DSA |EC |OPENSSH |SSH2 |ENCRYPTED )?PRIVATE KEY-----',
      },
    };
    const header = '-----BEGIN PRIVATE KEY-----';
    const text = header
      .repeat(Math.ceil(MAX_REGEX_INPUT_LENGTH / header.length))
      .slice(0, MAX_REGEX_INPUT_LENGTH);
    const cost = (r: Rule): number => {
      scan(text, [r]);
      let best = Infinity;
      for (let i = 0; i < 5; i++) {
        const start = performance.now();
        scan(text, [r]);
        best = Math.min(best, performance.now() - start);
      }
      return best;
    };
    const tailMs = cost(rule);
    const headerMs = cost(headerOnly);
    expect(
      tailMs,
      `the rule took ${tailMs.toFixed(1)}ms against ${headerMs.toFixed(1)}ms for its header ` +
        `alone on ${String(text.length)} chars of repeated headers; the END-marker tail is ` +
        `scanning past the next header again.`,
    ).toBeLessThan(Math.max(headerMs, 1) * 5);
  });
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
  // one green test per bundled rule, none of which checks anything.
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
  // 0ms for every bundled rule and pass forever — the same "green tests that check
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
    // decides whether the per-rule assertions above mean anything — and it is the
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
    // `worstProbeMs` and the per-rule assertions above stay green while every
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

  // The growth tier's own non-vacuity. Each pattern is linear-time on every
  // short probe above and still superlinear at scale on text an author does
  // not control: one-line JSON, quoted SQL keywords, whitespace runs, a call
  // opener repeated without its closer.
  describe('the growth tier', () => {
    function regexRule(pattern: string, flags: string, examples?: string[]): Rule {
      return Rule.parse({
        specVersion: 1,
        id: 'test-pack/growth',
        name: 'growth',
        category: 'custom',
        severity: 'low',
        matcher: { type: 'regex', pattern, flags },
        ...(examples ? { examples } : {}),
      });
    }

    const superlinear: [string, Rule][] = [
      [
        'lazy scans from every quote to a trailing operator',
        regexRule(`["'][^\\n]*?(select|insert|update|delete|drop|where)[^\\n]*?["']\\s*\\.`, 'gi'),
      ],
      [
        'a lazy scan to a dot from each space-separated literal',
        regexRule('"[^"\\n]*"\\s+[^\\n]*?\\.', 'g'),
      ],
      [
        'a SQL keyword scanned to a placeholder from every keyword',
        regexRule('(select|insert|update|delete|where)[^\\n]*?(#\\{|\\$[a-z_])', 'gi'),
      ],
      [
        'an optional whitespace run before a literal',
        regexRule(
          '(?:^|\\s+)at\\s+[A-Za-z0-9._$<>]+\\.[A-Za-z0-9_$]+\\s*\\([A-Za-z0-9._\\-/:]+:\\d+:\\d+\\)',
          'g',
        ),
      ],
      [
        'a lookahead scanning to a closer that never comes',
        regexRule('\\byaml\\.load\\s*\\((?![^)]*SafeLoader|[^)]*safe_load)', 'gi', [
          'data = yaml.load(user_input)',
        ]),
      ],
    ];

    it.each(superlinear)('catches %s', (_label, rule) => {
      // Run the way the bundled rules are run, on the same clock. The miss is
      // the verdict that fails here, so it is the one that has to reproduce.
      const { verdicts, failed } = growthRuns(rule, (found) => found === undefined);
      const breach = verdicts.at(-1);
      expect(
        failed ? undefined : breach,
        `the growth tier passed a pattern that is superlinear at scale, on ${GROWTH_CLOCK.name}, ` +
          `in each of ${String(GROWTH_RUNS)} runs`,
      ).toBeDefined();
      if (!breach) return;
      expect(
        breach.reason === 'over-budget' ||
          breach.largeMs / Math.max(breach.smallMs, 1e-6) > MAX_GROWTH_RATIO,
        describeBreach(breach),
      ).toBe(true);
    });

    it.each(superlinear)('the absolute-budget walk alone would miss %s', async (_label, rule) => {
      // Pins why the growth tier exists: every one of these clears the
      // single-probe walk. If that stops being true, the walk has grown a
      // probe that covers this class and the tier can be reconsidered.
      const breach = await probeBudgetBreach(rule);
      expect(breach && describeProbeBreach('test-pack/growth', breach)).toBeUndefined();
    });

    it.each([
      ['a quoted string confined to one string', regexRule(`["'][^"'\\n]*\\bwhere\\b`, 'gi')],
      ['a fixed-length key', regexRule('AKIA[A-Z0-9]{16}', 'g')],
      [
        'a call opener with no lookahead',
        regexRule('\\byaml\\.load\\(', 'g', ['data = yaml.load(user_input)']),
      ],
    ])('passes a linear pattern: %s', (_label, rule) => {
      const breach = reproducedBreach(rule);
      expect(breach && describeBreach(breach)).toBeUndefined();
    });
  });

  // The growth tier's verdicts made deterministic. The scans run for real and
  // are ignored: a scripted clock supplies every reading, so each case states
  // exactly what was read at each size. The rule is a fixed-length key with no
  // examples, so it is measured on the fixed corpora only and every corpus
  // reads the clock the same number of times.
  const scriptedRule = Rule.parse({
    specVersion: 1,
    id: 'test-pack/scripted',
    name: 'scripted',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern: 'AKIA[A-Z0-9]{16}', flags: 'g' },
  });

  // The sizes a corpus is scouted at on the way up, one reading each: every
  // doubling of the start size up to the top.
  const SCOUT_SIZES: number[] = [];
  for (let size = GROWTH_START_CHARS * 2; size <= GROWTH_MAX_CHARS; size *= 2) {
    SCOUT_SIZES.push(size);
  }
  const TOP = { smallChars: GROWTH_MAX_CHARS / 2, largeChars: GROWTH_MAX_CHARS };
  const NEXT_CHARS = GROWTH_MAX_CHARS * 2;

  type Reading = number | ((round: number) => number);
  const at = (reading: Reading, round: number): number =>
    typeof reading === 'number' ? reading : reading(round);

  // The cost of each scan, in the order the tier makes them. `rounds` rounds of
  // one scan per size, smallest first.
  const rounds = (count: number, ...sizes: Reading[]): number[] =>
    Array.from({ length: count }, (_, round) => sizes.map((size) => at(size, round))).flat();
  // A climb whose scouts all read cheap, so only the top pair is sampled.
  const cheapClimb = (): number[] => SCOUT_SIZES.map(() => 1);
  const firstPass = (small: Reading, large: Reading, count = GROWTH_SAMPLES): number[] =>
    rounds(count, small, large);
  const confirmPass = (
    small: Reading,
    large: Reading,
    next: Reading,
    count = GROWTH_CONFIRM_SAMPLES,
  ): number[] => rounds(count, small, large, next);

  // A clock that charges each scan the next cost in `scans`. It is read twice
  // per scan, start and end, and throws on a scan the script does not hold, so
  // a case whose script and the tier disagree on how many scans are made fails
  // instead of reading costs meant for another scan.
  function scripted(scans: readonly number[]): { clock: ProbeClock; unread: () => number } {
    let reads = 0;
    let time = 0;
    const clock: ProbeClock = () => {
      const read = reads++;
      if (read % 2 === 1) {
        const cost = scans[(read - 1) / 2];
        if (cost === undefined) {
          throw new Error(
            `scan ${String((read + 1) / 2)} is past the ${String(scans.length)} scripted`,
          );
        }
        time += cost;
      }
      return time;
    };
    return { clock, unread: () => scans.length - Math.ceil(reads / 2) };
  }

  // Runs the tier on a script and requires that every scripted scan was made.
  // `perCorpus` is what one corpus reads. A rule that is cleared reads it once
  // per corpus; a breach is returned on the first corpus and reads it once.
  function runCleared(perCorpus: readonly number[]): void {
    const { clock, unread } = scripted(GROWTH_CORPORA.flatMap(() => perCorpus));
    const breach = superlinearGrowth(scriptedRule, clock);
    expect(breach && describeBreach(breach)).toBeUndefined();
    expect(unread(), 'scripted scans the tier did not make').toBe(0);
  }
  function runBreached(perCorpus: readonly number[]): GrowthBreach {
    const { clock, unread } = scripted(perCorpus);
    const breach = superlinearGrowth(scriptedRule, clock);
    expect(unread(), 'scripted scans the tier did not make').toBe(0);
    if (!breach) throw new Error('expected a breach');
    expect(breach.corpus).toBe(GROWTH_CORPORA[0]?.name);
    return breach;
  }

  describe('the scripted clock', () => {
    it('throws on a scan past the end of its script', () => {
      const { clock } = scripted([1]);
      clock();
      clock();
      clock();
      expect(() => clock()).toThrow('scan 2 is past the 1 scripted');
    });

    it('fails a case that scripts fewer scans than the tier makes', () => {
      const { clock } = scripted([...cheapClimb(), ...firstPass(3, 6, GROWTH_SAMPLES - 1)]);
      expect(() => superlinearGrowth(scriptedRule, clock)).toThrow(/is past the \d+ scripted/);
    });
  });

  describe('the growth tier reads through stalls', () => {
    const SMALL_MS = 3;
    const CLEAN_LARGE_MS = 6;
    const STALLED_LARGE_MS = 30;
    // Over the ratio against a clean larger reading, so only the pair's own
    // ratio can clear a case that reads this.
    const NEXT_MS = 20;

    it('a stall on most of the larger readings does not read as growth', () => {
      // Three of five larger readings stalled: a median reads 30ms over 3ms,
      // the fastest reading 6ms over 3ms. The next doubling is never scanned.
      runCleared([
        ...cheapClimb(),
        ...firstPass(SMALL_MS, (i) => (i < 3 ? STALLED_LARGE_MS : CLEAN_LARGE_MS)),
      ]);
    });

    it('a stall on every larger reading of the first pass is sampled again, not reported', () => {
      // The second loop reads the pair at 2x. The doubling after it reads 3.3x,
      // so the pair's own ratio in that loop is what clears the rule.
      runCleared([
        ...cheapClimb(),
        ...firstPass(SMALL_MS, STALLED_LARGE_MS),
        ...confirmPass(SMALL_MS, CLEAN_LARGE_MS, NEXT_MS),
      ]);
    });

    it('a single clean round among stalled ones is enough to clear a linear rule', () => {
      // The fastest reading on each side decides, wherever in the run it falls.
      const last = GROWTH_CONFIRM_SAMPLES - 1;
      runCleared([
        ...cheapClimb(),
        ...firstPass(SMALL_MS, STALLED_LARGE_MS),
        ...confirmPass(SMALL_MS, (i) => (i === last ? CLEAN_LARGE_MS : STALLED_LARGE_MS), NEXT_MS),
      ]);
    });

    it('a stall on all but one reading of the next doubling does not read as growth', () => {
      // 3.3x, then 4x on fourteen readings and 2x on the last.
      const last = GROWTH_CONFIRM_SAMPLES - 1;
      runCleared([
        ...cheapClimb(),
        ...firstPass(3, 10),
        ...confirmPass(3, 10, (i) => (i === last ? 20 : 40)),
      ]);
    });
  });

  describe('the growth tier compares readings taken in the same rounds', () => {
    // A quadratic rule that reads 3 / 12 / 48 ms on a quiet machine.
    it('quadratic growth is a breach: 4x, then 4x', () => {
      expect(
        runBreached([...cheapClimb(), ...firstPass(3, 12), ...confirmPass(3, 12, 48)]),
      ).toEqual({
        reason: 'superlinear',
        corpus: GROWTH_CORPORA[0]?.name,
        ...TOP,
        smallMs: 3,
        largeMs: 12,
        nextChars: NEXT_CHARS,
        nextMs: 48,
      });
    });

    it('the same quadratic rule is a breach when every size runs 1.4x slower', () => {
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(4.2, 16.8),
        ...confirmPass(4.2, 16.8, 67.2),
      ]);
      // The clock accumulates, so these readings are differences of sums.
      expect(breach.reason).toBe('superlinear');
      expect(breach.largeMs).toBeCloseTo(16.8);
      expect(breach.nextMs).toBeCloseTo(67.2);
    });

    it('a quadratic rule is a breach when only the first pass ran slow', () => {
      // The verdict is given on the second loop's readings alone: 12 over 3,
      // then 48 over 12, not 48 over the first pass's 16.8.
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(4.2, 16.8),
        ...confirmPass(3, 12, 48),
      ]);
      expect(breach).toMatchObject({ reason: 'superlinear', smallMs: 3, largeMs: 12, nextMs: 48 });
    });

    it('a step followed by linear growth is not a breach: 3.3x, then 2x', () => {
      runCleared([...cheapClimb(), ...firstPass(3, 10), ...confirmPass(3, 10, 20)]);
    });

    it('a step followed by linear growth is not a breach when the second loop runs 1.6x slower', () => {
      // 4.8 / 16 / 32: the slow stretch is on all three sizes, so the second
      // ratio is still 2x. Against the first pass's 10ms it would read 3.2x.
      runCleared([...cheapClimb(), ...firstPass(3, 10), ...confirmPass(4.8, 16, 32)]);
    });

    it('growth just over the ratio on both doublings is a breach: 3.3x, then 3.3x', () => {
      const breach = runBreached([...cheapClimb(), ...firstPass(3, 10), ...confirmPass(3, 10, 33)]);
      expect(breach).toMatchObject({ reason: 'superlinear', largeMs: 10, nextMs: 33 });
      expect(describeBreach(breach)).toContain(
        `3.0ms at ${String(TOP.smallChars)} chars and 10.0ms at ${String(TOP.largeChars)} chars ` +
          `(3.3x for 2x the input), then 33.0ms at ${String(NEXT_CHARS)} chars ` +
          `(3.3x for 2x the input); superlinear`,
      );
    });
  });

  describe('the growth tier judges the budget at the pair, and the next doubling on its ratio', () => {
    const OVER_BUDGET_MS = BUDGET_MS + 20;

    it('a pair under the ratio is not measured at the next doubling: 31 / 90', () => {
      runCleared([...cheapClimb(), ...firstPass(31, 90)]);
    });

    it('a linear rule past a step is not a breach, whatever the next doubling costs: 15 / 55 / 110', () => {
      // 3.7x across the step, then 2x at a cost over the budget. Sampling stops
      // once OVER_BUDGET_READINGS rounds have all read the largest size over
      // the budget; the script holds exactly those rounds.
      expect(110).toBeGreaterThanOrEqual(BUDGET_MS);
      runCleared([
        ...cheapClimb(),
        ...firstPass(15, 55),
        ...confirmPass(15, 55, 110, OVER_BUDGET_READINGS),
      ]);
    });

    it('growth that persists into a next doubling over the budget is superlinear', () => {
      // 3.3x, then 12x: a cubic curve or worse, decided in the same rounds.
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(3, 10),
        ...confirmPass(3, 10, OVER_BUDGET_MS, OVER_BUDGET_READINGS),
      ]);
      expect(breach).toMatchObject({
        reason: 'superlinear',
        largeMs: 10,
        nextChars: NEXT_CHARS,
        nextMs: OVER_BUDGET_MS,
      });
    });

    it('a next doubling that read over the budget at first is sampled to the end', () => {
      // Two readings over the budget and the rest under it: no early stop, and
      // the fastest reading is 2x the pair's.
      runCleared([
        ...cheapClimb(),
        ...firstPass(3, 10),
        ...confirmPass(3, 10, (i) => (i < OVER_BUDGET_READINGS - 1 ? OVER_BUDGET_MS : 20)),
      ]);
    });

    it('a pair over the budget is a breach without measuring the next doubling', () => {
      // Decided once OVER_BUDGET_READINGS larger readings have all crossed the
      // budget; the script holds exactly those rounds and no scan at the next
      // doubling.
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(3, OVER_BUDGET_MS, OVER_BUDGET_READINGS),
      ]);
      expect(breach).toMatchObject({ reason: 'over-budget', ...TOP, largeMs: OVER_BUDGET_MS });
      expect(breach.nextMs).toBeUndefined();
      expect(breach.nextChars).toBeUndefined();
    });

    it('a pair over the budget is a breach at any ratio', () => {
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(OVER_BUDGET_MS / 2, OVER_BUDGET_MS, OVER_BUDGET_READINGS),
      ]);
      expect(breach).toMatchObject({ reason: 'over-budget', largeMs: OVER_BUDGET_MS });
    });

    it('a larger reading over the budget on fewer readings than that is sampled to the end', () => {
      runCleared([
        ...cheapClimb(),
        ...firstPass(3, (i) => (i < OVER_BUDGET_READINGS - 1 ? OVER_BUDGET_MS : 6)),
      ]);
    });

    it('a size the tier just measured is not scanned again as the next scout', () => {
      // The scout at the second size crosses the budget, so the pair under it
      // is sampled: over the ratio, then 2x at the third size. That reading is
      // the third size's scout, and the script holds no further scan of it.
      const [, , ...later] = SCOUT_SIZES;
      expect(later.length).toBeGreaterThanOrEqual(2);
      runCleared([
        1,
        OVER_BUDGET_MS,
        ...firstPass(3, 10),
        ...confirmPass(3, 10, 20),
        ...later.slice(1).map(() => 1),
        ...firstPass(3, 6),
      ]);
    });
  });

  describe('the growth tier asks a corroborating clock before it reports a pair over the budget', () => {
    const OVER_BUDGET_MS = BUDGET_MS + 20;

    // A corroborating clock that reads `perScan` over every window it is
    // asked about. It is read twice per scan, and only on the first pass of a
    // pair: the scouts and the second pass give their verdicts on `now` alone.
    function steadyWork(perScan: number): ProbeClock {
      let reads = 0;
      return () => {
        const read = reads++;
        return Math.floor(read / 2) * perScan + (read % 2) * perScan;
      };
    }

    // An over-budget pair at a ratio of two, so a pair the corroborating clock
    // turns away is cleared on its ratio rather than sampled again.
    const overBudgetPair = (): number[] => [
      ...cheapClimb(),
      ...firstPass(OVER_BUDGET_MS / 2, OVER_BUDGET_MS, OVER_BUDGET_READINGS),
    ];

    it('a pair over the budget on the wall that did no work is judged on its ratio', () => {
      const { clock, unread } = scripted(GROWTH_CORPORA.flatMap(overBudgetPair));
      const breach = superlinearGrowth(scriptedRule, clock, steadyWork(6.4));
      expect(breach && describeBreach(breach)).toBeUndefined();
      expect(unread(), 'scripted scans the tier did not make').toBe(0);
    });

    it('a reading just under the floor is not corroboration', () => {
      const { clock } = scripted(GROWTH_CORPORA.flatMap(overBudgetPair));
      const breach = superlinearGrowth(
        scriptedRule,
        clock,
        steadyWork(GROWTH_CORROBORATION_FLOOR_MS - 0.001),
      );
      expect(breach && describeBreach(breach)).toBeUndefined();
    });

    it('a pair the corroborating clock confirms is a breach, and says what it read', () => {
      const { clock, unread } = scripted(overBudgetPair());
      const breach = superlinearGrowth(
        scriptedRule,
        clock,
        steadyWork(GROWTH_CORROBORATION_FLOOR_MS),
      );
      expect(unread(), 'scripted scans the tier did not make').toBe(0);
      expect(breach).toMatchObject({
        reason: 'over-budget',
        ...TOP,
        largeMs: OVER_BUDGET_MS,
        largeWorkMs: GROWTH_CORROBORATION_FLOOR_MS,
      });
      if (!breach) throw new Error('expected a breach');
      expect(describeFailure('pack/rule', breach)).toContain(
        `${String(OVER_BUDGET_MS)}.0ms (${GROWTH_CORROBORATION_FLOOR_MS.toFixed(1)}ms of it`,
      );
    });

    it('without a corroborating clock, the wall reading decides alone', () => {
      const { clock } = scripted(overBudgetPair());
      expect(superlinearGrowth(scriptedRule, clock)).toMatchObject({
        reason: 'over-budget',
        largeMs: OVER_BUDGET_MS,
      });
    });
  });

  describe('a verdict that fails the run has to reproduce', () => {
    const breach: GrowthBreach = {
      reason: 'superlinear',
      corpus: 'space run',
      ...TOP,
      smallMs: 3,
      largeMs: 12,
      nextChars: NEXT_CHARS,
      nextMs: 48,
    };
    const fails = (found: GrowthBreach | undefined): boolean => found !== undefined;

    function sequence(verdicts: (GrowthBreach | undefined)[]): () => GrowthBreach | undefined {
      let at = 0;
      return () => {
        if (at >= verdicts.length) throw new Error('run past the scripted verdicts');
        return verdicts[at++];
      };
    }

    it('fails only when every run gives it', () => {
      const runs = Array.from({ length: GROWTH_RUNS }, () => breach);
      expect(repeatedVerdicts(sequence(runs), fails)).toEqual({ verdicts: runs, failed: true });
    });

    it('a single run that does not give it clears the rule, and stops there', () => {
      const runs = [breach, undefined];
      expect(repeatedVerdicts(sequence(runs), fails)).toEqual({ verdicts: runs, failed: false });
    });

    it('a first run that does not give it is the only run', () => {
      expect(repeatedVerdicts(sequence([undefined]), fails)).toEqual({
        verdicts: [undefined],
        failed: false,
      });
    });
  });

  describe('the clock the growth tier reads', () => {
    it('reads clocks that advance', () => {
      // A clock stuck at a constant reads every scan as free. As the reading
      // clock that clears every rule and misses every control; as the
      // corroborating clock it turns away every over-budget pair. The thread
      // CPU clock is one or the other on every platform, and a dead one would
      // also measure as infinitely coarse and quietly move the readings to the
      // wall, so it is checked by name.
      const clocks = [GROWTH_CLOCK.now, GROWTH_CLOCK.corroborate, threadCpuMs].filter(
        (clock): clock is ProbeClock => clock !== undefined,
      );
      const starts = clocks.map((clock) => clock());
      let spun = 0;
      // Enough work to cross a 16ms tick several times over.
      for (let i = 0; i < 100_000_000; i++) spun += i % 7;
      expect(spun).toBeGreaterThan(0);
      clocks.forEach((clock, i) => {
        expect(clock(), `clock ${String(i)} of the growth tier did not advance`).toBeGreaterThan(
          starts[i] ?? Infinity,
        );
      });
      expect(Number.isFinite(THREAD_CPU_RESOLUTION_MS)).toBe(true);
    });

    it('is not one that advances in scheduler ticks', () => {
      // The resolution measurement is what keeps a tick-credited CPU clock off
      // the ratio. Driven with a scripted 16ms tick: the step it reports is
      // the tick, which is far past what a ratio of 5ms readings can use.
      let reads = 0;
      const ticking: ProbeClock = () => Math.floor(reads++ / 3) * 16;
      expect(clockResolutionMs(ticking)).toBe(16);
      expect(clockResolutionMs(ticking)).toBeGreaterThan(RATIO_RESOLUTION_MS);
      if (GROWTH_CLOCK.now === threadCpuMs) {
        expect(THREAD_CPU_RESOLUTION_MS).toBeLessThanOrEqual(RATIO_RESOLUTION_MS);
      } else {
        expect(THREAD_CPU_RESOLUTION_MS).toBeGreaterThan(RATIO_RESOLUTION_MS);
      }
    });
  });

  describe('what a failing bundled rule is told', () => {
    const pair = { corpus: 'space run', ...TOP, smallMs: 15, largeMs: 120 };

    it('an over-budget breach is described by its cost, not by its growth', () => {
      const message = describeFailure('pack/rule', { reason: 'over-budget', ...pair });
      expect(message).toContain(`120.0ms to scan ${String(TOP.largeChars)} chars`);
      expect(message).toContain(`over the ${String(BUDGET_MS)}ms budget`);
      expect(message).not.toContain('linear');
    });

    it('a superlinear breach names the largest size that was measured', () => {
      const message = describeFailure('pack/rule', {
        reason: 'superlinear',
        ...pair,
        largeMs: 60,
        nextChars: NEXT_CHARS,
        nextMs: 240,
      });
      expect(message).toContain('more than linear time');
      expect(message).toContain(`up to ${String(NEXT_CHARS)} chars`);
      expect(message).not.toContain(`${String(TOP.largeChars)} chars`);
    });
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
