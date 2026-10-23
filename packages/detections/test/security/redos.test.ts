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
  GROWTH_FLOOR_MS,
  GROWTH_MAX_CHARS,
  GROWTH_SAMPLES,
  GROWTH_START_CHARS,
  GROWTH_WINDOW_DEADLINE_MS,
  GROWTH_WINDOW_STEPS,
  MAX_GROWTH_RATIO,
  OVER_BUDGET_READINGS,
  POLYNOMIAL_PROBES,
  SAMPLED_GROWTH,
  superlinearGrowth,
  windowReadingMs,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';
import { growthClock, medianStepMs, threadCpuMs } from '../helpers/growth-clock.ts';
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
const cpuMs: ProbeClock = () => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

const growth = growthClock();
const measuredGrowth = (rule: Rule): GrowthBreach | undefined =>
  superlinearGrowth(rule, growth.now, growth.stepMs);

// The same thread CPU clock rounded down to whole 16ms steps: the Windows
// runner's clock, imposed so the growth tier's windows are exercised on every
// machine rather than only where that clock is native.
const STEP_16_MS = 16;
const steppedThreadCpuMs: ProbeClock = () => Math.floor(threadCpuMs() / STEP_16_MS) * STEP_16_MS;
const measuredGrowthOn16msSteps = (rule: Rule): GrowthBreach | undefined =>
  superlinearGrowth(rule, steppedThreadCpuMs, STEP_16_MS);

// The per-rule budget, judged so that only a breach that reproduces fails.
//
// The in-process walk above is the screen. A walk that crosses the budget is
// measured again on a fresh worker thread (`walkInIsolation`): a new isolate,
// so every pattern runs interpreted again exactly as it did the first time,
// charged with that thread's own CPU, so neither the GC and compiler threads
// nor anything else in this process is in the reading. Only that second
// reading decides, and it clears the rule only from at least one clock step
// under the budget (below). A rule that really backtracks burns the same CPU
// on any thread and fails both. A first reading that was inflated by work the rule
// did not do is cleared by the second; benign rules have crossed the budget
// in-process on the loaded Windows runner, where that clock also advances in
// whole 16ms ticks.
//
// Measuring again on the SAME thread is not an option and is not what this
// does: the regex would run natively compiled the second time, at a fraction
// of the interpreted cost a hook process pays (see `worstProbeMs`).
//
// The re-measurement clears a rule only when it reads at least one clock step
// under the budget. A clock that advances in whole steps reads low by up to a
// step — on a 15.6ms-tick clock a 100-115ms breach can read 93.75ms — so a
// reading within one step of the budget cannot tell a real breach from a cheap
// rule, and it stays a breach. `resolutionMs` is that clock's measured step.
//
// `screen` and `remeasure` are the two walks, injectable so the wiring between
// them can be driven with scripted readings; the defaults are the real ones.
interface ProbeWalks {
  screen: (rule: Rule) => { ms: number };
  remeasure: (rule: Rule) => Promise<{ ms: number; probeLength: number; resolutionMs: number }>;
}
// Measured once, on the first screened breach. The worker reads the same
// per-thread CPU clock, so its step is this one. A clock too coarse to measure
// reads Infinity, which clears nothing.
let threadCpuStepMs: number | undefined;
const realProbeWalks: ProbeWalks = {
  screen: (rule) => worstProbeMs(rule, cpuMs),
  remeasure: async (rule) => {
    const walk = await walkInIsolation(rule);
    threadCpuStepMs ??= medianStepMs(threadCpuMs);
    return { ms: walk.ms, probeLength: walk.probeLength, resolutionMs: threadCpuStepMs };
  },
};

async function probeBudgetBreach(
  rule: Rule,
  { screen, remeasure }: ProbeWalks = realProbeWalks,
): Promise<{ firstMs: number; isolatedMs: number; probeLength: number } | undefined> {
  const first = screen(rule);
  if (first.ms < BUDGET_MS) return undefined;
  const isolated = await remeasure(rule);
  if (isolated.ms < BUDGET_MS - isolated.resolutionMs) return undefined;
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

  // The re-measurement is only worth having if it still pays what a hook
  // pays: the pattern's first, interpreted run. So the fresh-thread reading is
  // compared with what the SAME probe costs on this thread once the pattern is
  // compiled, rather than with the budget — a ratio of two runs of one probe
  // on one machine, which faster hardware moves on both sides.
  //
  // The pattern is walked on this thread first, which is the state every rule
  // is in when its in-process walk has just breached. A worker that measured
  // the compiled tier, or a re-measurement taken on this thread, reads the
  // compiled cost and a ratio near 1. Measured on an arm64 Mac at 7.4-7.8x
  // (122-130ms against 16.5-16.8ms), against a bound of 3.
  //
  // On a clock that advances in whole steps a reading is low by up to a step,
  // and the two readings must be read alike. The compiled cost is timed on
  // this thread's clock as it is, unquantized, so it is exact; under one step
  // the clock cannot tell the two tiers apart, and three times a cost that
  // small is a bound a coarse reading clears or misses by chance, so the case
  // is skipped saying so. The bound is floored at one step for the same
  // reason. The fresh-thread reading is the worker's, in whole steps, so it
  // stands for anything up to one step more: it is cold when the reading
  // itself clears the bound, compiled only when one step more would still sit
  // under it, and unmeasurable in between.
  const FRESH_THREAD_RATIO = 3;

  function freshThreadVerdict(
    isolatedMs: number,
    compiledMs: number,
    stepMs: number,
  ): { verdict: 'cold' | 'compiled' | 'unmeasurable'; boundMs: number } {
    const boundMs = Math.max(compiledMs, stepMs) * FRESH_THREAD_RATIO;
    if (isolatedMs > boundMs) return { verdict: 'cold', boundMs };
    if (compiledMs < stepMs || isolatedMs + stepMs > boundMs) {
      return { verdict: 'unmeasurable', boundMs };
    }
    return { verdict: 'compiled', boundMs };
  }

  it.each([
    ['cold against a compiled reading of one step', 125, 16, 16, 'cold'],
    ['cold against a compiled reading of zero, floored at the step', 125, 0, 16, 'cold'],
    ['compiled against a compiled reading of zero', 40, 0, 16, 'unmeasurable'],
    ['compiled against a measured compiled reading', 64, 48, 16, 'compiled'],
    ['compiled on a fine clock', 70, 65, 0.001, 'compiled'],
    ['compiled when a compiled-tier walk reads one step on a 16ms clock', 16, 17, 16, 'compiled'],
    // A 61ms fresh-thread walk floored to 48ms, against 8ms compiled: under one
    // step, so neither tier can be told apart.
    ['unmeasurable for a 61ms walk floored to 48 against 8ms compiled', 48, 8, 16, 'unmeasurable'],
    // The same floored walk against 17ms compiled: 3.6x if the walk took 61ms,
    // so the floor alone decides whether it clears the 51ms bound.
    ['unmeasurable for a walk floored to within one step of the bound', 48, 17, 16, 'unmeasurable'],
  ] as const)(
    'the fresh-thread verdict reads %s',
    (_label, isolatedMs, compiledMs, stepMs, verdict) => {
      expect(freshThreadVerdict(isolatedMs, compiledMs, stepMs).verdict).toBe(verdict);
    },
  );

  async function checkFreshThread(
    skip: (reason: string) => void,
    stepMs: number,
    clockName: string,
  ): Promise<void> {
    const parsed = parseRegexRule('^(a+)+bc');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const stepped: ProbeClock = () =>
      stepMs > 0 ? Math.floor(threadCpuMs() / stepMs) * stepMs : threadCpuMs();
    worstProbeMs(parsed.data, stepped);
    // A fixed step of zero means the clock as it is, measured at its own
    // resolution; a forced step is the resolution by construction.
    const isolated = await walkInIsolation(parsed.data, stepMs);
    expect(isolated.probe.length, 'the fresh-thread walk attributed no probe').toBeGreaterThan(0);
    // Both readings of each compiled run: the stepped one is reported, the
    // unquantized one is what the verdict reads.
    let compiledMs = Infinity;
    let compiledSteppedMs = Infinity;
    for (let i = 0; i < 5; i++) {
      const startRaw = threadCpuMs();
      const start = stepped();
      scan(isolated.probe, [parsed.data]);
      const end = stepped();
      compiledMs = Math.min(compiledMs, threadCpuMs() - startRaw);
      compiledSteppedMs = Math.min(compiledSteppedMs, end - start);
    }
    const resolutionMs = stepMs > 0 ? stepMs : medianStepMs(threadCpuMs);
    const { verdict, boundMs } = freshThreadVerdict(isolated.ms, compiledMs, resolutionMs);
    const readings =
      `the fresh-thread walk read ${isolated.ms.toFixed(1)}ms of CPU on its ` +
      `${String(isolated.probeLength)}-char probe, which reads ${compiledMs.toFixed(1)}ms on this ` +
      `thread compiled (${compiledSteppedMs.toFixed(1)}ms on the stepped clock), on ${clockName} ` +
      `(step ${resolutionMs.toFixed(3)}ms, bound ${boundMs.toFixed(1)}ms)`;
    if (verdict === 'unmeasurable') {
      skip(
        `${readings}: the compiled run read under one clock step, or the fresh-thread reading within one step of the bound, so this clock cannot tell the two tiers apart`,
      );
      return;
    }
    expect(
      verdict,
      `${readings}; a re-measurement that is not paying the interpreted cost clears every ` +
        `breach the in-process walk finds.`,
    ).toBe('cold');
  }

  it('measures a breach again on a fresh thread at its interpreted cost', async (ctx) => {
    await checkFreshThread((reason) => ctx.skip(reason), 0, 'thread CPU time');
  });

  it('measures it so on a CPU clock that advances in 16ms steps', async (ctx) => {
    // The Windows runner's clock, imposed on both threads, so this case runs
    // on every machine rather than only where that clock is native.
    await checkFreshThread((reason) => ctx.skip(reason), 16, 'a 16ms-step thread CPU clock');
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
    `${breach.reason}, each reading taken over several rounds`
  );
}

// The growth tier: how each rule's cost scales with input on structured
// corpora, which the absolute-budget walk above cannot see. A pattern that is
// quadratic with a small constant passes every 40KB probe and still costs
// seconds at the engine's 200,000-char input cap.
//
// The clock is the scanning thread's CPU time, on every platform
// (`growthClock`). Elapsed time is not a measure of work on a loaded runner. A
// scan that allocates fresh pages on every call, as V8 does once an input
// crosses its large-object size, is rescheduled around each page fault, and
// that stall grows faster than the input: a linear rule reads as superlinear,
// or as over the budget, and more samples do not remove it, because every
// sample pays it. CPU time does not count the waiting.
//
// It does advance in steps, from microseconds on macOS to 16ms on the Windows
// runner, and a single scan read on a stepped clock is its cost rounded to a
// step either way. So a pair reading repeats its scan until the clock has
// advanced by GROWTH_WINDOW_STEPS steps and reads the cost per scan
// (`windowReadingMs`); a pair whose larger text reads under the floor beyond
// one step is cleared as soon as one window shows it, so a cheap rule does not
// pay for whole windows. Each side of a ratio is then the FASTEST of its
// windows, taken in the same rounds: what a busy machine adds to work — a GC
// pause, a slower core, an emptied cache — can only leave a window alone or
// inflate it, and the rounding the window bounds is the one error that runs
// the other way. One doubling over the ratio is not a breach by itself: the
// growth has to persist over the next doubling, which is what separates a
// quadratic curve from a linear one with a step in it. Nor is one doubling
// under it a clearance: a pair over SAMPLED_GROWTH is read with the next
// doubling too, and the two are judged together, because a quadratic rule can
// read under the ratio on the pair alone on a loaded machine. The
// scripted-clock suites below pin each of these.

// What a failing bundled rule is told. An `over-budget` breach is a statement
// about cost at one size and says nothing about the shape of the curve; a
// `superlinear` one is a statement about shape over two doublings.
function describeFailure(id: string, breach: GrowthBreach): string {
  const consequence =
    `scan() runs each rule on up to ${String(MAX_REGEX_INPUT_LENGTH)} chars per field, and a ` +
    `hook that outlives its timeout fails open.`;
  if (breach.reason === 'over-budget') {
    return (
      `Rule "${id}" takes ${breach.largeMs.toFixed(1)}ms to scan ${String(breach.largeChars)} ` +
      `chars of one corpus, over the ${String(BUDGET_MS)}ms budget for a single scan. ` +
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
      const breach = measuredGrowth(rule);
      expect(
        breach && describeBreach(breach),
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

  // The fresh-thread re-measurement decides every per-rule verdict, so the
  // wiring between the screen and it is pinned on scripted readings: a
  // breach needs the screen over the budget and the re-measurement no more
  // than one clock step under it, the re-measurement runs only on a
  // screened breach, and a re-measurement that read nothing clears nothing
  // into a breach. The live halves are pinned elsewhere: the screen by the case
  // above, the re-measurement's cost by the fresh-thread control.
  describe('a per-rule breach is the screen and the fresh-thread re-measurement together', () => {
    const OVER = BUDGET_MS + 20;
    const UNDER = BUDGET_MS - 20;
    const parsed = parseRegexRule('wiring');
    if (!parsed.success) throw new Error('the scripted rule did not parse');
    const rule = parsed.data;
    function walks(screenMs: number, remeasureMs: number, resolutionMs = 1) {
      const calls = { screen: 0, remeasure: 0 };
      const scripted: ProbeWalks = {
        screen: () => {
          calls.screen++;
          return { ms: screenMs };
        },
        remeasure: () => {
          calls.remeasure++;
          return Promise.resolve({ ms: remeasureMs, probeLength: 25, resolutionMs });
        },
      };
      return { calls, scripted };
    }

    it('is a breach when both walks read over the budget', async () => {
      const { calls, scripted } = walks(OVER, OVER + 5);
      expect(await probeBudgetBreach(rule, scripted)).toEqual({
        firstMs: OVER,
        isolatedMs: OVER + 5,
        probeLength: 25,
      });
      expect(calls).toEqual({ screen: 1, remeasure: 1 });
    });

    it('is cleared when the re-measurement reads under the budget', async () => {
      const { calls, scripted } = walks(OVER, UNDER);
      expect(await probeBudgetBreach(rule, scripted)).toBeUndefined();
      expect(calls).toEqual({ screen: 1, remeasure: 1 });
    });

    it('does not re-measure a rule the screen cleared', async () => {
      const { calls, scripted } = walks(UNDER, OVER);
      expect(await probeBudgetBreach(rule, scripted)).toBeUndefined();
      expect(calls).toEqual({ screen: 1, remeasure: 0 });
    });

    it('is cleared when the re-measurement reads zero', async () => {
      const { calls, scripted } = walks(OVER, 0);
      expect(await probeBudgetBreach(rule, scripted)).toBeUndefined();
      expect(calls).toEqual({ screen: 1, remeasure: 1 });
    });

    it('is a breach when the re-measurement reads one step under the budget on a 16ms clock', async () => {
      // 84ms in 16ms steps can be any cost up to 100ms, so it clears nothing.
      const { calls, scripted } = walks(OVER, BUDGET_MS - 16, 16);
      expect(await probeBudgetBreach(rule, scripted)).toEqual({
        firstMs: OVER,
        isolatedMs: BUDGET_MS - 16,
        probeLength: 25,
      });
      expect(calls).toEqual({ screen: 1, remeasure: 1 });
    });

    it('is cleared when the re-measurement reads more than one step under the budget', async () => {
      const { scripted } = walks(OVER, BUDGET_MS - 17, 16);
      expect(await probeBudgetBreach(rule, scripted)).toBeUndefined();
    });
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

    // What a breach has to show: a cost over the budget, or growth past the
    // ratio on the second doubling and past its square across both.
    const showsGrowth = (breach: GrowthBreach): boolean => {
      if (breach.reason === 'over-budget') return true;
      const nextMs = breach.nextMs ?? 0;
      return (
        nextMs / Math.max(breach.largeMs, 1e-6) > MAX_GROWTH_RATIO &&
        nextMs / Math.max(breach.smallMs, 1e-6) > MAX_GROWTH_RATIO ** 2
      );
    };

    // A "catches" control asserts the tier CAN see a pattern that is known to be
    // superlinear, so a measurement spoiled by the machine (every round of one
    // size inflated by a neighbour's load, which pulls the ratio under the line)
    // is retried: the first breach of up to CATCH_ATTEMPTS measurements is the
    // one judged. A genuinely blind tier misses on every attempt and still
    // fails; the linear controls and the bundled-rule gate are not retried, so
    // a pattern is never cleared by a lucky measurement.
    //
    // This changes what the control proves: from "the tier sees this pattern
    // every time" to "the tier sees it at least once in CATCH_ATTEMPTS". The
    // retry is a statement about a noisy machine, not about the tier; a tier
    // that needs all the attempts is a weaker gate than it looks, so watch how
    // often the later attempts are the ones that breach.
    const CATCH_ATTEMPTS = 3;
    const firstBreach = (measure: (rule: Rule) => GrowthBreach | undefined, rule: Rule) => {
      let last: GrowthBreach | undefined;
      for (let attempt = 0; attempt < CATCH_ATTEMPTS; attempt++) {
        last = measure(rule);
        if (last) return last;
      }
      return last;
    };

    it.each(superlinear)('catches %s', (_label, rule) => {
      const breach = firstBreach(measuredGrowth, rule);
      expect(breach, 'the growth tier passed a pattern that is superlinear at scale').toBeDefined();
      if (!breach) return;
      expect(showsGrowth(breach), describeBreach(breach)).toBe(true);
    });

    it.each(superlinear)(
      'catches %s on a CPU clock that advances in 16ms steps',
      (_label, rule) => {
        // The smaller reading of each pair here costs a step or less, so a
        // single scan reads it as one step or as nothing. Only the window
        // resolves it.
        const breach = firstBreach(measuredGrowthOn16msSteps, rule);
        expect(
          breach,
          'the growth tier passed a pattern that is superlinear at scale',
        ).toBeDefined();
        if (!breach) return;
        expect(showsGrowth(breach), describeBreach(breach)).toBe(true);
      },
    );

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
      const native = measuredGrowth(rule);
      expect(native && describeBreach(native), 'thread CPU time').toBeUndefined();
      const stepped = measuredGrowthOn16msSteps(rule);
      expect(stepped && describeBreach(stepped), 'a 16ms-step CPU clock').toBeUndefined();
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
  // one scan per size, in the order given.
  const rounds = (count: number, ...sizes: Reading[]): number[] =>
    Array.from({ length: count }, (_, round) => sizes.map((size) => at(size, round))).flat();
  // A climb whose scouts all read cheap, so only the top pair is sampled.
  const cheapClimb = (): number[] => SCOUT_SIZES.map(() => 1);
  // The first pass reads the larger size first in each round, so a pair whose
  // larger text is under the floor is cleared before the smaller is read.
  const firstPass = (small: Reading, large: Reading, count = GROWTH_SAMPLES): number[] =>
    rounds(count, large, small);
  // `nextCount` is how many of the rounds also read the next doubling: fewer
  // than `count` when it reads over the budget and stops being read.
  const confirmPass = (
    small: Reading,
    large: Reading,
    next: Reading,
    count = GROWTH_CONFIRM_SAMPLES,
    nextCount = count,
  ): number[] =>
    Array.from({ length: count }, (_, round) => [
      at(small, round),
      at(large, round),
      ...(round < nextCount ? [at(next, round)] : []),
    ]).flat();

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
      // Two of three larger readings stalled: a median reads 30ms over 3ms,
      // the fastest reading 6ms over 3ms. The next doubling is never scanned.
      runCleared([
        ...cheapClimb(),
        ...firstPass(SMALL_MS, (i) => (i < 2 ? STALLED_LARGE_MS : CLEAN_LARGE_MS)),
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
      // 3.3x, then 4x on every reading but the last, and 2x on that.
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

  describe('a pair reading is a window of its clock', () => {
    // A run of fixed cost, read on a clock that advances in whole steps from a
    // given phase: `phase` ms into its first step.
    function stepped(costMs: number, stepMs: number, phase: number) {
      let time = phase;
      let runs = 0;
      return {
        run: () => {
          time += costMs;
          runs++;
        },
        now: (): number => Math.floor(time / stepMs) * stepMs,
        runs: () => runs,
      };
    }
    const phases = Array.from({ length: 16 }, (_, i) => i);

    it('one run of 3ms on a 16ms clock reads a whole step or nothing', () => {
      // The rounding a window exists to remove: no single reading is near 3.
      const single = phases.map((phase) => {
        const clock = stepped(3, 16, phase);
        const start = clock.now();
        clock.run();
        return clock.now() - start;
      });
      expect(new Set(single)).toEqual(new Set([0, 16]));
    });

    it.each(phases)(
      'a window of 3ms runs on a 16ms clock reads 3ms within one step over its runs (phase %i)',
      (phase) => {
        const clock = stepped(3, 16, phase);
        const { ms, cleared } = windowReadingMs(clock.run, clock.now, 16);
        expect(cleared).toBe(false);
        expect(clock.runs() * 3).toBeGreaterThanOrEqual(16 * GROWTH_WINDOW_STEPS - 16);
        expect(Math.abs(ms - 3)).toBeLessThanOrEqual(16 / clock.runs());
      },
    );

    it('a clock with no step reads one run', () => {
      const clock = stepped(3, 1e-9, 0);
      expect(windowReadingMs(clock.run, clock.now, 0).ms).toBeCloseTo(3);
      expect(clock.runs()).toBe(1);
    });

    it.each(phases)(
      'a cheap run is cleared under a line after a few runs, not a whole window (phase %i)',
      (phase) => {
        const clock = stepped(0.5, 16, phase);
        expect(windowReadingMs(clock.run, clock.now, 16, 5).cleared).toBe(true);
        expect(clock.runs()).toBeLessThanOrEqual(8);
      },
    );

    it.each(phases)(
      'a run over the line is never cleared under it, however the steps fall (phase %i)',
      (phase) => {
        // The window reads 0 for the first runs on most phases, and 0 plus one
        // step is still over 5ms a run until enough runs have been made to
        // show the cost: the bound clears nothing it cannot prove.
        const clock = stepped(5.2, 16, phase);
        const { ms, cleared } = windowReadingMs(clock.run, clock.now, 16, 5);
        expect(cleared).toBe(false);
        expect(ms).toBeGreaterThan(5.2 - 16 / clock.runs());
      },
    );

    it('a clock whose step was not measured is refused rather than read once', () => {
      const clock = stepped(3, 16, 0);
      expect(() => windowReadingMs(clock.run, clock.now, Infinity)).toThrow(
        /step was not measured/,
      );
    });

    // A clock that stops advancing never fills a window. The deadline is read
    // on an elapsed-time clock of its own, scripted here to pass a second a
    // read, and `run` gives up long after the deadline would have ended the
    // window, so a window with no deadline fails here instead of hanging.
    it.each([
      ['never advances', (): number => 0],
      [
        'advances once and then stops',
        (() => {
          let reads = 0;
          return (): number => (reads++ === 0 ? 0 : 5);
        })(),
      ],
    ])('a window on a clock that %s is refused at its deadline', (_, now) => {
      let wall = 0;
      const wallNow = (): number => (wall += 1_000);
      let runs = 0;
      const run = (): void => {
        if (++runs > 10_000) throw new Error('the window ran past its deadline');
      };
      expect(() => windowReadingMs(run, now, 16, undefined, wallNow)).toThrow(
        /the clock is starved or stopped/,
      );
      expect(runs).toBeLessThanOrEqual(GROWTH_WINDOW_DEADLINE_MS / 1_000);
    });
  });

  describe('the growth tier judges the budget at the pair, and the next doubling on its ratio', () => {
    const OVER_BUDGET_MS = BUDGET_MS + 20;

    it('a pair that grew linearly is not measured at the next doubling: 45 / 90', () => {
      runCleared([...cheapClimb(), ...firstPass(45, 90)]);
    });

    it('a pair at the line a quadratic next doubling would carry is not measured at it', () => {
      // SAMPLED_GROWTH times 4 is the square of the ratio, so a pair that grew by
      // no more than it cannot reach that square on one more quadratic doubling.
      expect(SAMPLED_GROWTH * 4).toBe(MAX_GROWTH_RATIO ** 2);
      runCleared([...cheapClimb(), ...firstPass(10, 10 * SAMPLED_GROWTH)]);
    });

    it('a pair under the ratio whose growth carries on is superlinear: 3 / 8.4 / 37', () => {
      // 2.8x, then 4.4x: a quadratic rule whose linear part still weighs on the
      // pair. 12.3x over the two doublings, against the ratio's square of 9.
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(3, 8.4),
        ...confirmPass(3, 8.4, 37),
      ]);
      // The clock accumulates, so these readings are differences of sums.
      expect(breach).toMatchObject({ reason: 'superlinear', smallMs: 3 });
      expect(breach.largeMs).toBeCloseTo(8.4);
      expect(breach.nextMs).toBeCloseTo(37);
    });

    it('a pair under the ratio is not a breach when the two doublings stay under its square: 3 / 7.2 / 25', () => {
      // 2.4x, then 3.5x: over the ratio on the second doubling, 8.3x over the two.
      runCleared([...cheapClimb(), ...firstPass(3, 7.2), ...confirmPass(3, 7.2, 25)]);
    });

    it('two doublings past the square are not a breach when the second is under the ratio: 3 / 20 / 58', () => {
      // 6.7x, then 2.9x: 19x over the two, all of it a step in the first.
      runCleared([...cheapClimb(), ...firstPass(3, 20), ...confirmPass(3, 20, 58)]);
    });

    it('a pair whose larger text reads under the floor is cleared on that one scan', () => {
      // The script holds the larger text's first reading and nothing else, so
      // reading the smaller text first, or reading on past the clear, scans
      // past the script.
      runCleared([...cheapClimb(), GROWTH_FLOOR_MS - 1]);
    });

    it('a linear rule past a step is not a breach, whatever the next doubling costs: 15 / 55 / 110', () => {
      // 3.7x across the step, then 2x at a cost over the budget. The next
      // doubling stops being read once OVER_BUDGET_READINGS rounds have all read
      // it over the budget; the pair is read through every round.
      expect(110).toBeGreaterThanOrEqual(BUDGET_MS);
      runCleared([
        ...cheapClimb(),
        ...firstPass(15, 55),
        ...confirmPass(15, 55, 110, GROWTH_CONFIRM_SAMPLES, OVER_BUDGET_READINGS),
      ]);
    });

    it('growth that persists into a next doubling over the budget is superlinear', () => {
      // 3.3x, then 12x: a cubic curve or worse, decided in the same rounds.
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(3, 10),
        ...confirmPass(3, 10, OVER_BUDGET_MS, GROWTH_CONFIRM_SAMPLES, OVER_BUDGET_READINGS),
      ]);
      expect(breach).toMatchObject({
        reason: 'superlinear',
        largeMs: 10,
        nextChars: NEXT_CHARS,
        nextMs: OVER_BUDGET_MS,
      });
    });

    it('a pair read slow on every round but the last still shows its growth when the next doubling is over the budget', () => {
      // 10 / 40 / 160 ms: 4x, then 4x. The pair reads 2x and 4x slow on every
      // round before the last, and the next doubling stops being read after
      // OVER_BUDGET_READINGS rounds. Ended with it, the pair's fastest readings
      // would be 20 and 160 ms against a next doubling of 160: no growth at all.
      const last = GROWTH_CONFIRM_SAMPLES - 1;
      const breach = runBreached([
        ...cheapClimb(),
        ...firstPass(10, 40),
        ...confirmPass(
          (i) => (i === last ? 10 : 20),
          (i) => (i === last ? 40 : 160),
          160,
          GROWTH_CONFIRM_SAMPLES,
          OVER_BUDGET_READINGS,
        ),
      ]);
      expect(breach).toMatchObject({
        reason: 'superlinear',
        smallMs: 10,
        largeMs: 40,
        nextMs: 160,
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
