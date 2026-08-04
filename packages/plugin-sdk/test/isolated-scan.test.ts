/**
 * The hard bound under the timing pre-flight.
 *
 * `rule-quarantine.ts` measures a rule against a fixed adversarial battery and
 * caches the verdict. That gate is empirical: it proves a pattern did not
 * backtrack on the inputs the battery constructs, not that it cannot. This
 * suite is built around two patterns that show where that leaves a gap, and
 * asserts the property the battery cannot give — whatever the pattern, the work
 * ends:
 *
 *   - one the battery CLEARS in microseconds and that then never returns on
 *     text the battery has no way to construct, which is what the isolated
 *     `scan` exists for;
 *   - one that hangs the BATTERY ITSELF, which is what the isolated `probe`
 *     exists for. Measuring a rule means driving its own pattern into
 *     backtracking, so the measurement is an unbounded run of an untrusted
 *     pattern too — and it runs first, before any scan.
 *
 * Both of those end at what the parent reports. The last block is about the
 * kill that ends the work, and is the only part of this file that watches the
 * thread rather than the answer.
 */
import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule, RuleProbeVerdict } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createIsolatedScanner } from '../src/isolated-scan.ts';
import type { RuleProbeGateway } from '../src/rule-quarantine.ts';
import { filterUnsafeRules } from '../src/rule-quarantine.ts';
import { spinCounters } from './helpers/spin-counters.ts';
import type { SpinningWorkerData } from './helpers/spinning-scan-worker.ts';

// The battery derives its probes from a pattern's own literal prefix and
// character classes. `literalPrefix` stops at the first `(`, so this pattern
// reports no prefix at all, and every probe — derived and fixed alike — fails
// at the `zzq` literal before it ever reaches the nested quantifier. The rule
// measures as safe and is admitted to the ruleset. Text that does carry the
// literal then drives `(a+)+$` into exponential backtracking.
const BATTERY_BLIND_PATTERN = String.raw`(?:zzq)(a+)+$`;
const BATTERY_BLIND_TEXT = `zzq${'a'.repeat(34)}!`;

// The other half of the gap. This one has no literal prefix at all, so the
// battery's own derived probe is `'a'.repeat(23) + '!'` — and four identical
// alternatives over 23 characters is ~4^23 paths, which does not come back.
// The measurement hangs, so a machine that measures it in-process never even
// reaches the scan it was trying to protect.
const BATTERY_KILLING_PATTERN = String.raw`(a|a|a|a)+$`;

const BUDGET_MS = 3_000;

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

const HOSTILE = regexRule('pulled/battery-blind', BATTERY_BLIND_PATTERN);
const BATTERY_KILLER = regexRule('pulled/battery-killer', BATTERY_KILLING_PATTERN);
const BENIGN = regexRule('pulled/benign', 'AKIA[A-Z0-9]{16}');

// Startup grace period for every scanner built here, and the reason is the test
// environment rather than the product's. CI runs the type-stripped `.ts` worker
// under vitest with the whole workspace's suites in parallel; a cold start on
// that path has been seen past 5s on a Windows runner, where the SHIPPED path
// starts a bundled 25KB script in ~15ms. Leaving these on the product's own
// ISOLATED_START_BUDGET_MS lets the runner's speed decide whether the assertion
// under test runs at all — the scanner reports `unavailable` and the case fails
// on something it was not written to measure. The two cases that ARE about the
// start budget pass their own value, which wins over this one.
const START_MS = 30_000;

// Applies START_MS unless the case sets its own.
function isolated(
  data: Parameters<typeof createIsolatedScanner>[0],
  opts: Parameters<typeof createIsolatedScanner>[1] = {},
) {
  return createIsolatedScanner(data, { startBudgetMs: START_MS, ...opts });
}

const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);
const NEVER_READY_WORKER = new URL('./helpers/never-ready-scan-worker.ts', import.meta.url);
const EXITING_WORKER = new URL('./helpers/exiting-scan-worker.ts', import.meta.url);
const LATE_PROGRESS_WORKER = new URL('./helpers/late-progress-scan-worker.ts', import.meta.url);
const SPINNING_WORKER = new URL('./helpers/spinning-scan-worker.ts', import.meta.url);

// How long the spinning fixture executes before it answers a job.
const SPIN_MS = 1_500;

// The deadline the kill cases run under. Short enough that it always lands
// while the fixture is still spinning; long enough that a job posted the
// instant the thread said `ready` is always delivered first, so a case that
// counts threads counts every one of them.
const KILL_BUDGET_MS = 600;

// How long a kill is given to land before the first heartbeat reading. Only an
// upper bound on the terminator: it reaches a tight loop at the next back-edge,
// which is microseconds, and reading too early would be the one way these cases
// could fail on a machine that is merely slow.
const KILL_SETTLE_MS = 400;

// How long the counters are watched afterwards.
const KILL_OBSERVE_MS = 2_500;

// The pre-flight's own pass budget must not be what ends the pass below. A rule
// it skips for lack of time is never measured, so it starts no thread — and the
// case would then assert its property over fewer threads than it meant to,
// silently, and most easily on the slow runner where the property matters most.
const PRE_FLIGHT_PASS_MS = Number.POSITIVE_INFINITY;

// A kill case pays a worker START (granted START_MS above) per thread it kills,
// the budget it kills on, and then the fixed observation window — three times
// over for the pre-flight case. Sized above that sum so a case that runs long
// fails on the assertion that names what went wrong, not on the package's 20s
// default, which just says the test timed out.
const KILL_CASE_TIMEOUT_MS = 120_000;

const wait = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

function fakeProbeCache(): RuleProbeGateway {
  const store = new Map<string, { verdict: RuleProbeVerdict; worstProbeMs: number }>();
  return {
    getRuleProbeVerdict: (key) => Promise.resolve(store.get(key)),
    setRuleProbeVerdict: (key, verdict, worstProbeMs) => {
      store.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
  };
}

function spinningWorkerData(counters: SharedArrayBuffer): SpinningWorkerData {
  return { verified: [], unverified: [], counters, spinMs: SPIN_MS };
}

describe('the residual risk the probe battery leaves open', () => {
  it('clears the timing pre-flight and still never returns on the right text', () => {
    // If this ever starts reporting unsafe, the battery grew a probe that
    // catches this shape — good news, and this whole suite would then be
    // testing a rule that never reaches the runtime. Change the pattern rather
    // than deleting the case: the gap is in the approach, not in one pattern.
    const verdict = checkRuleTiming(HOSTILE);
    expect(verdict.safe).toBe(true);
    expect(verdict.worstMs).toBeLessThan(10);
  });
});

describe('createIsolatedScanner.probe', () => {
  it('measures an ordinary rule and reports the battery verdict', async () => {
    const scanner = isolated({ verified: [], unverified: [] });
    try {
      const outcome = await scanner.probe(BENIGN);
      expect(outcome.status).toBe('ok');
      if (outcome.status !== 'ok') return;
      expect(outcome.safe).toBe(true);
      // The whole battery for a real rule is ~2ms at worst on an arm64 Mac; the
      // ceiling is loose enough to survive a loaded Windows runner.
      expect(outcome.worstMs).toBeLessThan(100);
    } finally {
      await scanner.close();
    }
  });

  it('reports the rule the battery clears as safe, so nothing over-quarantines', async () => {
    const scanner = isolated({ verified: [], unverified: [] });
    try {
      const outcome = await scanner.probe(HOSTILE);
      expect(outcome.status).toBe('ok');
      if (outcome.status !== 'ok') return;
      // Same verdict the in-process battery gives. Moving the measurement off
      // this thread must not change what it decides — only where it can be
      // killed. This rule is caught later, by the scan bound.
      expect(outcome.safe).toBe(true);
    } finally {
      await scanner.close();
    }
  });

  it('terminates a pattern that hangs the battery itself', async () => {
    // This is the case an in-process pre-flight cannot survive: measuring the
    // rule IS running it, so the gate meant to catch a catastrophic pattern is
    // itself hung by one. Left on the calling thread this call never returns
    // and the hook is killed by the harness — which fails open, unscanned.
    const scanner = isolated({ verified: [], unverified: [] }, { probeBudgetMs: 1_500 });
    try {
      const started = performance.now();
      const outcome = await scanner.probe(BATTERY_KILLER);
      const elapsedMs = performance.now() - started;

      expect(outcome.status).toBe('timeout');
      // A loose ceiling: the assertion is "the measurement ended", not "it
      // ended in exactly N ms".
      expect(elapsedMs).toBeLessThan(1_500 * 8);
    } finally {
      await scanner.close();
    }
  });

  it('keeps measuring after a terminated probe', async () => {
    // A hostile rule in the middle of a pack must not deny the rest of the pack
    // its verdict — the thread it killed is replaceable.
    const scanner = isolated({ verified: [], unverified: [] }, { probeBudgetMs: 1_000 });
    try {
      expect((await scanner.probe(BATTERY_KILLER)).status).toBe('timeout');
      const after = await scanner.probe(BENIGN);
      expect(after.status).toBe('ok');
      if (after.status !== 'ok') return;
      expect(after.safe).toBe(true);
    } finally {
      await scanner.close();
    }
  });
});

describe('createIsolatedScanner.scan', () => {
  it('returns the findings of the whole ruleset', async () => {
    const scanner = isolated({ verified: [BENIGN], unverified: [] });
    try {
      const outcome = await scanner.scan('key AKIA0123456789ABCDEF here');
      expect(outcome.status).toBe('ok');
      if (outcome.status !== 'ok') return;
      expect(outcome.findings.map((f) => f.ruleId)).toEqual(['pulled/benign']);
      expect(outcome.findings[0]?.rawMatch).toBe('AKIA0123456789ABCDEF');
    } finally {
      await scanner.close();
    }
  });

  it('blames nobody when it was not asked to attribute', async () => {
    // The cost of naming a rule is a whole extra pass over the unverified
    // rules, so an ordinary scan does not pay it: one scan() call, no progress
    // messages, and therefore no culprit. This is what keeps the isolated cost
    // scaling like the in-process cost.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN, HOSTILE] },
      { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    );
    try {
      expect((await scanner.scan('nothing to find here')).status).toBe('ok');
      const outcome = await scanner.scan(BATTERY_BLIND_TEXT);
      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      expect(outcome.culpritIndex).toBeUndefined();
    } finally {
      await scanner.close();
    }
  });

  it('terminates a rule that never returns, and says which one it was', async () => {
    const scanner = isolated(
      { verified: [], unverified: [BENIGN, HOSTILE] },
      { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    );
    try {
      // Warm the thread on a scan that finishes, so the deadline below is spent
      // on the hostile rule rather than on worker startup.
      expect((await scanner.scan('nothing to find here')).status).toBe('ok');

      const started = performance.now();
      const outcome = await scanner.scan(BATTERY_BLIND_TEXT, undefined, { attribute: true });
      const elapsedMs = performance.now() - started;

      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      // Index 1 of `unverified` — the hostile rule, not its benign neighbour.
      expect(outcome.culpritIndex).toBe(1);
      // The scan itself has no upper bound at all: left alone this text runs for
      // longer than any test suite would wait. A loose ceiling is the point —
      // the assertion is "it ended", not "it ended in exactly N ms".
      expect(elapsedMs).toBeLessThan(BUDGET_MS * 5);
    } finally {
      await scanner.close();
    }
  });

  it('names the rule at the SHIPPED attribution default, not just a test override', async () => {
    // Every other attributing case lowers minAttributionMs to 50ms so it can
    // use a short budget. That leaves the 500ms default — the guard that
    // decides whether a real machine ever quarantines anything — unexercised in
    // both directions. This is the "it still fires" half.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN, HOSTILE] },
      { budgetMs: BUDGET_MS },
    );
    try {
      expect((await scanner.scan('nothing to find here')).status).toBe('ok');
      const outcome = await scanner.scan(BATTERY_BLIND_TEXT, undefined, { attribute: true });
      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      expect(outcome.culpritIndex).toBe(1);
    } finally {
      await scanner.close();
    }
  });

  it('blames nobody for a rule that was merely resident when the deadline landed', async () => {
    // …and the "it holds back" half. This worker announces rule 1 late and then
    // hangs, which is what a machine freezing mid-scan looks like from the
    // parent: rule 1's residency (~1.2s) clears the shipped 500ms floor easily,
    // but is a minority of the ~3s job. A floor alone would quarantine rule 1
    // forever on that; the share test is what refuses.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN, HOSTILE] },
      { budgetMs: BUDGET_MS, workerUrl: LATE_PROGRESS_WORKER },
    );
    try {
      const outcome = await scanner.scan('anything', undefined, { attribute: true });
      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      expect(outcome.culpritIndex).toBeUndefined();
    } finally {
      await scanner.close();
    }
  });

  it('blames nobody when the hang is not inside a single unverified rule', async () => {
    // The hostile rule is verified here, so it is only ever run as part of the
    // combined pass — the stage the parent must not attribute to any one rule.
    const scanner = isolated(
      { verified: [HOSTILE], unverified: [BENIGN] },
      { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    );
    try {
      expect((await scanner.scan('nothing to find here')).status).toBe('ok');

      const outcome = await scanner.scan(BATTERY_BLIND_TEXT, undefined, { attribute: true });
      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      expect(outcome.culpritIndex).toBeUndefined();
    } finally {
      await scanner.close();
    }
  });

  it('keeps scanning on a fresh thread after a deadline', async () => {
    // A thread killed on a deadline is replaceable, and the replacement must
    // answer for itself. The trap is that the dead thread's 'exit' arrives
    // AFTER the parent has already started the next job, so a handler that is
    // not scoped to its own worker settles the WRONG job — the next scan comes
    // back "the scan worker exited before answering" while a perfectly healthy
    // thread is running it.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN, HOSTILE] },
      { budgetMs: 1_500, minAttributionMs: 50 },
    );
    try {
      expect((await scanner.scan(BATTERY_BLIND_TEXT)).status).toBe('timeout');

      const after = await scanner.scan('key AKIA0123456789ABCDEF here');
      expect(after.status).toBe('ok');
      if (after.status !== 'ok') return;
      expect(after.findings.map((f) => f.ruleId)).toEqual(['pulled/benign']);
    } finally {
      await scanner.close();
    }
  });
});

/**
 * Everything above asserts what the PARENT does when a deadline fires: the
 * outcome it returns, the rule it names, the thread it starts next. None of
 * that needs the worker to have actually stopped — replace `terminate()` in
 * `kill()` with a no-op and every one of those cases still passes, because a
 * rule that never returns reports nothing either way.
 *
 * `terminate()` is the whole reason a worker was the answer, though: it reaches
 * V8's execution terminator and interrupts a spinning regex, which nothing on
 * the calling thread can do. Without it the deadline is bookkeeping — the
 * caller is told the scan ended while a thread keeps burning a core on the
 * pattern that hung it.
 *
 * So these cases watch the thread instead of the answer. The fixture spins for
 * a fixed stretch and then reports completion through shared memory, and a
 * killed thread must show neither a heartbeat nor a completion after the fact.
 *
 * NOTHING HERE ASSERTS AN ELAPSED TIME. The two readings are exhaustive over a
 * thread that was not stopped: at any instant it is either still executing (the
 * heartbeat moves) or has finished (the completion count moves), so a runner
 * slow enough to blunt one signal sharpens the other. The wall-clock constants
 * are waits, and waiting longer only ever makes these cases safer.
 */
describe('the kill behind the deadline', () => {
  it(
    'lets the fixture finish when no deadline fires, so the counters mean something',
    async () => {
      // The control for both cases below. A `completed` count that can never
      // reach 1 asserts nothing when it reads 0 — a mistyped slot index, a
      // buffer that never crossed into the thread, or a fixture that answers
      // without spinning would all look exactly like a successful kill.
      const counters = spinCounters();
      const scanner = isolated(spinningWorkerData(counters.buffer), {
        // Far above the spin: this case is about the fixture, not the bound.
        budgetMs: SPIN_MS * 10,
        workerUrl: SPINNING_WORKER,
      });
      try {
        expect((await scanner.scan('anything')).status).toBe('ok');
        expect(counters.entered()).toBe(1);
        expect(counters.heartbeat()).toBeGreaterThan(0);
        expect(counters.completed()).toBe(1);
      } finally {
        await scanner.close();
      }
    },
    KILL_CASE_TIMEOUT_MS,
  );

  it(
    'stops the scan thread, so the work it was doing never finishes',
    async () => {
      const counters = spinCounters();
      const scanner = isolated(spinningWorkerData(counters.buffer), {
        budgetMs: KILL_BUDGET_MS,
        workerUrl: SPINNING_WORKER,
      });
      try {
        expect((await scanner.scan('anything')).status).toBe('timeout');
        // The thread reached the work — otherwise the readings below would be
        // about a job that never started.
        expect(counters.entered()).toBe(1);

        await wait(KILL_SETTLE_MS);
        const beat = counters.heartbeat();
        await wait(KILL_OBSERVE_MS);

        // It executed no further instruction…
        expect(counters.heartbeat()).toBe(beat);
        // …and so the work it was in the middle of never finished.
        expect(counters.completed()).toBe(0);
      } finally {
        await scanner.close();
      }
    },
    KILL_CASE_TIMEOUT_MS,
  );

  it(
    'lets the pre-flight finish a measurement it did not have to kill',
    async () => {
      // The pre-flight's own control, and the pair to the case below: same
      // driver, same fixture, same rule shape — only the budget differs. A
      // measurement that comes back keeps the rule and completes the spin.
      const counters = spinCounters();
      const scanner = isolated(spinningWorkerData(counters.buffer), {
        probeBudgetMs: SPIN_MS * 10,
        workerUrl: SPINNING_WORKER,
      });
      const rule = regexRule('pulled/measurable', 'AAAA[0-9]{4}');
      try {
        const kept = await filterUnsafeRules([rule], fakeProbeCache(), {
          prober: scanner,
          passBudgetMs: PRE_FLIGHT_PASS_MS,
        });
        expect(kept).toEqual([rule]);
        expect(counters.completed()).toBe(1);
      } finally {
        await scanner.close();
      }
    },
    KILL_CASE_TIMEOUT_MS,
  );

  it(
    'stops every thread the pre-flight kills, not just the last one',
    async () => {
      // The scan path retires isolation after its first failure, so it can leak
      // at most one thread per scanner. The pre-flight cannot: it warns and
      // KEEPS ITERATING, so a pack whose rules each hang the battery gets a
      // thread apiece, all of them inside one pass. That is the path where a
      // missing kill costs more than one core, and it is reached before any
      // scan runs.
      const counters = spinCounters();
      const scanner = isolated(spinningWorkerData(counters.buffer), {
        probeBudgetMs: KILL_BUDGET_MS,
        workerUrl: SPINNING_WORKER,
      });
      const rules = [
        regexRule('pulled/one', 'AAAA[0-9]{4}'),
        regexRule('pulled/two', 'BBBB[0-9]{4}'),
        regexRule('pulled/three', 'CCCC[0-9]{4}'),
      ];
      try {
        const kept = await filterUnsafeRules(rules, fakeProbeCache(), {
          prober: scanner,
          passBudgetMs: PRE_FLIGHT_PASS_MS,
        });

        // Every rule was measured and every measurement had to be killed…
        expect(kept).toEqual([]);
        // …on a thread of its own, which is what makes this more than a repeat
        // of the scan case: the count is what the pack decides, not what the
        // scanner allows.
        expect(counters.entered()).toBe(rules.length);

        await wait(KILL_SETTLE_MS);
        const beat = counters.heartbeat();
        await wait(KILL_OBSERVE_MS);

        expect(counters.heartbeat()).toBe(beat);
        // Zero across all three, not "the last one stopped": a thread killed
        // early in the pass has the rest of the pass to finish its spin in.
        expect(counters.completed()).toBe(0);
      } finally {
        await scanner.close();
      }
    },
    KILL_CASE_TIMEOUT_MS,
  );
});

describe('createIsolatedScanner failure reporting', () => {
  it('reports a worker that dies before answering as a crash, not a timeout', async () => {
    const scanner = isolated(
      { verified: [], unverified: [BENIGN] },
      { budgetMs: 10_000, workerUrl: CRASHING_WORKER },
    );
    try {
      const started = performance.now();
      const outcome = await scanner.scan('anything');
      const elapsedMs = performance.now() - started;

      expect(outcome.status).toBe('unavailable');
      if (outcome.status !== 'unavailable') return;
      expect(outcome.reason).toContain('crashed');
      expect(outcome.reason).toContain('scan worker failed to load');
      // The whole point: the answer arrives when the worker dies, not when the
      // budget runs out. A parent that could not receive the worker's 'error'
      // event would sit here for the full 10s and then call it a timeout.
      expect(elapsedMs).toBeLessThan(5_000);
    } finally {
      await scanner.close();
    }
  });

  it('reports a worker that never starts as a slow start, not as a hung rule', async () => {
    // Startup has its own grace period, separate from the job's deadline. If
    // the two were one budget a cold machine would look exactly like a
    // catastrophic rule — and that misreading gets a legitimate rule
    // quarantined forever, which nothing undoes on its own.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN] },
      { budgetMs: 60_000, startBudgetMs: 400, workerUrl: NEVER_READY_WORKER },
    );
    try {
      const outcome = await scanner.scan('anything');
      expect(outcome.status).toBe('unavailable');
      if (outcome.status !== 'unavailable') return;
      expect(outcome.reason).toContain('did not start');
    } finally {
      await scanner.close();
    }
  });

  it('does not charge worker startup to the job budget', async () => {
    // A budget far below a cold start: the job still succeeds, because the
    // deadline does not begin until the worker says it can take work.
    const scanner = isolated(
      { verified: [BENIGN], unverified: [] },
      { budgetMs: 250, startBudgetMs: 20_000 },
    );
    try {
      const outcome = await scanner.scan('key AKIA0123456789ABCDEF here');
      expect(outcome.status).toBe('ok');
    } finally {
      await scanner.close();
    }
  });

  it('does not respawn a worker that already died on its own', async () => {
    const scanner = isolated(
      { verified: [], unverified: [BENIGN] },
      { budgetMs: 10_000, workerUrl: CRASHING_WORKER },
    );
    try {
      await scanner.scan('first');
      const started = performance.now();
      const outcome = await scanner.scan('second');
      // Same verdict, without paying to start a thread that dies the same way.
      expect(outcome.status).toBe('unavailable');
      expect(performance.now() - started).toBeLessThan(1_000);
    } finally {
      await scanner.close();
    }
  });

  it('does not respawn a worker that exited on its own', async () => {
    // The quiet sibling of the crash case: this thread emits no 'error' at all,
    // only an 'exit'. Without latching that, the pre-flight — which warns and
    // CONTINUES on an unavailable prober — respawns a thread per rule and burns
    // its whole 2s pass budget inside a pass that was already doomed.
    const scanner = isolated(
      { verified: [], unverified: [BENIGN] },
      { budgetMs: 10_000, workerUrl: EXITING_WORKER },
    );
    try {
      const first = await scanner.scan('first');
      expect(first.status).toBe('unavailable');

      const second = await scanner.scan('second');
      expect(second.status).toBe('unavailable');
      if (second.status !== 'unavailable') return;
      // The latched wording, not a fresh 'exited before answering': that is the
      // difference between remembering and rebuilding the thread.
      expect(second.reason).toContain('crashed');
      expect(second.reason).toContain('exited before answering');
    } finally {
      await scanner.close();
    }
  });

  it('reports a missing worker script rather than scanning unbounded', async () => {
    const scanner = isolated(
      { verified: [], unverified: [BENIGN] },
      { workerUrl: new URL('file:///aka-no-such-dir/scan-worker.js') },
    );
    try {
      const outcome = await scanner.scan('anything');
      expect(outcome.status).toBe('unavailable');
    } finally {
      await scanner.close();
    }
  });

  it('answers nothing once closed', async () => {
    const scanner = isolated({ verified: [BENIGN], unverified: [] });
    await scanner.close();
    const outcome = await scanner.scan('anything');
    expect(outcome.status).toBe('unavailable');
    expect((await scanner.probe(BENIGN)).status).toBe('unavailable');
  });
});
