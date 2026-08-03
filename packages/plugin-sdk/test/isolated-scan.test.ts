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
 *   - one the battery CLEARS without ever reaching its nested quantifier, and
 *     that then never returns on text the battery has no way to construct,
 *     which is what the isolated `scan` exists for;
 *   - one that hangs the BATTERY ITSELF, which is what the isolated `probe`
 *     exists for. Measuring a rule means driving its own pattern into
 *     backtracking, so the measurement is an unbounded run of an untrusted
 *     pattern too — and it runs first, before any scan.
 */
import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createIsolatedScanner } from '../src/isolated-scan.ts';

// The battery derives its probes from a pattern's own literal prefix and
// character classes. `literalPrefix` stops at the first `(`, so this pattern
// reports no prefix at all, and every probe — derived and fixed alike — fails
// at the `zzq` literal before it ever reaches the nested quantifier. The rule
// measures as safe and is admitted to the ruleset. Text that does carry the
// literal then drives `(a+)+$` into exponential backtracking.
const BATTERY_BLIND_LITERAL = 'zzq';
const BATTERY_BLIND_PATTERN = String.raw`(?:${BATTERY_BLIND_LITERAL})(a+)+$`;
const BATTERY_BLIND_TEXT = `${BATTERY_BLIND_LITERAL}${'a'.repeat(34)}!`;

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

describe('the residual risk the probe battery leaves open', () => {
  it('clears the timing pre-flight and still never returns on the right text', () => {
    // If this ever starts reporting unsafe, the battery grew a probe that
    // catches this shape — good news, and this whole suite would then be
    // testing a rule that never reaches the runtime. Change the pattern rather
    // than deleting the case: the gap is in the approach, not in one pattern.
    const verdict = checkRuleTiming(HOSTILE);
    expect(verdict.safe).toBe(true);

    // WHY it clears, stated structurally rather than as a millisecond ceiling.
    // The battery's slowest probe never carries the literal this pattern
    // requires, so the nested quantifier behind that literal is unreachable and
    // nothing backtracks. Move the literal out of the group so `literalPrefix`
    // can see it and both assertions flip together — the derived probes carry
    // it, the battery spends hundreds of milliseconds, and the rule reports
    // unsafe.
    //
    // A ceiling asserts the same property by proxy and measures the runner
    // instead. The whole battery costs hundredths of a millisecond for this
    // rule — V8 locates the required literal by substring search before running
    // the regex, so even the 40KB polynomial probes are nearly free — which
    // leaves a scheduler pause on a loaded machine orders of magnitude above the
    // signal being measured. A ratio against a second rule's battery is no
    // better here, because both numbers are that small.
    //
    // The length check is the positive control: `worstProbeMs` leaves `probe`
    // empty if no probe ever measures above zero, and an empty string satisfies
    // the absence check vacuously.
    expect(verdict.probe.length).toBeGreaterThan(0);
    expect(verdict.probe).not.toContain(BATTERY_BLIND_LITERAL);
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
