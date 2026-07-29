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

const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);
const NEVER_READY_WORKER = new URL('./helpers/never-ready-scan-worker.ts', import.meta.url);

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
    const scanner = createIsolatedScanner({ verified: [], unverified: [] });
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
    const scanner = createIsolatedScanner({ verified: [], unverified: [] });
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
    const scanner = createIsolatedScanner(
      { verified: [], unverified: [] },
      { probeBudgetMs: 1_500 },
    );
    try {
      const started = performance.now();
      const outcome = await scanner.probe(BATTERY_KILLER);
      const elapsedMs = performance.now() - started;

      expect(outcome.status).toBe('timeout');
      // A loose ceiling: the assertion is "the measurement ended", not "it
      // ended in exactly N ms".
      expect(elapsedMs).toBeLessThan(1_500 * 4);
    } finally {
      await scanner.close();
    }
  });

  it('keeps measuring after a terminated probe', async () => {
    // A hostile rule in the middle of a pack must not deny the rest of the pack
    // its verdict — the thread it killed is replaceable.
    const scanner = createIsolatedScanner(
      { verified: [], unverified: [] },
      { probeBudgetMs: 1_000 },
    );
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
    const scanner = createIsolatedScanner({ verified: [BENIGN], unverified: [] });
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
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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
      expect(elapsedMs).toBeLessThan(BUDGET_MS * 3);
    } finally {
      await scanner.close();
    }
  });

  it('blames nobody when the hang is not inside a single unverified rule', async () => {
    // The hostile rule is verified here, so it is only ever run as part of the
    // combined pass — the stage the parent must not attribute to any one rule.
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner(
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

  it('reports a missing worker script rather than scanning unbounded', async () => {
    const scanner = createIsolatedScanner(
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
    const scanner = createIsolatedScanner({ verified: [BENIGN], unverified: [] });
    await scanner.close();
    const outcome = await scanner.scan('anything');
    expect(outcome.status).toBe('unavailable');
    expect((await scanner.probe(BENIGN)).status).toBe('unavailable');
  });
});
