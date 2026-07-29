/**
 * The hard bound under the timing pre-flight.
 *
 * `rule-quarantine.ts` measures a rule against a fixed adversarial battery and
 * caches the verdict. That gate is empirical: it proves a pattern did not
 * backtrack on the inputs the battery constructs, not that it cannot. This
 * suite is built around a pattern that demonstrates the difference — it clears
 * the battery in microseconds and then never returns on text the battery has no
 * way to construct — and asserts the property the battery cannot give: whatever
 * the pattern, the scan ends.
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

// Long enough that worker startup is never what the deadline measures — the
// cases below warm the worker with a real scan first, and this has to cover a
// cold start on the Windows runner with room to spare. Short enough that a
// couple of deliberate hangs do not dominate the run.
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
const BENIGN = regexRule('pulled/benign', 'AKIA[A-Z0-9]{16}');

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

describe('createIsolatedScanner', () => {
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
      const outcome = await scanner.scan(BATTERY_BLIND_TEXT);
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

      const outcome = await scanner.scan(BATTERY_BLIND_TEXT);
      expect(outcome.status).toBe('timeout');
      if (outcome.status !== 'timeout') return;
      expect(outcome.culpritIndex).toBeUndefined();
    } finally {
      await scanner.close();
    }
  });

  it('reports a worker that dies before answering as a crash, not a timeout', async () => {
    const scanner = createIsolatedScanner(
      { verified: [], unverified: [BENIGN] },
      {
        budgetMs: 10_000,
        workerUrl: new URL('./helpers/crashing-scan-worker.ts', import.meta.url),
      },
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

  it('does not respawn a worker that already died on its own', async () => {
    const scanner = createIsolatedScanner(
      { verified: [], unverified: [BENIGN] },
      {
        budgetMs: 10_000,
        workerUrl: new URL('./helpers/crashing-scan-worker.ts', import.meta.url),
      },
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
  });
});
