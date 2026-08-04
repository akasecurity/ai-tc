/**
 * The policy on top of the hard bound: who gets isolated, what a hang costs,
 * and what still runs afterwards.
 *
 * The properties worth breaking a build over:
 *   - a machine with no pulled or custom pack pays nothing at all;
 *   - an ordinary scan pays no attribution pass — that cost belongs to the
 *     retry of a scan that already timed out, never to the scans that work;
 *   - a hang is charged once per process, never once per scanned field;
 *   - a scan that loses its worker keeps the built-in packs and drops the
 *     unverified rules, rather than quietly running them unbounded;
 *   - a store that will not take the quarantine verdict costs the caller
 *     nothing on top of the hang it already absorbed.
 */
import type { Rule } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createGuardedScanner } from '../src/guarded-scan.ts';
import { ruleProbeKey } from '../src/rule-quarantine.ts';

const BATTERY_BLIND_PATTERN = String.raw`(?:zzq)(a+)+$`;
const BATTERY_BLIND_TEXT = `zzq${'a'.repeat(34)}!`;
const BUDGET_MS = 1_500;

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

// Points the isolated scanner at a worker that dies at load, so a case can
// exercise the degraded path without waiting out a deadline.
const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);

function regexRule(id: string, pattern: string, over: Partial<Rule> = {}): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
    ...over,
  };
}

const AWS_KEY = 'AKIA0123456789ABCDEF';
const VERIFIED_SECRET = regexRule('secrets/aws-key', 'AKIA[A-Z0-9]{16}', { category: 'secret' });
const HOSTILE = regexRule('pulled/battery-blind', BATTERY_BLIND_PATTERN);

function fakeGateway() {
  const setRuleProbeVerdict = vi.fn(() => Promise.resolve());
  return { setRuleProbeVerdict };
}

// A store that refuses the write. The quarantine runs on a recovery path, so a
// failure here must cost the caller nothing beyond the verdict itself.
function refusingGateway() {
  const setRuleProbeVerdict = vi.fn(() => Promise.reject(new Error('SQLITE_READONLY')));
  return { setRuleProbeVerdict };
}

function captureStderr(): { lines: () => string } {
  const written: string[] = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  return { lines: () => written.join('') };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('createGuardedScanner', () => {
  it('never starts a worker when every rule is verified', async () => {
    // The worker URL points at a module that throws on load, so the only way
    // this scan can succeed is by never reaching a worker at all.
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [] },
      fakeGateway(),
      { workerUrl: CRASHING_WORKER, startBudgetMs: START_MS },
    );
    try {
      const findings = await scanner.scan(`key ${AWS_KEY} here`);
      expect(findings.map((f) => f.ruleId)).toEqual(['secrets/aws-key']);
      expect(scanner.degraded()).toBe(false);
    } finally {
      await scanner.close();
    }
  });

  it('reports no degradation after an ordinary close', async () => {
    // `degraded()` means "coverage was lost", not "the worker is gone". A
    // caller that stops writing scan-ledger rows on it must not be tripped by
    // the ordinary teardown every hook does.
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [regexRule('pulled/benign', 'TOKENX')] },
      fakeGateway(),
      { startBudgetMs: START_MS },
    );
    expect((await scanner.scan(`TOKENX and ${AWS_KEY}`)).map((f) => f.ruleId).sort()).toEqual([
      'pulled/benign',
      'secrets/aws-key',
    ]);
    await scanner.close();
    expect(scanner.degraded()).toBe(false);
  });

  it('keeps requiresNearby corroboration working across the verified/unverified split', async () => {
    // The gated rule only fires when a `secret` match sits within its window.
    // Its corroborator is a VERIFIED rule, so this passes only because both
    // halves reach the worker in ONE scan() call — split them and the finding
    // silently disappears.
    const gated = regexRule('pulled/gated', 'TOKENX', {
      requiresNearby: { categories: ['secret'], windowChars: 160 },
    });
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [gated] },
      fakeGateway(),
      { startBudgetMs: START_MS },
    );
    try {
      const near = await scanner.scan(`${AWS_KEY} and TOKENX`);
      expect(near.map((f) => f.ruleId).sort()).toEqual(['pulled/gated', 'secrets/aws-key']);

      // Same rules, no corroborator in the window: the gate still bites, so the
      // corroboration above is real and not an artifact of the rule always firing.
      const alone = await scanner.scan('TOKENX on its own');
      expect(alone).toEqual([]);
    } finally {
      await scanner.close();
    }
  });

  it('quarantines the rule it had to terminate and keeps the built-in packs running', async () => {
    const gateway = fakeGateway();
    const stderr = captureStderr();
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [HOSTILE] },
      gateway,
      {
        budgetMs: BUDGET_MS,
        minAttributionMs: 50,
        startBudgetMs: START_MS,
      },
    );
    try {
      // Warm the worker so the deadline below is spent on the rule, not on startup.
      expect(await scanner.scan('nothing here')).toEqual([]);

      const findings = await scanner.scan(`${BATTERY_BLIND_TEXT} ${AWS_KEY}`);

      // The verdict is persisted under the same key the timing pre-flight reads,
      // so the next process drops this rule before it ever reaches a scan.
      expect(gateway.setRuleProbeVerdict).toHaveBeenCalledWith(
        ruleProbeKey(HOSTILE),
        'quarantined',
        expect.any(Number),
      );
      // Terminating the scan does not cost the user the first-party detection
      // that was in the same text.
      expect(findings.map((f) => f.ruleId)).toEqual(['secrets/aws-key']);
      expect(scanner.degraded()).toBe(true);

      const output = stderr.lines();
      expect(output).toContain('quarantined rule "pulled/battery-blind"');
      expect(output).toContain('isolated scanning is off for the rest of this process');
      // The verdict is cached forever and this line is the only place the
      // machine ever mentions it, so it has to say how to undo it.
      expect(output).toContain('aka detections unquarantine');
    } finally {
      await scanner.close();
    }
  });

  it('survives a store that refuses the quarantine verdict', async () => {
    const gateway = refusingGateway();
    const stderr = captureStderr();
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [HOSTILE] },
      gateway,
      {
        budgetMs: BUDGET_MS,
        minAttributionMs: 50,
        startBudgetMs: START_MS,
      },
    );
    try {
      expect(await scanner.scan('nothing here')).toEqual([]);
      const findings = await scanner.scan(`${BATTERY_BLIND_TEXT} ${AWS_KEY}`);

      // The write failed, so the caller still gets its scan and the built-in
      // finding in the same text. A failed cache write must never cost more
      // than a re-measurement next process.
      expect(gateway.setRuleProbeVerdict).toHaveBeenCalled();
      expect(findings.map((f) => f.ruleId)).toEqual(['secrets/aws-key']);

      const output = stderr.lines();
      expect(output).toContain('quarantined rule "pulled/battery-blind"');
      // …and it must NOT offer to undo a verdict that was never recorded.
      expect(output).not.toContain('aka detections unquarantine');
    } finally {
      await scanner.close();
    }
  });

  it('charges a hang once per process, not once per scanned field', async () => {
    const gateway = fakeGateway();
    captureStderr();
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [HOSTILE] },
      gateway,
      {
        budgetMs: BUDGET_MS,
        minAttributionMs: 50,
        startBudgetMs: START_MS,
      },
    );
    try {
      expect(await scanner.scan('nothing here')).toEqual([]);
      await scanner.scan(BATTERY_BLIND_TEXT);

      // A PreToolUse hook can scan thousands of fields. If each one paid the
      // deadline again the hook would blow its harness timeout — and a
      // timed-out hook fails open, letting the whole call through unscanned.
      const started = performance.now();
      const findings = await scanner.scan(`${BATTERY_BLIND_TEXT} ${AWS_KEY}`);
      const elapsedMs = performance.now() - started;

      expect(elapsedMs).toBeLessThan(BUDGET_MS);
      expect(findings.map((f) => f.ruleId)).toEqual(['secrets/aws-key']);
    } finally {
      await scanner.close();
    }
  });

  it('drops the unverified rules rather than running them in-process when the worker is gone', async () => {
    const stderr = captureStderr();
    // A rule that WOULD match, so its absence from the findings is evidence it
    // was never run rather than evidence it found nothing.
    const unverified = regexRule('pulled/would-match', 'TOKENX');
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [unverified] },
      fakeGateway(),
      { workerUrl: CRASHING_WORKER, startBudgetMs: START_MS },
    );
    try {
      const findings = await scanner.scan(`TOKENX next to ${AWS_KEY}`);
      expect(findings.map((f) => f.ruleId)).toEqual(['secrets/aws-key']);
      expect(scanner.degraded()).toBe(true);
      expect(stderr.lines()).toContain('isolated scanning is off for the rest of this process');
      // Nothing was terminated, so nothing is blamed: a worker that will not
      // start is not evidence against any particular rule.
      expect(stderr.lines()).not.toContain('quarantined rule');
    } finally {
      await scanner.close();
    }
  });

  it('says how long a degradation really lasts when the caller is not a hook', async () => {
    const stderr = captureStderr();
    // A scanner built per unit of work rather than per process — what the
    // dashboard's folder scan does, because a long-running server must not lose
    // its pulled rules until someone restarts it. The default sentence would
    // claim exactly that, so the scope is the caller's to state.
    const scanner = createGuardedScanner(
      { verified: [VERIFIED_SECRET], unverified: [regexRule('pulled/would-match', 'TOKENX')] },
      fakeGateway(),
      {
        workerUrl: CRASHING_WORKER,
        startBudgetMs: START_MS,
        degradeScope: 'the rest of this scan',
      },
    );
    try {
      await scanner.scan(`TOKENX next to ${AWS_KEY}`);
      expect(stderr.lines()).toContain('isolated scanning is off for the rest of this scan');
      // The claim it replaced, so a scope that is silently ignored fails here
      // rather than reading as a passing test of a parameter nothing honours.
      expect(stderr.lines()).not.toContain('the rest of this process');
    } finally {
      await scanner.close();
    }
  });
});
