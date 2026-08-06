import type { checkRuleTiming as CheckRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { filterUnsafeRules, ruleProbeKey } from '../src/rule-quarantine.ts';

// Wrap the real `checkRuleTiming` in a spy so most tests exercise the actual
// probe battery unchanged, while the measurement-error test below can force
// a single call to throw via `mockImplementationOnce` (which reverts to this
// real implementation for every subsequent call).
vi.mock('@akasecurity/detections', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, checkRuleTiming: vi.fn(actual.checkRuleTiming as typeof CheckRuleTiming) };
});

const { checkRuleTiming } = await import('@akasecurity/detections');
const checkRuleTimingMock = vi.mocked(checkRuleTiming);

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

function keywordRule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['x'], caseSensitive: false },
  };
}

function fakeCacheGateway() {
  const store = new Map<string, { verdict: 'safe' | 'quarantined'; worstProbeMs: number }>();
  const getRuleProbeVerdict = vi.fn((key: string) => Promise.resolve(store.get(key)));
  const setRuleProbeVerdict = vi.fn(
    (key: string, verdict: 'safe' | 'quarantined', worstProbeMs: number) => {
      store.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
  );
  return { getRuleProbeVerdict, setRuleProbeVerdict, store };
}

let restoreStderr: (() => void) | undefined;

/** Every line the pre-flight wrote, joined — so `toContain` is a substring test. */
function captureStderr(): { lines: () => string; writes: () => number } {
  const written: string[] = [];
  const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  restoreStderr = () => {
    spy.mockRestore();
  };
  return { lines: () => written.join(''), writes: () => written.length };
}

afterEach(() => {
  // Restores ONLY this spy. `vi.restoreAllMocks()` would also reach the
  // module-level `checkRuleTiming` wrapper above and strip its implementation,
  // which every case that measures a rule for real depends on.
  restoreStderr?.();
  restoreStderr = undefined;
});

describe('filterUnsafeRules', () => {
  it('passes a benign regex rule through and caches it as safe', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/benign', 'AKIA[A-Z0-9]{16}');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('excludes a catastrophic regex rule and caches it as quarantined', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('passes non-regex rules through unchecked', async () => {
    const gateway = fakeCacheGateway();
    const rule = keywordRule('pack/keyword');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.getRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('reuses a cached verdict instead of re-measuring', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');
    const key = ruleProbeKey(rule);
    if (key === undefined) throw new Error('expected a rule key for a regex rule');
    gateway.store.set(key, { verdict: 'quarantined', worstProbeMs: 150 });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('reuses a cached safe verdict instead of re-measuring', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/cached-safe', 'AKIA[A-Z0-9]{16}');
    const key = ruleProbeKey(rule);
    if (key === undefined) throw new Error('expected a rule key for a regex rule');
    gateway.store.set(key, { verdict: 'safe', worstProbeMs: 75 });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('excludes remaining unchecked rules once the pass budget is exhausted, without caching a verdict for them', async () => {
    const gateway = fakeCacheGateway();
    const ruleA = regexRule('pack/a', 'AKIA[A-Z0-9]{16}');
    const ruleB = regexRule('pack/b', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([ruleA, ruleB], gateway, { passBudgetMs: -1 });

    expect(result).toEqual([]);
    // Neither rule was ever actually measured (the budget was exhausted
    // before reaching either), so no verdict should be persisted for
    // either — persisting 'quarantined' here would permanently and
    // silently exclude a rule that might be perfectly safe.
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
    expect(gateway.store.size).toBe(0);
  });

  it('treats a cache-read failure as a cache miss and still measures the rule', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/benign-read-error', 'AKIA[A-Z0-9]{16}');
    gateway.getRuleProbeVerdict.mockImplementationOnce(() =>
      Promise.reject(new Error('transient store read error')),
    );

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('quarantines a rule whose timing measurement itself throws, and persists the verdict', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/measurement-blows-up', 'AKIA[A-Z0-9]{16}');
    checkRuleTimingMock.mockImplementationOnce(() => {
      throw new Error('probe battery exploded');
    });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('keeps the rule when the store refuses the verdict, and does not lose the pass', async () => {
    // The verdict is a cache, not a decision: the decision for THIS pass is
    // already in hand. A store that will not take the write costs one
    // re-measurement next process and nothing else — it must never abort the
    // pass and take the rest of the pack down with it.
    const gateway = fakeCacheGateway();
    gateway.setRuleProbeVerdict.mockImplementationOnce(() =>
      Promise.reject(new Error('SQLITE_READONLY')),
    );
    const first = regexRule('pack/write-fails', 'AKIA[A-Z0-9]{16}');
    const second = regexRule('pack/after', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([first, second], gateway);

    expect(result).toEqual([first, second]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(2);
  });
});

// The battery decides whether a pattern is safe by driving it into
// backtracking, so measuring a rule is a way to hang on it. When the caller
// supplies somewhere killable to run the measurement, the filter must use it —
// and must treat "could not measure" and "measured, and it never returned" as
// the opposite verdicts they are.
describe('filterUnsafeRules with a prober', () => {
  const rule = regexRule('pulled/needs-measuring', 'AKIA[A-Z0-9]{16}');

  // The spy is module-scoped, so its call log carries over from the suite
  // above. These cases assert it was NOT called, which is vacuously false
  // without this.
  beforeEach(() => {
    checkRuleTimingMock.mockClear();
  });

  it('takes the prober verdict instead of measuring on this thread', async () => {
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() => Promise.resolve({ status: 'ok' as const, safe: true, worstMs: 1.5 }));

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([rule]);
    expect(probe).toHaveBeenCalledWith(rule);
    // The unbounded in-process call is exactly what the prober replaces.
    expect(checkRuleTimingMock).not.toHaveBeenCalled();
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('persists a quarantine when the measurement had to be terminated', async () => {
    // Stronger evidence than an over-budget probe, not weaker: the pattern did
    // not merely run long, it never came back. Caching it is what stops the
    // next process paying the same deadline to learn the same thing.
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() =>
      Promise.resolve({ status: 'timeout' as const, culpritIndex: undefined, elapsedMs: 1_000 }),
    );

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('excludes without persisting when there is nowhere safe to measure', async () => {
    // No worker means no measurement. Falling back to this thread would restore
    // the unbounded call, and caching a verdict would condemn a rule that was
    // never actually timed — so the rule sits out this pass and is measured
    // again next process.
    const gateway = fakeCacheGateway();
    const probe = vi.fn(() =>
      Promise.resolve({ status: 'unavailable' as const, reason: 'no worker script' }),
    );

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([]);
    expect(checkRuleTimingMock).not.toHaveBeenCalled();
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('never reaches the prober for a rule whose verdict is already cached', async () => {
    // The steady state on any machine that has loaded its packs once. A worker
    // started here would be a thread per hook invocation, for nothing.
    const gateway = fakeCacheGateway();
    const key = ruleProbeKey(rule);
    gateway.store.set(key ?? '', { verdict: 'safe', worstProbeMs: 1 });
    const probe = vi.fn(() => Promise.resolve({ status: 'ok' as const, safe: true, worstMs: 0 }));

    const result = await filterUnsafeRules([rule], gateway, { prober: { probe } });

    expect(result).toEqual([rule]);
    expect(probe).not.toHaveBeenCalled();
  });
});

// A rule can leave the pre-flight for three reasons, and they are NOT
// interchangeable: one is a fact about the rule, one is a fact about this pass,
// and one is a fact about the install. Reporting them alike tells a user to fix
// a ruleset that is fine — and in the third case the ruleset is not the problem
// at all: with no reachable worker, EVERY pulled/custom regex rule on the
// machine is excluded from every scan until the install is repaired.
//
// Nothing below asserts on behaviour the other suites already pin; what these
// cases hold is the one thing no other test in this file reads, which is why
// the three collapsed into one line unnoticed: the stderr text.
describe('what the pre-flight says on stderr', () => {
  const rule = regexRule('pulled/needs-measuring', 'AKIA[A-Z0-9]{16}');

  const overBudget = { status: 'ok' as const, safe: false, worstMs: 812.5 };
  const noWorker = {
    status: 'unavailable' as const,
    reason: 'the scan worker script was not found next to this bundle',
  };

  function proberOf(outcome: { status: 'ok'; safe: boolean; worstMs: number } | typeof noWorker) {
    return { probe: vi.fn(() => Promise.resolve(outcome)) };
  }

  beforeEach(() => {
    checkRuleTimingMock.mockClear();
  });

  describe('case 1 — the rule was measured and failed', () => {
    it('quotes the reading, names the timing budget, and points at the way back', async () => {
      const stderr = captureStderr();

      await filterUnsafeRules([rule], fakeCacheGateway(), { prober: proberOf(overBudget) });

      const line = stderr.lines();
      expect(line).toContain('quarantined rule "pulled/needs-measuring"');
      expect(line).toContain('exceeded the ReDoS timing budget (812.5ms)');
      // The verdict is cached forever and this line is the only place the
      // machine ever mentions it, so this is the one case that has somewhere to
      // send anyone — and the only one allowed to say so.
      expect(line).toContain('aka detections unquarantine');
    });

    it('quotes no duration when the battery itself failed rather than returning one', async () => {
      // The in-process fallback records a failed measurement as
      // POSITIVE_INFINITY. It is still a real attempt, so it is still
      // quarantined and still persisted — but a naive format prints
      // "Infinityms", which reads as a measurement rather than the absence of
      // one, and invites a reader to compare it against a budget.
      const gateway = fakeCacheGateway();
      const stderr = captureStderr();
      checkRuleTimingMock.mockImplementationOnce(() => {
        throw new Error('battery blew up');
      });

      const result = await filterUnsafeRules([rule], gateway);

      expect(result).toEqual([]);
      expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
      expect(stderr.lines()).toContain('the timing battery failed while measuring');
      expect(stderr.lines()).not.toContain('Infinity');
    });
  });

  describe('case 2 — the pass budget ran out before this rule was reached', () => {
    it('says the pre-flight ran out of time, and does not blame the rule', async () => {
      const gateway = fakeCacheGateway();
      const stderr = captureStderr();

      await filterUnsafeRules([rule], gateway, {
        passBudgetMs: -1,
        prober: proberOf(overBudget),
      });

      const line = stderr.lines();
      // The positive control: without it every absence below is satisfied by an
      // empty stderr, which is exactly the wrong reading of "says nothing bad".
      expect(line).toContain('the timing pre-flight ran out of time');
      expect(line).toContain('measured again next time');
      expect(line).not.toContain('ReDoS timing budget');
      // Nothing was measured, so nothing was cached and nothing is quarantined —
      // "unquarantine" would send the user to a list this rule is not on.
      expect(line).not.toContain('quarantined');
      expect(line).not.toContain('aka detections unquarantine');
      expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
    });
  });

  describe('case 3 — there was nowhere to measure anything', () => {
    it('names the worker instead of the rule, and does not claim a timing failure', async () => {
      const gateway = fakeCacheGateway();
      const stderr = captureStderr();

      const result = await filterUnsafeRules([rule], gateway, { prober: proberOf(noWorker) });

      const line = stderr.lines();
      // The accurate diagnosis exists one frame away, in the prober's own
      // reason. This is the assertion that it reaches the user.
      expect(line).toContain('the scan worker script was not found next to this bundle');
      expect(line).toContain('reinstalling AKA brings them straight back');
      // The span is part of the diagnosis, not decoration. The pre-flight runs
      // once per process and a hook scans many fields in it, so any claim of
      // "this scan" would understate a whole-category gap as momentary.
      expect(line).toContain('excluded from every scan on this machine');
      expect(line).not.toContain('ReDoS timing budget');
      // Not attributed to the rule, in either spelling: the id itself, and the
      // verb that would make it the rule's fault.
      expect(line).not.toContain('pulled/needs-measuring');
      expect(line).not.toContain('quarantined rule');
      expect(line).not.toContain('aka detections unquarantine');

      // AC3 — the safety behaviour this message describes is unchanged. Pinned
      // beside the wording so a future edit cannot make the line honest by
      // making the behaviour worse.
      expect(result).toEqual([]);
      expect(checkRuleTimingMock).not.toHaveBeenCalled();
      expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
    });

    it('reports the install once for the pass, not once per rule', async () => {
      // The failure is one fact about the machine. A pulled pack is routinely
      // dozens of rules, and a line apiece both buries the diagnosis and reads
      // as dozens of separate rule problems.
      const rules = [
        regexRule('pulled/one', 'AKIA[A-Z0-9]{16}'),
        regexRule('pulled/two', 'ASIA[A-Z0-9]{16}'),
        regexRule('pulled/three', 'AROA[A-Z0-9]{16}'),
      ];
      const stderr = captureStderr();

      await filterUnsafeRules(rules, fakeCacheGateway(), { prober: proberOf(noWorker) });

      expect(stderr.writes()).toBe(1);
      expect(stderr.lines()).toContain('3 pulled/custom-pack rule(s) could not be time-checked');
    });

    it('still reports the install when the pass is abandoned part-way', async () => {
      // The line is buffered to the end of the pass, so it now depends on the
      // pass finishing. Every other failure in the loop is caught, but the
      // prober is awaited unguarded — and losing the one accurate account of a
      // broken install to an unrelated throw is the silence this reporting
      // exists to break.
      const rules = [
        regexRule('pulled/one', 'AKIA[A-Z0-9]{16}'),
        regexRule('pulled/two', 'ASIA[A-Z0-9]{16}'),
      ];
      let call = 0;
      const probe = vi.fn(() =>
        call++ === 0
          ? Promise.resolve({ status: 'unavailable' as const, reason: 'no worker script' })
          : Promise.reject(new Error('prober blew up')),
      );
      const stderr = captureStderr();

      const error = await filterUnsafeRules(rules, fakeCacheGateway(), { prober: { probe } }).then(
        () => undefined,
        (e: unknown) => e as Error,
      );

      // The throw still propagates — this buys the diagnosis, not a swallowed
      // error, and a pass that silently returned a short ruleset would be worse
      // than one that failed.
      expect(error?.message).toBe('prober blew up');
      expect(stderr.lines()).toContain('1 pulled/custom-pack rule(s) could not be time-checked');
    });

    it('keeps two different faults apart rather than merging them into one count', async () => {
      // A pass normally sees one reason, because the scanner latches a dead
      // worker. Two reasons are two faults, and a merged count names neither.
      const rules = [
        regexRule('pulled/one', 'AKIA[A-Z0-9]{16}'),
        regexRule('pulled/two', 'ASIA[A-Z0-9]{16}'),
      ];
      const reasons = ['the scan worker script was not found next to this bundle', 'it crashed'];
      let call = 0;
      const probe = vi.fn(() =>
        Promise.resolve({ status: 'unavailable' as const, reason: reasons[call++] ?? '' }),
      );
      const stderr = captureStderr();

      await filterUnsafeRules(rules, fakeCacheGateway(), { prober: { probe } });

      expect(stderr.writes()).toBe(2);
      expect(stderr.lines()).toContain(
        '1 pulled/custom-pack rule(s) could not be time-checked: the scan worker script was not found',
      );
      expect(stderr.lines()).toContain(
        '1 pulled/custom-pack rule(s) could not be time-checked: it crashed',
      );
    });
  });

  it('says something different for each of the three, and something for all of them', async () => {
    // The defect this suite exists for was not a wrong sentence but an
    // INDISTINGUISHABLE one: cases 2 and 3 were byte-identical, so a user
    // reading either was told to fix a rule. Asserting the wordings pairwise is
    // the only form that goes red on a future collapse whatever the new wording
    // turns out to be.
    const said: string[] = [];
    for (const opts of [
      { prober: proberOf(overBudget) },
      { prober: proberOf(overBudget), passBudgetMs: -1 },
      { prober: proberOf(noWorker) },
    ]) {
      const stderr = captureStderr();
      await filterUnsafeRules([rule], fakeCacheGateway(), opts);
      said.push(stderr.lines());
      restoreStderr?.();
    }

    // Silence is not distinctness: two cases that both said nothing would be
    // equal, but one that said nothing while the others spoke would not.
    for (const line of said) expect(line).not.toBe('');
    expect(new Set(said).size).toBe(said.length);
  });
});
