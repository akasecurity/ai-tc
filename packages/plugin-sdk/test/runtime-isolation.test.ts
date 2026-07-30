/**
 * The hard scan bound seen from the capture path — the level the product
 * actually runs at.
 *
 * Three things have to hold together here, and none of them is visible from the
 * scanner in isolation: a capture whose pulled rule never returns still returns
 * a decision rather than hanging the hook; the built-in packs keep detecting
 * through it; and the machine converges — the next process drops the offending
 * rule before it can cost a second budget.
 *
 * The last section measures what isolation costs when nothing is wrong, because
 * the reason this was not built alongside the timing pre-flight was an estimate
 * of a permanent per-call tax.
 */
import type { PolicyBundle, Rule, RuleProbeVerdict, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CaptureRecord, DataGateway, RuleProbeVerdictEntry } from '../src/data-gateway.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { ruleProbeKey } from '../src/rule-quarantine.ts';
import { createPluginRuntime } from '../src/runtime.ts';

// A bundled-pack rule, standing in for the compiled-in packs: it must keep
// detecting even in the capture whose pulled rule had to be terminated.
registerRulePack('isolation-test-pack', [
  {
    specVersion: 1,
    id: 'isolation/secret-marker',
    name: 'Isolation secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['SECRET_MARKER'] },
    examples: ['SECRET_MARKER'],
  },
]);

// Clears the runtime probe battery in microseconds (its probes all fail at the
// `zzq` literal) and then backtracks without end on text that carries it. See
// test/isolated-scan.test.ts, which pins both halves of that claim.
const HOSTILE: Rule = {
  specVersion: 1,
  id: 'pulled/battery-blind',
  name: 'Battery-blind pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(?:zzq)(a+)+$`, flags: 'g' },
};
const HOSTILE_TEXT = `zzq${'a'.repeat(34)}!`;

// The other shape, and the one the pre-flight cannot survive on its own:
// measuring a rule means driving its own pattern into backtracking, so a
// pattern that is catastrophic on the battery's OWN probe (`'a'.repeat(23)+'!'`,
// which is what the derivation builds for a pattern with no literal prefix)
// hangs the measurement itself — before any scan runs. See
// test/isolated-scan.test.ts, which pins that directly.
const BATTERY_KILLER: Rule = {
  specVersion: 1,
  id: 'pulled/battery-killer',
  name: 'Battery-killing pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(a|a|a|a)+$`, flags: 'g' },
};

// A pulled KEYWORD rule. Its matcher compiles one fully-escaped literal per
// keyword, so nothing its author writes can make it backtrack — it needs no
// worker, and a keyword-only custom pack must start none.
const PULLED_KEYWORD: Rule = {
  specVersion: 1,
  id: 'pulled/keyword',
  name: 'Pulled keyword rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'keyword', keywords: ['TOKENX'], caseSensitive: false },
};

const BUDGET_MS = 1_500;

// Points the isolated scanner at a module that throws on load, so a case that
// must not reach a worker fails loudly if it ever does.
const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };
}

function bundle(rules: Rule[] = []): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    rules,
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

interface FakeGateway extends DataGateway {
  records: CaptureRecord[];
  verdicts: Map<string, RuleProbeVerdictEntry>;
}

// The probe-verdict map is passed in rather than owned, so two runtimes can
// share one store the way two hook processes share ~/.aka/data/aka.db.
function fakeGateway(b: PolicyBundle, verdicts = new Map<string, RuleProbeVerdictEntry>()) {
  const records: CaptureRecord[] = [];
  const gateway: FakeGateway = {
    records,
    verdicts,
    recordCapture: (record) => {
      records.push(record);
      return Promise.resolve();
    },
    ensureInventory: () => Promise.resolve({}),
    recordAuditEvent: () => Promise.resolve(),
    recordLlmCall: () => Promise.resolve(),
    recordLlmCalls: () => Promise.resolve(),
    recordToolCalls: () => Promise.resolve(),
    recordConfigScan: () => Promise.resolve(),
    configInventoryReport: () =>
      Promise.resolve({
        scannedAt: null,
        skills: [],
        hooks: [],
        mcpServers: [],
        configFiles: [],
        topics: [],
      }),
    readSessionProvider: () => Promise.resolve(undefined),
    facets: () => Promise.resolve({ hosts: [], harnesses: [], osVersions: [], projects: [] }),
    getPolicyBundle: () => Promise.resolve(b),
    consumeException: () => Promise.resolve(false),
    recordBlockedDetection: () => Promise.resolve(),
    recentFindings: () => Promise.resolve([]),
    healthSummary: () =>
      Promise.resolve({
        findings: 0,
        byAction: {} as never,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        coverage: 0,
      }),
    activityByDay: () => Promise.resolve([]),
    tokenReports: () => Promise.resolve([]),
    knownContentHashes: () => Promise.resolve(new Set<string>()),
    scanLedger: () => Promise.resolve(new Map()),
    recordScanned: () => Promise.resolve(),
    getRuleProbeVerdict: (key: string) => Promise.resolve(verdicts.get(key)),
    setRuleProbeVerdict: (key: string, verdict: RuleProbeVerdict, worstProbeMs: number) => {
      verdicts.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    recordProjectEgress: () =>
      Promise.resolve({
        destinations: 0,
        endpoints: 0,
        callSites: 0,
        truncated: false,
        droppedFiles: [],
      }),
    close: () => Promise.resolve(),
  };
  return gateway;
}

/**
 * A pre-flight cache that already says "safe" for `rules`.
 *
 * Every case below whose premise is "the battery CLEARED this rule and the SCAN
 * is what has to catch it" needs this. Without it the rule must survive a live
 * measurement on the test runner first — and a slow or contended one can
 * quarantine it at the gate instead, on either the battery's own 100ms
 * per-probe budget or the prober's deadline. The scan bound then never runs,
 * and the case still passes on its other assertions because the BUILT-IN packs
 * did the detecting: a green test that exercised nothing it was written for.
 * (Seen for real on the Windows runner, where backtracking is 4-5x slower.)
 *
 * This is also the honest steady state: a real machine measures a rule once,
 * ever, and every scan after that reads the cached verdict.
 */
function clearedByPreflight(...rules: Rule[]): Map<string, RuleProbeVerdictEntry> {
  const verdicts = new Map<string, RuleProbeVerdictEntry>();
  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key !== undefined) verdicts.set(key, { verdict: 'safe', worstProbeMs: 0.1 });
  }
  return verdicts;
}

// The degraded path is loud by design; keep the suite's own output readable.
function silenceStderr(): void {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a pulled rule that never returns', () => {
  it('is terminated, and the capture still decides on the built-in packs', async () => {
    silenceStderr();
    const gw = fakeGateway(bundle([HOSTILE]), clearedByPreflight(HOSTILE));
    const rt = createPluginRuntime(gw, settings(), {
      scanIsolation: { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    });
    try {
      const text = `${HOSTILE_TEXT} and SECRET_MARKER`;
      const started = performance.now();
      const result = await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
      const elapsedMs = performance.now() - started;

      // Fail-open in the sense that matters: the call returns. Left in-process
      // this text runs longer than the harness would ever wait, and a hook the
      // harness kills lets the whole tool call through unscanned. Worst case
      // here is TWO budgets — the scan, then the retry that names the rule —
      // and the ceiling is loose on top of that.
      expect(elapsedMs).toBeLessThan(BUDGET_MS * 10);
      // The bundled rule in the same text is untouched by the termination.
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
      expect(result.action).toBe('warn');
      // Anything keyed on the ruleset fingerprint has to stop writing now: the
      // fingerprint still names the pulled rule that is no longer running.
      expect(rt.scanIsolationDegraded()).toBe(true);
      // And the event was still persisted, with the finding masked as usual.
      expect(gw.records).toHaveLength(1);
      expect(gw.records[0]?.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await rt.close();
    }
  });

  it('is quarantined, so the next process never loads it again', async () => {
    silenceStderr();
    const verdicts = clearedByPreflight(HOSTILE);

    const first = createPluginRuntime(fakeGateway(bundle([HOSTILE]), verdicts), settings(), {
      scanIsolation: { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    });
    try {
      await first.processText(HOSTILE_TEXT);
    } finally {
      await first.close();
    }

    const key = ruleProbeKey(HOSTILE);
    expect(key).toBeDefined();
    expect(verdicts.get(key ?? '')?.verdict).toBe('quarantined');

    // A fresh runtime over the same store: filterUnsafeRules reads the cached
    // verdict and drops the rule before it can reach a scan, so this costs no
    // budget at all rather than another termination.
    const second = createPluginRuntime(fakeGateway(bundle([HOSTILE]), verdicts), settings(), {
      scanIsolation: { budgetMs: BUDGET_MS, minAttributionMs: 50 },
    });
    try {
      const started = performance.now();
      const result = await second.processText(`${HOSTILE_TEXT} and SECRET_MARKER`);
      expect(performance.now() - started).toBeLessThan(BUDGET_MS);
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await second.close();
    }
  });
});

describe('a pulled rule that hangs the timing battery itself', () => {
  it('is terminated during the pre-flight, and the capture still decides', async () => {
    // The gate that decides whether a pulled rule is safe works by running the
    // rule. Measured on this thread it never returns, the hook is killed by the
    // harness at 10s, and a killed hook fails open — the whole tool call goes
    // through unscanned. That is the same bypass the scan bound exists for, one
    // call earlier, so the measurement runs where it can be killed too.
    silenceStderr();
    const verdicts = new Map<string, RuleProbeVerdictEntry>();
    const rt = createPluginRuntime(fakeGateway(bundle([BATTERY_KILLER]), verdicts), settings(), {
      scanIsolation: { probeBudgetMs: BUDGET_MS },
    });
    try {
      const started = performance.now();
      const result = await rt.processText('deploy with SECRET_MARKER now');
      expect(performance.now() - started).toBeLessThan(BUDGET_MS * 8);

      // A measurement that had to be terminated is the strongest unsafe verdict
      // there is, and it is cached, so the next process never loads the rule.
      const key = ruleProbeKey(BATTERY_KILLER);
      expect(key).toBeDefined();
      expect(verdicts.get(key ?? '')?.verdict).toBe('quarantined');
      // …and the built-in packs are untouched by any of it.
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await rt.close();
    }
  });
});

// The pointer shield's guarantee is "no rule ever sees a pointer, whatever rules
// are installed" — and a PULLED rule is both the case where that matters most
// (nobody audited it) and the only case where the scan leaves this thread. The
// shield runs before the scan, so the text that crosses into the worker is
// already blanked; these two cases are what keep that true.
describe('a pulled rule and a vault pointer', () => {
  // A generic high-entropy matcher, the shape that would happily match a
  // pointer's own base32 body and re-tokenize a pointer into a pointer.
  const GREEDY: Rule = {
    specVersion: 1,
    id: 'pulled/long-upper',
    name: 'Long uppercase run',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern: '[A-Z]{20,}', flags: 'g' },
  };
  const POINTER = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;

  it('fires on a bare match, so the absence below is the shield and not the rule', async () => {
    const rt = createPluginRuntime(
      fakeGateway(bundle([GREEDY]), clearedByPreflight(GREEDY)),
      settings(),
    );
    try {
      const result = await rt.processText(`token ${'A'.repeat(26)} here`);
      expect(result.findings.map((f) => f.ruleId)).toEqual(['pulled/long-upper']);
    } finally {
      await rt.close();
    }
  });

  it('never matches inside the pointer, even though the scan ran in the worker', async () => {
    const rt = createPluginRuntime(
      fakeGateway(bundle([GREEDY]), clearedByPreflight(GREEDY)),
      settings(),
    );
    try {
      const result = await rt.processText(`resubmit ${POINTER} please`);
      expect(result.findings).toEqual([]);
    } finally {
      await rt.close();
    }
  });
});

describe('what isolation costs when nothing is wrong', () => {
  it('costs nothing at all when the bundle carries no pulled regex rule', async () => {
    // No worker is startable here — the URL points at a module that throws on
    // load — so finishing at all proves the in-process path was taken. This is
    // the steady state of a machine that installed no extra pack.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings(), {
      scanIsolation: { workerUrl: CRASHING_WORKER },
    });
    try {
      const result = await rt.processText('deploy with SECRET_MARKER now');
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
      expect(rt.scanIsolationDegraded()).toBe(false);
    } finally {
      await rt.close();
    }
  });

  it('starts no worker for a keyword-only custom pack', async () => {
    // A keyword matcher compiles one fully-escaped literal per keyword, so no
    // pack author can make it catastrophic and it needs no bound. The crashing
    // worker URL is the proof: this can only pass by never starting a thread,
    // for the gate or for the scan.
    const rt = createPluginRuntime(fakeGateway(bundle([PULLED_KEYWORD])), settings(), {
      scanIsolation: { workerUrl: CRASHING_WORKER },
    });
    try {
      const result = await rt.processText('TOKENX beside SECRET_MARKER');
      // Both fire, so the pulled rule really is in the effective ruleset rather
      // than having been dropped along with the worker.
      expect(result.findings.map((f) => f.ruleId).sort()).toEqual([
        'isolation/secret-marker',
        'pulled/keyword',
      ]);
      expect(rt.scanIsolationDegraded()).toBe(false);
    } finally {
      await rt.close();
    }
  });

  it('costs the cold starts once, then a round trip per scan', async () => {
    const benign: Rule = {
      specVersion: 1,
      id: 'pulled/benign',
      name: 'Benign pulled rule',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'AKIA[A-Z0-9]{16}', flags: 'g' },
    };
    const rt = createPluginRuntime(fakeGateway(bundle([benign])), settings());
    try {
      const text = 'lorem ipsum dolor sit amet '.repeat(80); // ~2KB, a typical prompt

      // The worst case by construction: this gateway's verdict map is empty, so
      // the first capture pays BOTH cold starts — the prober that measures the
      // pulled rule against the battery, and then the scan worker. A real
      // machine pays the prober once per rule ever and nothing after that.
      const coldStart = performance.now();
      await rt.processText(text);
      const startupMs = performance.now() - coldStart;

      // A PreToolUse hook scans one field per MCP leaf, so the steady-state
      // round trip — not the start — is what a real payload multiplies.
      const samples: number[] = [];
      for (let i = 0; i < 40; i++) {
        const started = performance.now();
        await rt.processText(text);
        samples.push(performance.now() - started);
      }
      samples.sort((a, b) => a - b);
      const medianMs = samples[Math.floor(samples.length / 2)] ?? Infinity;

      // Ceilings, not measurements — CI runners are far too noisy to assert a
      // real timing, and these two are noisy in very different degrees.
      //
      // The round trip is the load-bearing one: it is what a real payload
      // MULTIPLIES, one scan per MCP leaf, and it is stable because it measures
      // a message round trip and nothing else. 0.195ms here against an
      // in-process scan of ~0.173ms, so 25ms is ~128x headroom and would catch
      // the regression that matters — a worker started per scan instead of per
      // process.
      //
      // The cold start is the noisy one and guards much less. It covers two
      // thread creations plus a whole probe battery, and in the repo Node
      // strips the types on the way in; 189ms here, and a contended Linux CI
      // runner has been seen at 2.7s for the same work. So the ceiling is a
      // smoke bound, sized to clear that with room while still catching a
      // change of SHAPE — a worker per rule, or a prober that re-measures what
      // the cache already answered, both scale with the ruleset and blow this
      // by orders of magnitude. Do not tighten it toward the observed number:
      // the last time this was sized against one worker start, adding the
      // second one turned it into a red CI run rather than a real signal.
      expect(startupMs).toBeLessThan(10_000);
      expect(medianMs).toBeLessThan(25);
    } finally {
      await rt.close();
    }
  });
});
