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

const BUDGET_MS = 3_000;

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
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
    const gw = fakeGateway(bundle([HOSTILE]));
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
      // harness kills lets the whole tool call through unscanned.
      expect(elapsedMs).toBeLessThan(BUDGET_MS * 3);
      // The bundled rule in the same text is untouched by the termination.
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
      expect(result.action).toBe('warn');
      // And the event was still persisted, with the finding masked as usual.
      expect(gw.records).toHaveLength(1);
      expect(gw.records[0]?.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await rt.close();
    }
  });

  it('is quarantined, so the next process never loads it again', async () => {
    silenceStderr();
    const verdicts = new Map<string, RuleProbeVerdictEntry>();

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
      expect(performance.now() - started).toBeLessThan(BUDGET_MS / 2);
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await second.close();
    }
  });
});

describe('what isolation costs when nothing is wrong', () => {
  it('costs nothing at all when the bundle carries no pulled regex rule', async () => {
    // No worker is startable here — the URL points at a module that throws on
    // load — so finishing at all proves the in-process path was taken. This is
    // the steady state of a machine that installed no extra pack.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings(), {
      scanIsolation: { workerUrl: new URL('./helpers/crashing-scan-worker.ts', import.meta.url) },
    });
    try {
      const result = await rt.processText('deploy with SECRET_MARKER now');
      expect(result.findings.map((f) => f.ruleId)).toEqual(['isolation/secret-marker']);
    } finally {
      await rt.close();
    }
  });

  it('costs one worker start, then a round trip per scan', async () => {
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

      // Ceilings, not measurements: on this hardware startup is ~50ms and the
      // median round trip ~0.2ms against an in-process scan of ~0.18ms, so both
      // bounds carry roughly two orders of magnitude of headroom. They exist to
      // catch a change that makes isolation cost seconds, not to track a trend
      // — CI runners are far too noisy to assert a real timing here.
      expect(startupMs).toBeLessThan(2_000);
      expect(medianMs).toBeLessThan(25);
    } finally {
      await rt.close();
    }
  });
});
