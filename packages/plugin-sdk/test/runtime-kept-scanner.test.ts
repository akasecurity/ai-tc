/**
 * A process that runs many hooks keeps one scanner across the runtimes it
 * creates, so a ruleset with a worker behind it starts that worker once. These
 * cases drive that at the capture path, counting the threads started.
 */
import type { PolicyBundle, Rule, RuleProbeVerdict, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway, RuleProbeVerdictEntry } from '../src/data-gateway.ts';
import { ruleProbeKey } from '../src/rule-quarantine.ts';
import { createPluginRuntime, reuseScanners } from '../src/runtime.ts';
import { countWorkerStarts } from './helpers/worker-starts.ts';

// A pulled regex rule: it has a worker behind its scanner, which is what a kept
// scanner saves starting.
const PULLED: Rule = {
  specVersion: 1,
  id: 'pulled/kept-token',
  name: 'Kept token',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`KEPT-TOKEN-[0-9]{6}`, flags: 'g' },
};
const OTHER: Rule = {
  ...PULLED,
  id: 'pulled/other-token',
  matcher: { type: 'regex', pattern: String.raw`OTHER-TOKEN-[0-9]{6}`, flags: 'g' },
};

const START_MS = 30_000;

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
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
    scanLedgerPaths: () => Promise.resolve([]),
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

afterEach(async () => {
  await reuseScanners(false);
});

async function captureOnce(
  gateway: DataGateway,
  starts: ReturnType<typeof countWorkerStarts>,
  text: string,
) {
  const runtime = createPluginRuntime(gateway, settings(), {
    scanIsolation: { startBudgetMs: START_MS, onWorkerStart: starts.onWorkerStart },
  });
  try {
    return await runtime.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
  } finally {
    await runtime.close();
  }
}

describe('a scanner kept across runtimes', () => {
  it('starts its worker once for many runtimes, and every capture still detects', async () => {
    await reuseScanners(true);
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const starts = countWorkerStarts();
    for (let i = 0; i < 3; i += 1) {
      const result = await captureOnce(gateway, starts, 'note KEPT-TOKEN-123456 here');
      expect(result.findings.map((f) => f.ruleId)).toEqual(['pulled/kept-token']);
    }
    expect(starts.count()).toBe(1);
  });

  it('starts a worker for every runtime when nothing is kept', async () => {
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const starts = countWorkerStarts();
    for (let i = 0; i < 3; i += 1) await captureOnce(gateway, starts, 'KEPT-TOKEN-123456');
    expect(starts.count()).toBe(3);
  });

  it('replaces the kept scanner when the ruleset changes', async () => {
    await reuseScanners(true);
    const verdicts = clearedByPreflight(PULLED, OTHER);
    const starts = countWorkerStarts();
    const first = await captureOnce(
      fakeGateway(bundle([PULLED]), verdicts),
      starts,
      'KEPT-TOKEN-123456 OTHER-TOKEN-123456',
    );
    expect(first.findings.map((f) => f.ruleId)).toEqual(['pulled/kept-token']);
    const second = await captureOnce(
      fakeGateway(bundle([PULLED, OTHER]), verdicts),
      starts,
      'KEPT-TOKEN-123456 OTHER-TOKEN-123456',
    );
    expect(second.findings.map((f) => f.ruleId).sort()).toEqual([
      'pulled/kept-token',
      'pulled/other-token',
    ]);
    expect(starts.count()).toBe(2);
  });

  it('is not reused for a different gateway', async () => {
    await reuseScanners(true);
    const verdicts = clearedByPreflight(PULLED);
    const starts = countWorkerStarts();
    await captureOnce(fakeGateway(bundle([PULLED]), verdicts), starts, 'KEPT-TOKEN-123456');
    await captureOnce(fakeGateway(bundle([PULLED]), verdicts), starts, 'KEPT-TOKEN-123456');
    expect(starts.count()).toBe(2);
  });

  it('is closed when keeping is turned off, so the next runtime starts afresh', async () => {
    await reuseScanners(true);
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const starts = countWorkerStarts();
    await captureOnce(gateway, starts, 'KEPT-TOKEN-123456');
    await reuseScanners(false);
    await captureOnce(gateway, starts, 'KEPT-TOKEN-123456');
    expect(starts.count()).toBe(2);
  });
});
