/**
 * The `scanIsolation` value a runtime is given is the value each built-in
 * isolated scanner it builds receives: the same object, or `undefined` when
 * none was given.
 */
import type { PolicyBundle, Rule, RuleProbeVerdict, WorkspaceSettings } from '@akasecurity/schema';
import type { MockInstance } from 'vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DataGateway, RuleProbeVerdictEntry } from '../src/data-gateway.ts';
import type * as IsolatedScan from '../src/isolated-scan.ts';
import type { IsolatedScanOptions } from '../src/isolated-scan.ts';
import { ruleProbeKey } from '../src/rule-quarantine.ts';

vi.mock('../src/isolated-scan.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof IsolatedScan>();
  return { ...actual, createIsolatedScanner: vi.fn(actual.createIsolatedScanner) };
});

const { createIsolatedScanner } = await import('../src/isolated-scan.ts');
const { createPluginRuntime } = await import('../src/runtime.ts');
const createIsolatedScannerMock = vi.mocked(createIsolatedScanner);

const PULLED: Rule = {
  specVersion: 1,
  id: 'pulled/pass-through-token',
  name: 'Pass-through token',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`PASS-TOKEN-[0-9]{6}`, flags: 'g' },
};

// A worker module that throws on load, so no case here waits on a real scan.
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
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
  };
}

function bundle(rules: Rule[]): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    rules,
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

function fakeGateway(b: PolicyBundle, verdicts = new Map<string, RuleProbeVerdictEntry>()) {
  const gateway: DataGateway = {
    recordCapture: () => Promise.resolve(),
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

function clearedByPreflight(rule: Rule): Map<string, RuleProbeVerdictEntry> {
  const key = ruleProbeKey(rule);
  return new Map(key === undefined ? [] : [[key, { verdict: 'safe', worstProbeMs: 0.1 }]]);
}

async function capture(
  gateway: DataGateway,
  scanIsolation: IsolatedScanOptions | undefined,
): Promise<void> {
  const runtime = createPluginRuntime(gateway, settings(), {
    scanIsolation,
    largeInput: { thresholdChars: 32, budgetMs: 2_000, startBudgetMs: 30_000 },
  });
  try {
    await runtime.capture({ kind: 'prompt', sourceTool: 'claude-code', text: 'PASS-TOKEN-123456' });
    await runtime.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: `PASS-TOKEN-123456 ${'x'.repeat(64)}`,
    });
  } finally {
    await runtime.close();
  }
}

let stderrSpy: MockInstance | undefined;

beforeEach(() => {
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  stderrSpy?.mockRestore();
  createIsolatedScannerMock.mockClear();
});

describe('the scanIsolation value a runtime passes on', () => {
  it('reaches the prober, the scan scanner and the bounded scanner as one object', async () => {
    const scanIsolation: IsolatedScanOptions = {
      workerUrl: CRASHING_WORKER,
      startBudgetMs: 30_000,
    };

    // Uncached, so the timing pre-flight builds its prober.
    await capture(fakeGateway(bundle([PULLED])), scanIsolation);
    // Cached as safe, so the ordinary and the bounded scanner are built.
    await capture(fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED)), scanIsolation);

    const passed = createIsolatedScannerMock.mock.calls.map(([, opts]) => opts);
    expect(passed.length).toBeGreaterThanOrEqual(3);
    expect(passed.every((opts) => opts === scanIsolation)).toBe(true);
  });

  it('reaches them as undefined when the runtime was given none', async () => {
    await capture(fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED)), undefined);

    const passed = createIsolatedScannerMock.mock.calls.map(([, opts]) => opts);
    expect(passed.length).toBeGreaterThanOrEqual(2);
    expect(passed.every((opts) => opts === undefined)).toBe(true);
  });
});
