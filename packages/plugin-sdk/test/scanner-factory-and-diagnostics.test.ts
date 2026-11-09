/**
 * The runtime's two caller-supplied options for isolated scanning: a factory for
 * the isolated scanner, and a sink for the diagnostic lines the runtime writes.
 * Absent, each falls back to the worker-thread scanner and to stderr.
 */
import { runInNewContext } from 'node:vm';

import { scan } from '@akasecurity/detections';
import type { PolicyBundle, Rule, RuleProbeVerdict, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CaptureRecord, DataGateway, RuleProbeVerdictEntry } from '../src/data-gateway.ts';
import { diagnosticWriter } from '../src/diagnostics.ts';
import { createGuardedScanner } from '../src/guarded-scan.ts';
import type {
  IsolatedProbeOutcome,
  IsolatedScanner,
  IsolatedScannerFactory,
  IsolatedScanOptions,
  IsolatedScanOutcome,
} from '../src/isolated-scan.ts';
import { buildIsolatedScanner } from '../src/isolated-scan.ts';
import { filterUnsafeRules, quarantineRule, ruleProbeKey } from '../src/rule-quarantine.ts';
import { createPluginRuntime, reuseScanners } from '../src/runtime.ts';

const PULLED: Rule = {
  specVersion: 1,
  id: 'pulled/factory-token',
  name: 'Factory token',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`FACTORY-TOKEN-[0-9]{6}`, flags: 'g' },
};
const TOKEN_TEXT = 'note FACTORY-TOKEN-123456 here';
const OTHER: Rule = {
  ...PULLED,
  id: 'pulled/other-token',
  matcher: { type: 'regex', pattern: String.raw`OTHER-TOKEN-[0-9]{6}`, flags: 'g' },
};

const START_MS = 30_000;

// A worker module that throws on load: a scan that reaches a real worker
// thread through it comes back unavailable.
const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);

const SAFE_PROBE: IsolatedProbeOutcome = {
  status: 'ok',
  verdict: 'safe',
  worstMs: 0.1,
  corroboratedMs: 0.1,
};
const NO_WORKER: IsolatedProbeOutcome & IsolatedScanOutcome = {
  status: 'unavailable',
  reason: 'no worker here',
};

interface Built {
  verified: string[];
  unverified: string[];
  opts: IsolatedScanOptions | undefined;
}

interface ScriptedFactory {
  factory: IsolatedScannerFactory;
  built: Built[];
}

// A factory whose scanners run the scan on the calling thread, or answer with
// the outcomes the case scripts.
function scriptedFactory(
  script: {
    scan?: IsolatedScanOutcome;
    probe?: IsolatedProbeOutcome;
  } = {},
): ScriptedFactory {
  const built: Built[] = [];
  const factory: IsolatedScannerFactory = (data, opts) => {
    built.push({
      verified: data.verified.map((rule) => rule.id),
      unverified: data.unverified.map((rule) => rule.id),
      opts,
    });
    const rules = [...data.verified, ...data.unverified];
    const scanner: IsolatedScanner = {
      scan: (text, context) =>
        Promise.resolve(script.scan ?? { status: 'ok', findings: scan(text, rules, context) }),
      probe: () => Promise.resolve(script.probe ?? SAFE_PROBE),
      close: () => Promise.resolve(),
    };
    return scanner;
  };
  return { factory, built };
}

const throwingFactory: IsolatedScannerFactory = () => {
  throw new Error('factory failed');
};

function collectLines(): { sink: (line: string) => void; lines: string[] } {
  const lines: string[] = [];
  return { sink: (line) => lines.push(line), lines };
}

function captureStderr(): { text: () => string } {
  const written: string[] = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  return { text: () => written.join('') };
}

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

// A probe cache that already holds a safe verdict for `rules`, so the case
// starts at the scan rather than at the timing pre-flight.
function clearedByPreflight(...rules: Rule[]): Map<string, RuleProbeVerdictEntry> {
  const verdicts = new Map<string, RuleProbeVerdictEntry>();
  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key !== undefined) verdicts.set(key, { verdict: 'safe', worstProbeMs: 0.1 });
  }
  return verdicts;
}

async function captureWith(
  gateway: DataGateway,
  opts: Parameters<typeof createPluginRuntime>[2],
  text = TOKEN_TEXT,
) {
  const runtime = createPluginRuntime(gateway, settings(), opts);
  try {
    const result = await runtime.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
    return { result, degraded: runtime.scanIsolationDegraded() };
  } finally {
    await runtime.close();
  }
}

afterEach(async () => {
  vi.restoreAllMocks();
  await reuseScanners(false);
});

describe('the isolated scanner factory', () => {
  it('builds the timing prober and the scan scanner, with the runtime scan options', async () => {
    const { factory, built } = scriptedFactory();
    const gateway = fakeGateway(bundle([PULLED]));
    const stderr = captureStderr();
    // A real worker built from this URL fails, so the pulled rule is found
    // only if both the probe and the scan go through the factory.
    const scanIsolation = { workerUrl: CRASHING_WORKER, startBudgetMs: START_MS };

    const { result, degraded } = await captureWith(gateway, {
      isolatedScanner: factory,
      scanIsolation,
    });

    expect(result.findings.map((f) => f.ruleId)).toEqual(['pulled/factory-token']);
    expect(degraded).toBe(false);
    expect(built.map((entry) => entry.unverified)).toEqual([[], ['pulled/factory-token']]);
    expect(built.every((entry) => entry.opts === scanIsolation)).toBe(true);
    expect(
      built
        .flatMap((entry): unknown[] => Object.values(entry.opts ?? {}))
        .filter((v) => typeof v === 'function'),
    ).toEqual([]);
    expect(gateway.verdicts.get(ruleProbeKey(PULLED) ?? '')?.verdict).toBe('safe');
    expect(stderr.text()).toBe('');
  });

  it('builds no scanner for a ruleset with nothing to isolate', async () => {
    const { factory, built } = scriptedFactory();
    const { result } = await captureWith(fakeGateway(bundle()), { isolatedScanner: factory });
    expect(result.findings).toEqual([]);
    expect(built).toEqual([]);
  });

  it('excludes the pulled rules, persisting nothing, when its prober is unavailable', async () => {
    const { factory } = scriptedFactory({ probe: NO_WORKER });
    const gateway = fakeGateway(bundle([PULLED]));
    const { sink, lines } = collectLines();

    const { result } = await captureWith(gateway, { isolatedScanner: factory, diagnostics: sink });

    expect(result.findings).toEqual([]);
    expect(gateway.verdicts.size).toBe(0);
    expect(lines).toEqual([
      '[aka] 1 pulled/custom-pack rule(s) could not be time-checked: no worker here. ' +
        'That is a problem with this install, not with the rules — until it is fixed they are ' +
        'excluded from every scan on this machine. Nothing was quarantined, so reinstalling AKA ' +
        'brings them straight back.',
    ]);
  });

  it('degrades to the verified rules when its scanner is unavailable', async () => {
    const { factory } = scriptedFactory({ scan: NO_WORKER });
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { sink, lines } = collectLines();

    const { result, degraded } = await captureWith(gateway, {
      isolatedScanner: factory,
      diagnostics: sink,
    });

    expect(result.findings).toEqual([]);
    expect(degraded).toBe(true);
    expect(lines).toEqual([
      '[aka] isolated scanning is off for the rest of this process: no worker here. ' +
        '1 pulled/custom-pack rule(s) are excluded; the built-in packs still run.',
    ]);
  });

  it('serves the bounded large-input scan', async () => {
    const { factory, built } = scriptedFactory();
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

    const { result } = await captureWith(gateway, {
      isolatedScanner: factory,
      largeInput: { thresholdChars: 8, budgetMs: 2_000, startBudgetMs: START_MS },
    });

    expect(result.findings.map((f) => f.ruleId)).toEqual(['pulled/factory-token']);
    expect(result).not.toHaveProperty('scanIncomplete');
    // One scanner for ordinary scans and one for bounded scans.
    expect(built.map((entry) => entry.unverified)).toEqual([
      ['pulled/factory-token'],
      ['pulled/factory-token'],
    ]);
  });

  it('excludes the pulled rules, persisting nothing, when it throws building the prober', async () => {
    const gateway = fakeGateway(bundle([PULLED]));
    const { sink, lines } = collectLines();

    const { result } = await captureWith(gateway, {
      isolatedScanner: throwingFactory,
      diagnostics: sink,
    });

    expect(result.findings).toEqual([]);
    expect(gateway.verdicts.size).toBe(0);
    expect(lines).toEqual([
      '[aka] 1 pulled/custom-pack rule(s) could not be time-checked: factory failed. ' +
        'That is a problem with this install, not with the rules — until it is fixed they are ' +
        'excluded from every scan on this machine. Nothing was quarantined, so reinstalling AKA ' +
        'brings them straight back.',
    ]);
  });

  it('excludes the pulled rules, persisting nothing, when its prober rejects', async () => {
    const rejectingProbe: IsolatedScannerFactory = (data, opts) => ({
      ...scriptedFactory().factory(data, opts),
      probe: () => Promise.reject(new Error('probe down')),
    });
    const gateway = fakeGateway(bundle([PULLED]));
    const { sink, lines } = collectLines();

    const { result } = await captureWith(gateway, {
      isolatedScanner: rejectingProbe,
      diagnostics: sink,
    });

    expect(result.findings).toEqual([]);
    expect(gateway.verdicts.size).toBe(0);
    expect(lines).toEqual([
      '[aka] 1 pulled/custom-pack rule(s) could not be time-checked: probe down. ' +
        'That is a problem with this install, not with the rules — until it is fixed they are ' +
        'excluded from every scan on this machine. Nothing was quarantined, so reinstalling AKA ' +
        'brings them straight back.',
    ]);
  });

  it('keeps the bundled packs detecting when its prober rejects', async () => {
    const rejectingProbe: IsolatedScannerFactory = (data, opts) => ({
      ...scriptedFactory().factory(data, opts),
      probe: () => Promise.reject(new Error('probe down')),
    });
    const gateway = fakeGateway(bundle([PULLED]));

    const { result } = await captureWith(
      gateway,
      { isolatedScanner: rejectingProbe, diagnostics: () => undefined },
      'key AKIAIOSFODNN7EXAMPLE here',
    );

    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('keeps the bundled packs detecting when its prober rejects, and rejects again on close', async () => {
    let built = 0;
    // The prober is the one scanner built with no rules of its own.
    const rejectingProber: IsolatedScannerFactory = (data, opts) => {
      const scanner = scriptedFactory().factory(data, opts);
      if (data.verified.length + data.unverified.length > 0) return scanner;
      built += 1;
      return {
        ...scanner,
        probe: () => Promise.reject(new Error('probe down')),
        close: () => Promise.reject(new Error('terminate failed')),
      };
    };
    const gateway = fakeGateway(bundle([PULLED]));

    const { result } = await captureWith(
      gateway,
      { isolatedScanner: rejectingProber, diagnostics: () => undefined },
      'key AKIAIOSFODNN7EXAMPLE here',
    );

    expect(built).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('names a thrown value that is not an Error', async () => {
    const throwsString: IsolatedScannerFactory = () => {
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- a host may throw a bare value
      throw 'factory down';
    };
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { sink, lines } = collectLines();

    await captureWith(gateway, {
      isolatedScanner: throwsString,
      diagnostics: sink,
      largeInput: { thresholdChars: 8, budgetMs: 2_000, startBudgetMs: START_MS },
    });

    expect(lines).toEqual([
      '[aka] a large input could not be scanned and was refused: factory down.',
    ]);
  });

  it('degrades to the verified rules when it throws building the scan scanner', async () => {
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { sink, lines } = collectLines();

    const { result, degraded } = await captureWith(gateway, {
      isolatedScanner: throwingFactory,
      diagnostics: sink,
    });

    expect(result.findings).toEqual([]);
    expect(degraded).toBe(true);
    expect(lines).toEqual([
      '[aka] isolated scanning is off for the rest of this process: factory failed. ' +
        '1 pulled/custom-pack rule(s) are excluded; the built-in packs still run.',
    ]);
  });

  it('refuses a large input when it throws building the bounded scanner', async () => {
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { sink, lines } = collectLines();

    const { result } = await captureWith(gateway, {
      isolatedScanner: throwingFactory,
      diagnostics: sink,
      largeInput: { thresholdChars: 8, budgetMs: 2_000, startBudgetMs: START_MS },
    });

    expect(result.scanIncomplete).toBe('unavailable');
    expect(lines).toEqual([
      '[aka] a large input could not be scanned and was refused: factory failed.',
    ]);
  });

  it('keeps a scanner across runtimes only for the factory that built it', async () => {
    await reuseScanners(true);
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const first = scriptedFactory();
    const second = scriptedFactory();
    const scanIsolation = { startBudgetMs: START_MS };

    await captureWith(gateway, { isolatedScanner: first.factory, scanIsolation });
    await captureWith(gateway, { isolatedScanner: first.factory, scanIsolation });
    expect(first.built).toHaveLength(1);

    const { result } = await captureWith(gateway, {
      isolatedScanner: second.factory,
      scanIsolation,
    });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['pulled/factory-token']);
    expect(second.built).toHaveLength(1);
    expect([...first.built, ...second.built].every((entry) => entry.opts === scanIsolation)).toBe(
      true,
    );
  });

  it('keeps a scanner across runtimes only for the scan options it was built with', async () => {
    await reuseScanners(true);
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { factory, built } = scriptedFactory();
    const first = { startBudgetMs: START_MS, workerUrl: new URL('./worker.js', import.meta.url) };
    const sameValues = {
      startBudgetMs: START_MS,
      workerUrl: new URL('./worker.js', import.meta.url),
    };
    const otherWorker = {
      startBudgetMs: START_MS,
      workerUrl: new URL('./other.js', import.meta.url),
    };
    const smallerBudget = { startBudgetMs: START_MS, budgetMs: 50 };

    await captureWith(gateway, { isolatedScanner: factory, scanIsolation: first });
    await captureWith(gateway, { isolatedScanner: factory, scanIsolation: sameValues });
    await captureWith(gateway, { isolatedScanner: factory, scanIsolation: otherWorker });
    await captureWith(gateway, { isolatedScanner: factory, scanIsolation: smallerBudget });

    expect(built.map((entry) => entry.opts)).toEqual([first, otherWorker, smallerBudget]);
    expect(built[1]?.opts).toBe(otherWorker);
    expect(built[2]?.opts).toBe(smallerBudget);
  });
});

describe('the diagnostics sink', () => {
  it('keeps a scanner across runtimes only for the sink it reports to', async () => {
    await reuseScanners(true);
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));
    const { factory, built } = scriptedFactory();
    const one = collectLines();
    const other = collectLines();

    await captureWith(gateway, { isolatedScanner: factory, diagnostics: one.sink });
    await captureWith(gateway, { isolatedScanner: factory, diagnostics: one.sink });
    expect(built).toHaveLength(1);

    await captureWith(gateway, { isolatedScanner: factory, diagnostics: other.sink });
    expect(built).toHaveLength(2);
  });

  it('takes the default scanner lines in place of stderr', async () => {
    const stderr = captureStderr();
    const { sink, lines } = collectLines();

    await captureWith(fakeGateway(bundle([PULLED])), {
      scanIsolation: { workerUrl: CRASHING_WORKER, startBudgetMs: START_MS },
      diagnostics: sink,
    });

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^\[aka\] 1 pulled\/custom-pack rule\(s\) could not be time-checked: /,
    );
    expect(lines[0]).not.toMatch(/\n/);
    expect(stderr.text()).toBe('');
  });

  it('absent, leaves each line on stderr with its newline', async () => {
    const { sink, lines } = collectLines();
    await captureWith(fakeGateway(bundle([PULLED])), {
      isolatedScanner: scriptedFactory({ probe: NO_WORKER }).factory,
      diagnostics: sink,
    });

    const stderr = captureStderr();
    await captureWith(fakeGateway(bundle([PULLED])), {
      isolatedScanner: scriptedFactory({ probe: NO_WORKER }).factory,
    });

    expect(lines).toHaveLength(1);
    expect(stderr.text()).toBe(`${lines[0] ?? ''}\n`);
  });

  it('takes the quarantine and degrade lines of a scan that hit its bound', async () => {
    const stderr = captureStderr();
    const { sink, lines } = collectLines();
    const { factory } = scriptedFactory({
      scan: { status: 'timeout', culpritIndex: 0, elapsedMs: 1_500 },
    });
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

    await captureWith(gateway, { isolatedScanner: factory, diagnostics: sink });

    expect(lines).toEqual([
      '[aka] quarantined rule "pulled/factory-token": it did not finish within the 1500ms ' +
        'isolated-scan bound and was terminated; excluded from every later scan. ' +
        '(clear it with `aka detections unquarantine`)',
      '[aka] isolated scanning is off for the rest of this process: rule ' +
        '"pulled/factory-token" had to be terminated mid-scan. 1 pulled/custom-pack rule(s) ' +
        'are excluded; the built-in packs still run.',
    ]);
    expect(gateway.verdicts.get(ruleProbeKey(PULLED) ?? '')?.verdict).toBe('quarantined');
    expect(stderr.text()).toBe('');
  });

  it('takes the refusal line of a large input that could not be scanned', async () => {
    const stderr = captureStderr();
    const { sink, lines } = collectLines();
    const { factory } = scriptedFactory({ scan: NO_WORKER });
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

    const { result } = await captureWith(gateway, {
      isolatedScanner: factory,
      diagnostics: sink,
      largeInput: { thresholdChars: 8, budgetMs: 2_000, startBudgetMs: START_MS },
    });

    expect(result.scanIncomplete).toBe('unavailable');
    expect(lines).toEqual([
      '[aka] a large input could not be scanned and was refused: no worker here.',
    ]);
    expect(stderr.text()).toBe('');
  });
});

describe('the scan building blocks', () => {
  it('createGuardedScanner builds through the factory and reports to the sink', async () => {
    const { factory, built } = scriptedFactory({ scan: NO_WORKER });
    const { sink, lines } = collectLines();
    const scanner = createGuardedScanner(
      { verified: [], unverified: [PULLED] },
      { setRuleProbeVerdict: () => Promise.resolve() },
      { degradeScope: 'this scan' },
      { isolatedScanner: factory, diagnostics: sink },
    );
    try {
      expect(await scanner.scan(TOKEN_TEXT)).toEqual([]);
    } finally {
      await scanner.close();
    }
    expect(built.map((entry) => entry.unverified)).toEqual([['pulled/factory-token']]);
    expect(lines).toEqual([
      '[aka] isolated scanning is off for this scan: no worker here. ' +
        '1 pulled/custom-pack rule(s) are excluded; the built-in packs still run.',
    ]);
  });

  it('filterUnsafeRules reports a cached quarantine to the sink', async () => {
    const stderr = captureStderr();
    const { sink, lines } = collectLines();
    const key = ruleProbeKey(PULLED) ?? '';
    const gateway = {
      getRuleProbeVerdict: (k: string) =>
        Promise.resolve(
          k === key ? { verdict: 'quarantined' as const, worstProbeMs: 12 } : undefined,
        ),
      setRuleProbeVerdict: () => Promise.resolve(),
    };

    expect(await filterUnsafeRules([PULLED], gateway, { diagnostics: sink })).toEqual([]);
    expect(lines).toEqual([
      '[aka] quarantined rule "pulled/factory-token": regex matcher exceeded the ReDoS timing ' +
        'budget (12.0ms); excluded from this scan. (clear it with `aka detections unquarantine`)',
    ]);
    expect(stderr.text()).toBe('');
  });

  it('quarantineRule reports to the sink, and to stderr without one', async () => {
    const gateway = { setRuleProbeVerdict: () => Promise.resolve() };
    const { sink, lines } = collectLines();
    await quarantineRule(gateway, PULLED, 5, 'hung.', sink);

    const stderr = captureStderr();
    await quarantineRule(gateway, PULLED, 5, 'hung.');

    expect(lines).toEqual([
      '[aka] quarantined rule "pulled/factory-token": hung. ' +
        '(clear it with `aka detections unquarantine`)',
    ]);
    expect(stderr.text()).toBe(`${lines[0] ?? ''}\n`);
  });
});

describe('a scanner that breaks its contract', () => {
  const NO_DATA = { verified: [], unverified: [] };
  const misbehaving = (over: Partial<IsolatedScanner>): IsolatedScannerFactory => {
    return (data, opts) => ({ ...scriptedFactory().factory(data, opts), ...over });
  };

  it('answers unavailable for a scan or probe that throws, rejects or answers nothing', async () => {
    const throws = buildIsolatedScanner(
      misbehaving({
        scan: () => {
          throw new Error('scan threw');
        },
        probe: () => Promise.reject(new Error('probe rejected')),
      }),
      NO_DATA,
    );
    const silent = buildIsolatedScanner(
      misbehaving({
        scan: () => Promise.resolve(undefined as unknown as IsolatedScanOutcome),
        probe: () => Promise.resolve({ verdict: 'safe' } as unknown as IsolatedProbeOutcome),
      }),
      NO_DATA,
    );

    expect(await throws.scan(TOKEN_TEXT)).toEqual({ status: 'unavailable', reason: 'scan threw' });
    expect(await throws.probe(PULLED)).toEqual({
      status: 'unavailable',
      reason: 'probe rejected',
    });
    const noOutcome = { status: 'unavailable', reason: 'the scanner answered no outcome' };
    expect(await silent.scan(TOKEN_TEXT)).toEqual(noOutcome);
    expect(await silent.probe(PULLED)).toEqual(noOutcome);
  });

  it('drops a close that throws or rejects', async () => {
    const throwing = buildIsolatedScanner(
      misbehaving({
        close: () => {
          throw new Error('close threw');
        },
      }),
      NO_DATA,
    );
    const rejecting = buildIsolatedScanner(
      misbehaving({ close: () => Promise.reject(new Error('terminate failed')) }),
      NO_DATA,
    );

    await expect(throwing.close()).resolves.toBeUndefined();
    await expect(rejecting.close()).resolves.toBeUndefined();
  });

  it('leaves a guarded scan its verified findings when the retired scanner rejects on close', async () => {
    const { sink, lines } = collectLines();
    const scanner = createGuardedScanner(
      { verified: [OTHER], unverified: [PULLED] },
      { setRuleProbeVerdict: () => Promise.resolve() },
      undefined,
      {
        isolatedScanner: misbehaving({
          scan: () => Promise.resolve({ status: 'timeout', culpritIndex: 0, elapsedMs: 1_500 }),
          close: () => Promise.reject(new Error('terminate failed')),
        }),
        diagnostics: sink,
      },
    );
    try {
      const findings = await scanner.scan('note OTHER-TOKEN-123456 here');
      expect(findings.map((finding) => finding.ruleId)).toEqual(['pulled/other-token']);
    } finally {
      await expect(scanner.close()).resolves.toBeUndefined();
    }
    expect(scanner.degraded()).toBe(true);
    expect(lines.at(-1)).toContain('the built-in packs still run');
  });

  it('refuses a large input whose scanner answers no outcome', async () => {
    const { sink, lines } = collectLines();
    const scanner = createGuardedScanner(
      { verified: [], unverified: [PULLED] },
      { setRuleProbeVerdict: () => Promise.resolve() },
      undefined,
      {
        isolatedScanner: misbehaving({
          scan: () => Promise.resolve(undefined as unknown as IsolatedScanOutcome),
        }),
        diagnostics: sink,
      },
    );
    try {
      expect(
        await scanner.scanBounded(TOKEN_TEXT, undefined, {
          budgetMs: 2_000,
          startBudgetMs: START_MS,
        }),
      ).toEqual({
        status: 'unavailable',
        reason: 'the scanner answered no outcome',
      });
    } finally {
      await scanner.close();
    }
    expect(lines).toEqual([
      '[aka] a large input could not be scanned and was refused: the scanner answered no outcome.',
    ]);
  });
});

describe('a diagnostics sink that throws', () => {
  const throwingSink = (): never => {
    throw new Error('sink failed');
  };
  const KEYWORD: Rule = {
    specVersion: 1,
    id: 'pack/keyword-marker',
    name: 'Keyword marker',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['KEYWORD_MARKER'], caseSensitive: true },
  };

  it('leaves a scan that hit its bound with its fallback findings, degraded', async () => {
    const setRuleProbeVerdict = vi.fn(() => Promise.resolve());
    const { factory } = scriptedFactory({
      scan: { status: 'timeout', culpritIndex: 0, elapsedMs: 1_500 },
    });
    const scanner = createGuardedScanner(
      { verified: [KEYWORD], unverified: [PULLED] },
      { setRuleProbeVerdict },
      undefined,
      { isolatedScanner: factory, diagnostics: throwingSink },
    );
    try {
      const findings = await scanner.scan(`KEYWORD_MARKER ${TOKEN_TEXT}`);
      expect(findings.map((f) => f.ruleId)).toEqual(['pack/keyword-marker']);
      expect(scanner.degraded()).toBe(true);
      expect(setRuleProbeVerdict).toHaveBeenCalledWith(ruleProbeKey(PULLED), 'quarantined', 1_500);
    } finally {
      await scanner.close();
    }
  });

  it('leaves the runtime degraded after a scan that hit its bound', async () => {
    const { factory } = scriptedFactory({
      scan: { status: 'timeout', culpritIndex: 0, elapsedMs: 1_500 },
    });
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

    const { degraded } = await captureWith(gateway, {
      isolatedScanner: factory,
      diagnostics: throwingSink,
    });

    expect(degraded).toBe(true);
    expect(gateway.verdicts.get(ruleProbeKey(PULLED) ?? '')?.verdict).toBe('quarantined');
  });

  it('leaves a large input refused rather than failing the capture', async () => {
    const { factory } = scriptedFactory({ scan: NO_WORKER });
    const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

    const { result } = await captureWith(gateway, {
      isolatedScanner: factory,
      diagnostics: throwingSink,
      largeInput: { thresholdChars: 8, budgetMs: 2_000, startBudgetMs: START_MS },
    });

    expect(result.scanIncomplete).toBe('unavailable');
  });

  it('does not reject a pre-flight that would otherwise succeed', async () => {
    const quarantinedKey = ruleProbeKey(PULLED) ?? '';
    const gateway = {
      getRuleProbeVerdict: (k: string) =>
        Promise.resolve(
          k === quarantinedKey ? { verdict: 'quarantined' as const, worstProbeMs: 12 } : undefined,
        ),
      setRuleProbeVerdict: () => Promise.resolve(),
    };

    await expect(
      filterUnsafeRules([PULLED, OTHER], gateway, {
        prober: { probe: () => Promise.resolve(NO_WORKER) },
        diagnostics: throwingSink,
      }),
    ).resolves.toEqual([]);
  });

  it('does not replace an error already leaving the pre-flight', async () => {
    let probes = 0;
    const gateway = {
      getRuleProbeVerdict: () => Promise.resolve(undefined),
      setRuleProbeVerdict: () => Promise.resolve(),
    };

    await expect(
      filterUnsafeRules([PULLED, OTHER], gateway, {
        prober: {
          probe: () => {
            probes += 1;
            return probes === 1
              ? Promise.resolve(NO_WORKER)
              : Promise.reject(new Error('probe failed'));
          },
        },
        diagnostics: throwingSink,
      }),
    ).rejects.toThrow('probe failed');
  });

  it('does not reject quarantineRule', async () => {
    const setRuleProbeVerdict = vi.fn(() => Promise.resolve());
    await expect(
      quarantineRule({ setRuleProbeVerdict }, PULLED, 5, 'hung.', throwingSink),
    ).resolves.toBeUndefined();
    expect(setRuleProbeVerdict).toHaveBeenCalledTimes(1);
  });
});

describe('a diagnostics sink that rejects', () => {
  it('leaves a scan that hit its bound degraded, with no unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const { factory } = scriptedFactory({
        scan: { status: 'timeout', culpritIndex: 0, elapsedMs: 1_500 },
      });
      const gateway = fakeGateway(bundle([PULLED]), clearedByPreflight(PULLED));

      const { degraded } = await captureWith(gateway, {
        isolatedScanner: factory,
        // eslint-disable-next-line @typescript-eslint/no-misused-promises -- an async sink is the case under test
        diagnostics: async () => {
          await Promise.resolve();
          throw new Error('sink rejected');
        },
      });
      await new Promise((resolve) => setImmediate(resolve));

      expect(degraded).toBe(true);
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('drops the rejection of a promise from another realm', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const crossRealm = (): unknown =>
        runInNewContext('Promise.reject(new Error("sink rejected"))');
      const write = diagnosticWriter(crossRealm);
      write('[aka] a line');
      await new Promise((resolve) => setImmediate(resolve));

      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});
