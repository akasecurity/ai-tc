/**
 * The large-input bound, seen from the capture path.
 *
 * A hook that opts in (`largeInput`) scans a field at or above the threshold in
 * a worker under a hard deadline, and a scan that cannot finish there FAILS
 * CLOSED: the decision is `block` and says why on `scanIncomplete`. The
 * properties worth breaking a build over:
 *
 *   - below the threshold, and with the option absent, nothing changes: the
 *     scan runs in-process and no worker is ever built;
 *   - a scan that times out, or a worker that cannot run, blocks — and the slow
 *     scan is never re-run in-process, which is the call the bound exists to
 *     keep off the hook's thread;
 *   - the caller's remaining time wins over the per-scan budget, so several
 *     large fields cannot add up past the host's own timeout.
 *
 * In-process scans are counted through a spy on the engine's `scan`. The worker
 * thread loads its own copy of the engine outside vitest's module graph, so the
 * spy sees the calling thread and nothing else — which is exactly the thread a
 * re-run would land on.
 */
import type { scan as Scan } from '@akasecurity/detections';
import type { PolicyBundle, Rule, RuleProbeVerdict, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CaptureRecord, DataGateway, RuleProbeVerdictEntry } from '../src/data-gateway.ts';
import { contentHashOf } from '../src/events.ts';
import type { LargeInputScanOptions } from '../src/runtime.ts';

vi.mock('@akasecurity/detections', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, scan: vi.fn(actual.scan as typeof Scan) };
});

const { scan } = await import('@akasecurity/detections');
const scanMock = vi.mocked(scan);

const { registerRulePack } = await import('../src/rule-packs.ts');
const { createPluginRuntime } = await import('../src/runtime.ts');
const { countWorkerStarts } = await import('./helpers/worker-starts.ts');

registerRulePack('large-input-test-pack', [
  {
    specVersion: 1,
    id: 'large-input/secret-marker',
    name: 'Large-input secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['SECRET_MARKER'] },
    examples: ['SECRET_MARKER'],
  },
]);

const THRESHOLD = 256;
const SMALL_TEXT = 'deploy with SECRET_MARKER now';
const LARGE_TEXT = `${'lorem ipsum dolor sit amet '.repeat(20)} SECRET_MARKER`;

// Generous on purpose: a type-stripped worker under a parallel workspace run has
// been seen past 5s to start. Every case whose premise is that the worker DID
// start grants this, so the runner's speed cannot turn a timeout case into an
// unavailable one.
const START_MS = 30_000;
const BUDGET_MS = 500;
const CASE_TIMEOUT_MS = 120_000;

const ENDLESS_WORKER = new URL('./helpers/endless-scan-worker.ts', import.meta.url);
const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);
const NEVER_READY_WORKER = new URL('./helpers/never-ready-scan-worker.ts', import.meta.url);
const MISSING_WORKER = new URL('./helpers/no-such-scan-worker.ts', import.meta.url);

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

interface FakeGateway {
  gateway: DataGateway;
  records: CaptureRecord[];
}

// Only what the capture path reaches. Anything else is a defect in the case,
// and the missing method throws to say so.
function fakeGateway(b: PolicyBundle = bundle()): FakeGateway {
  const records: CaptureRecord[] = [];
  const verdicts = new Map<string, RuleProbeVerdictEntry>();
  const gateway = {
    getPolicyBundle: () => Promise.resolve(b),
    recordCapture: (record: CaptureRecord) => {
      records.push(record);
      return Promise.resolve();
    },
    consumeException: () => Promise.resolve(false),
    recordBlockedDetection: () => Promise.resolve(),
    getRuleProbeVerdict: (key: string) => Promise.resolve(verdicts.get(key)),
    setRuleProbeVerdict: (key: string, verdict: RuleProbeVerdict, worstProbeMs: number) => {
      verdicts.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
    close: () => Promise.resolve(),
  } as unknown as DataGateway;
  return { gateway, records };
}

function largeInput(over: Partial<LargeInputScanOptions> = {}): LargeInputScanOptions {
  return {
    thresholdChars: THRESHOLD,
    budgetMs: BUDGET_MS,
    startBudgetMs: START_MS,
    ...over,
  };
}

function scannedInProcess(text: string): boolean {
  return scanMock.mock.calls.some(([scanned]) => scanned === text);
}

beforeEach(() => {
  scanMock.mockClear();
  // The fail-closed path explains itself on stderr; keep the suite readable.
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('without the option', () => {
  it('scans a large field in-process exactly as before, and builds no worker', async () => {
    const starts = countWorkerStarts();
    const { gateway } = fakeGateway();
    const rt = createPluginRuntime(gateway, settings(), {
      scanIsolation: { workerUrl: CRASHING_WORKER, onWorkerStart: starts.onWorkerStart },
    });
    try {
      const result = await rt.capture({
        kind: 'prompt',
        sourceTool: 'claude-code',
        text: LARGE_TEXT,
      });
      expect(result.findings.map((f) => f.ruleId)).toEqual(['large-input/secret-marker']);
      expect(result.action).toBe('warn');
      expect(result).not.toHaveProperty('scanIncomplete');
      expect(scannedInProcess(LARGE_TEXT)).toBe(true);
      expect(starts.count()).toBe(0);
    } finally {
      await rt.close();
    }
  });
});

describe('below the threshold', () => {
  it('keeps the in-process fast path and builds no worker', async () => {
    const starts = countWorkerStarts();
    const { gateway } = fakeGateway();
    const rt = createPluginRuntime(gateway, settings(), {
      // A worker that dies on load: reaching it at all would fail the case.
      scanIsolation: { workerUrl: CRASHING_WORKER, onWorkerStart: starts.onWorkerStart },
      largeInput: largeInput(),
    });
    try {
      const result = await rt.capture({
        kind: 'prompt',
        sourceTool: 'claude-code',
        text: SMALL_TEXT,
      });
      expect(result.findings.map((f) => f.ruleId)).toEqual(['large-input/secret-marker']);
      expect(result).not.toHaveProperty('scanIncomplete');
      expect(scannedInProcess(SMALL_TEXT)).toBe(true);
      expect(starts.count()).toBe(0);
    } finally {
      await rt.close();
    }
  });
});

describe('at or above the threshold', () => {
  it(
    'scans in the worker and decides on what it found',
    async () => {
      const starts = countWorkerStarts();
      const { gateway } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { onWorkerStart: starts.onWorkerStart },
        largeInput: largeInput({ budgetMs: 20_000 }),
      });
      try {
        const first = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        const second = await rt.processText(`${LARGE_TEXT} again`);
        expect(first.findings.map((f) => f.ruleId)).toEqual(['large-input/secret-marker']);
        expect(first.action).toBe('warn');
        expect(first).not.toHaveProperty('scanIncomplete');
        expect(second.findings.map((f) => f.ruleId)).toEqual(['large-input/secret-marker']);
        // The bundled rules ran over there, not here.
        expect(scannedInProcess(LARGE_TEXT)).toBe(false);
        // One worker per runtime, reused across fields.
        expect(starts.count()).toBe(1);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'blocks a field whose scan outlasts the budget, without re-running it in-process',
    async () => {
      const starts = countWorkerStarts();
      const { gateway, records } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: ENDLESS_WORKER, onWorkerStart: starts.onWorkerStart },
        largeInput: largeInput(),
      });
      try {
        const started = performance.now();
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        const elapsedMs = performance.now() - started;

        expect(result).toMatchObject({
          action: 'block',
          text: null,
          findings: [],
          scanIncomplete: 'timeout',
        });
        // The guarded path answers a lost worker with an in-process scan. Here
        // that re-run IS the unbounded call, so it must never happen.
        expect(scannedInProcess(LARGE_TEXT)).toBe(false);
        // One thread: no attribution retry on a second one.
        expect(starts.count()).toBe(1);
        // A start the case granted, plus one budget. Separates "returned" from
        // "kept going", which the case timeout alone reports the same way.
        expect(elapsedMs).toBeLessThan(START_MS + BUDGET_MS * 4);
        // Recorded like any live capture, so the block leaves a trace.
        expect(records).toHaveLength(1);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'records a blocked capture even when only findings are persisted',
    async () => {
      const { gateway, records } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: ENDLESS_WORKER },
        largeInput: largeInput(),
      });
      try {
        const result = await rt.capture(
          { kind: 'response', sourceTool: 'claude-code', text: LARGE_TEXT },
          { persist: 'with-findings' },
        );
        expect(result.scanIncomplete).toBe('timeout');
        expect(records).toHaveLength(1);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it.each([
    ['dies on load', CRASHING_WORKER, START_MS],
    ['is missing', MISSING_WORKER, START_MS],
    ['never announces itself', NEVER_READY_WORKER, 200],
  ])(
    'blocks when the worker %s',
    async (_label, workerUrl, startBudgetMs) => {
      const { gateway, records } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl },
        largeInput: largeInput({ startBudgetMs }),
      });
      try {
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        expect(result).toMatchObject({
          action: 'block',
          text: null,
          findings: [],
          scanIncomplete: 'unavailable',
        });
        expect(scannedInProcess(LARGE_TEXT)).toBe(false);
        expect(records[0]?.event.metadata?.scanIncomplete).toBe('unavailable');
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'honours a remaining time shorter than the budget',
    async () => {
      const { gateway } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: ENDLESS_WORKER },
        // A budget no case would wait out, and a caller with far less left.
        largeInput: largeInput({ budgetMs: 60_000, remainingMs: () => 300 }),
      });
      try {
        const started = performance.now();
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        expect(result.scanIncomplete).toBe('timeout');
        expect(performance.now() - started).toBeLessThan(15_000);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it('blocks without starting a worker once no time is left', async () => {
    const starts = countWorkerStarts();
    const { gateway } = fakeGateway();
    const rt = createPluginRuntime(gateway, settings(), {
      scanIsolation: { workerUrl: CRASHING_WORKER, onWorkerStart: starts.onWorkerStart },
      largeInput: largeInput({ remainingMs: () => 0 }),
    });
    try {
      const result = await rt.capture({
        kind: 'prompt',
        sourceTool: 'claude-code',
        text: LARGE_TEXT,
      });
      expect(result).toMatchObject({ action: 'block', scanIncomplete: 'timeout' });
      expect(starts.count()).toBe(0);
      expect(scannedInProcess(LARGE_TEXT)).toBe(false);
    } finally {
      await rt.close();
    }
  });

  // The capture result is the same whether or not the caller refuses; what
  // `refuses` changes is whether the SDK writes its "was refused" line.
  it.each([
    ['omitted', undefined, true],
    ['false', false, false],
  ] as const)(
    'passes refuses %s through to the stderr line',
    async (_label, refuses, writesLine) => {
      const lines: string[] = [];
      vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
        lines.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
        return true;
      });
      const { gateway } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: CRASHING_WORKER },
        largeInput: largeInput({
          remainingMs: () => 0,
          ...(refuses === undefined ? {} : { refuses }),
        }),
      });
      try {
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        expect(result).toMatchObject({ action: 'block', scanIncomplete: 'timeout' });
        // The refusing default is the positive control: the same capture
        // writes the line, so the empty stderr below is the option at work.
        const written = lines.join('');
        if (writesLine) expect(written).toContain('and was refused');
        else expect(written).toBe('');
      } finally {
        await rt.close();
      }
    },
  );

  // The callback is typed to return a number, but it is the caller's code: a
  // value that is not one is a limit nobody can read, and that is treated as
  // spent, never as no limit. `undefined` is the dangerous one — it is also
  // what "no caller limit" looks like further down.
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', '5000'],
    ['NaN', Number.NaN],
  ])(
    'fails closed when the remaining-time callback answers %s',
    async (_label, answer) => {
      const starts = countWorkerStarts();
      const { gateway } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: ENDLESS_WORKER, onWorkerStart: starts.onWorkerStart },
        largeInput: largeInput({ budgetMs: 60_000, remainingMs: () => answer as number }),
      });
      try {
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        expect(result).toMatchObject({ action: 'block', scanIncomplete: 'timeout' });
        expect(starts.count()).toBe(0);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it('fails closed when the remaining-time callback itself fails', async () => {
    const { gateway } = fakeGateway();
    const rt = createPluginRuntime(gateway, settings(), {
      scanIsolation: { workerUrl: CRASHING_WORKER },
      largeInput: largeInput({
        remainingMs: () => {
          throw new Error('clock unavailable');
        },
      }),
    });
    try {
      const result = await rt.capture({
        kind: 'prompt',
        sourceTool: 'claude-code',
        text: LARGE_TEXT,
      });
      expect(result).toMatchObject({ action: 'block', scanIncomplete: 'timeout' });
    } finally {
      await rt.close();
    }
  });
});

// A refused field was never scanned, so nothing is known about what it holds:
// it may carry a secret no rule got to see. With no findings there is nothing
// to mask, and the ordinary at-rest path would store the text verbatim. These
// cases read back everything the capture produced and require the raw text to
// be in none of it.
describe('a refused capture at rest', () => {
  // The well-known fabricated AWS example key id, composed so the repo's own
  // secret scanning does not flag this file.
  const KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const TEXT = `${'lorem ipsum dolor sit amet '.repeat(20)} aws_access_key_id = ${KEY}`;

  it.each(['always', 'with-findings'] as const)(
    'stores no raw text with persist %s, and keeps the hash of the original',
    async (persist) => {
      const stderrLines: string[] = [];
      vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
        stderrLines.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
        return true;
      });
      const { gateway, records } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        scanIsolation: { workerUrl: ENDLESS_WORKER },
        largeInput: largeInput(),
      });
      try {
        const result = await rt.capture(
          { kind: 'tool_use', sourceTool: 'claude-code', text: TEXT },
          { persist },
        );
        expect(result.scanIncomplete).toBe('timeout');
        expect(result.text).toBeNull();
        expect(JSON.stringify(result)).not.toContain(KEY);

        expect(records).toHaveLength(1);
        const record = records[0];
        // The row says WHY it is empty: without the marker a refused field
        // reads as a clean capture whose content happened to be ''.
        expect(record?.event.metadata?.scanIncomplete).toBe('timeout');
        expect(record?.event.content).toBe('');
        expect(record?.event.contentHash).toBe(contentHashOf(TEXT));
        expect(record?.findings).toEqual([]);
        const stored = JSON.stringify(record);
        expect(stored).not.toContain(KEY);
        expect(stored).not.toContain('lorem ipsum');

        const written = stderrLines.join('');
        // The refusal does say something on stderr, so this is not vacuous.
        expect(written).toContain('refused');
        expect(written).not.toContain(KEY);
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'still stores a scanned large field as before',
    async () => {
      // The control: the blanking is keyed on the refusal, not on the size or
      // the bounded path, so a large field that WAS scanned keeps its content.
      const { gateway, records } = fakeGateway();
      const rt = createPluginRuntime(gateway, settings(), {
        largeInput: largeInput({ budgetMs: 20_000 }),
        scanIsolation: { startBudgetMs: START_MS },
      });
      try {
        const result = await rt.capture({
          kind: 'prompt',
          sourceTool: 'claude-code',
          text: LARGE_TEXT,
        });
        expect(result).not.toHaveProperty('scanIncomplete');
        expect(records[0]?.event.content).toBe(LARGE_TEXT);
        expect(records[0]?.event.metadata?.scanIncomplete).toBeUndefined();
      } finally {
        await rt.close();
      }
    },
    CASE_TIMEOUT_MS,
  );
});
