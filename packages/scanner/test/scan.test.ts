import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CaptureInput, PluginConfig, ScanLedgerEntry } from '@akasecurity/plugin-sdk';
import { contentHashOf } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scanAllRepos, scanWorktree } from '../src/scan.ts';

const {
  capture,
  close,
  knownContentHashes,
  rulesetFingerprint,
  scanLedger,
  recordScanned,
  openAtRestKeysForPath,
  resolvedAtRestKeysForPath,
  insertResolution,
  recordProjectEgress,
} = vi.hoisted(() => ({
  capture: vi.fn(),
  close: vi.fn(),
  knownContentHashes: vi.fn(),
  rulesetFingerprint: vi.fn(),
  scanLedger: vi.fn(),
  recordScanned: vi.fn(),
  openAtRestKeysForPath: vi.fn(),
  resolvedAtRestKeysForPath: vi.fn(),
  insertResolution: vi.fn(),
  recordProjectEgress: vi.fn(),
}));

vi.mock('@akasecurity/plugin-runtime', () => ({
  resolveDataGateway: vi.fn(() => ({
    knownContentHashes,
    scanLedger,
    recordScanned,
    openAtRestKeysForPath,
    resolvedAtRestKeysForPath,
    insertResolution,
    recordProjectEgress,
  })),
}));

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  createPluginRuntime: vi.fn(() => ({ capture, close, rulesetFingerprint })),
}));

// dataSharesInPlace mirrors the schema default, so this suite exercises the
// same egress-enabled path a real scan takes. The egress writes themselves are
// asserted in ./egress.test.ts.
const config = { settings: { dataSharesInPlace: true } } as PluginConfig;

function capturedInputs(): CaptureInput[] {
  return capture.mock.calls.map(([input]) => input as CaptureInput);
}

function recordedEntries(): ScanLedgerEntry[] {
  return recordScanned.mock.calls.flatMap(([entries]) => entries as ScanLedgerEntry[]);
}

// Mirrors persistence's ResolutionInput shape structurally — the scanner
// package doesn't depend on @akasecurity/persistence directly, so this
// stays a plain local type rather than importing one just for test typing.
interface ResolutionCall {
  findingKey: string;
  status: string;
  method: string;
  resolvedAt: number;
  evidence: string;
}

function insertedResolutions(): ResolutionCall[] {
  return insertResolution.mock.calls.map(([input]) => input as ResolutionCall);
}

let tmp: string;

beforeEach(() => {
  vi.clearAllMocks();
  capture.mockResolvedValue({ action: 'allow', text: null, findings: [] });
  close.mockResolvedValue(undefined);
  // Fresh set per call: the scanner mutates it, and clean files never become
  // events, so the real gateway would not remember them across runs.
  knownContentHashes.mockImplementation(() => Promise.resolve(new Set<string>()));
  rulesetFingerprint.mockResolvedValue('ruleset-v1');
  scanLedger.mockResolvedValue(new Map());
  recordScanned.mockResolvedValue(undefined);
  recordProjectEgress.mockResolvedValue({
    destinations: 0,
    endpoints: 0,
    callSites: 0,
    truncated: false,
    droppedFiles: [],
  });
  // No prior open at-rest findings by default — most tests don't care about
  // the resolver, so this keeps computeResolutions() a no-op (empty diff)
  // unless a test explicitly seeds a prior key.
  openAtRestKeysForPath.mockResolvedValue([]);
  // No redetect candidates by default — most tests don't care about the
  // redetect side, so this keeps reopenRedetectedFindings a no-op unless a
  // test explicitly seeds a resolved key.
  resolvedAtRestKeysForPath.mockResolvedValue([]);
  insertResolution.mockResolvedValue(undefined);
  tmp = mkdtempSync(join(tmpdir(), 'aka-scan-test-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const full = join(tmp, rel);
  mkdirSync(full.slice(0, full.lastIndexOf('/')), { recursive: true });
  writeFileSync(full, content);
}

describe('scanWorktree — provenance', () => {
  it('stamps every captured file with the caller-supplied sourceTool', async () => {
    write('src/a.ts', 'const a = 1;');
    write('src/b.ts', 'const b = 2;');

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'cursor' });

    const inputs = capturedInputs();
    expect(inputs).toHaveLength(2);
    for (const input of inputs) {
      expect(input.sourceTool).toBe('cursor');
      expect(input.kind).toBe('code_change');
    }
  });

  it('threads a different sourceTool untouched', async () => {
    write('src/a.ts', 'const a = 1;');

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'github-copilot' });

    expect(capturedInputs().map((i) => i.sourceTool)).toEqual(['github-copilot']);
  });
});

describe('scanWorktree — scan ledger', () => {
  // The ledger key is a hash DERIVED from the ruleset fingerprint combined with
  // the egress extraction material, not the bare fingerprint — so an extractor
  // or registry change invalidates the ledger exactly like a new rule pack does.
  it('keys the ledger on a derived hash that moves with the ruleset fingerprint', async () => {
    write('src/a.ts', 'const a = 1;');

    rulesetFingerprint.mockResolvedValue('ruleset-v42');
    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    const keyV42 = scanLedger.mock.calls.at(-1)?.[0] as string;

    rulesetFingerprint.mockResolvedValue('ruleset-v43');
    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    const keyV43 = scanLedger.mock.calls.at(-1)?.[0] as string;

    expect(keyV42).toMatch(/^[0-9a-f]{64}$/);
    expect(keyV42).not.toBe('ruleset-v42');
    expect(keyV43).not.toBe(keyV42);
  });

  it('records a ledger entry for every processed file — including clean ones', async () => {
    write('src/a.ts', 'const a = 1;');
    write('src/b.ts', 'const b = 2;');

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    const entries = recordedEntries();
    expect(entries.map((e) => e.path).sort()).toEqual([
      join(tmp, 'src/a.ts'),
      join(tmp, 'src/b.ts'),
    ]);
    // Entries must be written under exactly the key the ledger was READ with —
    // if the two ever diverged, every scan would miss and re-read the whole tree.
    const readKey = scanLedger.mock.calls.at(-1)?.[0] as string;
    for (const entry of entries) {
      expect(entry.rulesetHash).toBe(readKey);
      expect(entry.contentHash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.mtime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('skips unchanged files (same mtime) without re-running detection', async () => {
    write('src/a.ts', 'const a = 1;');

    // First run populates the ledger; feed its entries back as the prior state.
    const first = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    expect(first.scanned).toBe(1);
    const prior = new Map(
      recordedEntries().map((e) => [e.path, { mtime: e.mtime, contentHash: e.contentHash }]),
    );
    scanLedger.mockResolvedValue(prior);
    capture.mockClear();

    const second = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(capture).not.toHaveBeenCalled();
    expect(second.scanned).toBe(0);
    expect(second.skipped).toBe(1);
  });

  it('skips detection on an mtime-only touch (same content hash) and refreshes the ledger', async () => {
    write('src/a.ts', 'const a = 1;');
    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    const entry = recordedEntries()[0];
    expect(entry).toBeDefined();
    if (!entry) return;
    scanLedger.mockResolvedValue(
      new Map([[entry.path, { mtime: entry.mtime, contentHash: entry.contentHash }]]),
    );
    capture.mockClear();
    recordScanned.mockClear();

    // Bump mtime without changing content.
    const touched = new Date(Date.now() + 60_000);
    utimesSync(entry.path, touched, touched);

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(capture).not.toHaveBeenCalled();
    expect(summary.skipped).toBe(1);
    // The refreshed entry carries the NEW mtime so the next run skips at tier 1.
    const refreshed = recordedEntries().find((e) => e.path === entry.path);
    expect(refreshed?.mtime).not.toBe(entry.mtime);
    expect(refreshed?.contentHash).toBe(entry.contentHash);
  });

  it('rescans a file whose content changed', async () => {
    write('src/a.ts', 'const a = 1;');
    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    const entry = recordedEntries()[0];
    expect(entry).toBeDefined();
    if (!entry) return;
    scanLedger.mockResolvedValue(
      new Map([[entry.path, { mtime: entry.mtime, contentHash: entry.contentHash }]]),
    );
    capture.mockClear();

    write('src/a.ts', 'const a = 2; // changed');
    const touched = new Date(Date.now() + 60_000);
    utimesSync(entry.path, touched, touched);

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(capture).toHaveBeenCalledTimes(1);
    expect(summary.scanned).toBe(1);
  });

  it('rescans everything when the ruleset fingerprint changes (gateway returns no entries)', async () => {
    write('src/a.ts', 'const a = 1;');
    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    const firstKey = scanLedger.mock.calls.at(-1)?.[0] as string;
    capture.mockClear();

    // A new rule pack: the fingerprint moves, and the gateway (which filters by
    // ruleset hash) returns an empty ledger — everything is a miss again.
    rulesetFingerprint.mockResolvedValue('ruleset-v2');
    scanLedger.mockResolvedValue(new Map());

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    const secondKey = scanLedger.mock.calls.at(-1)?.[0] as string;
    expect(secondKey).not.toBe(firstKey);
    expect(capture).toHaveBeenCalledTimes(1);
    expect(summary.scanned).toBe(1);
    expect(recordedEntries().at(-1)?.rulesetHash).toBe(secondKey);
  });

  it('ledgers files skipped by the cross-repo content-hash dedup', async () => {
    write('src/a.ts', 'const same = 1;');
    write('src/b.ts', 'const same = 1;');

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(summary.scanned).toBe(1);
    expect(summary.skipped).toBe(1);
    // Both paths land in the ledger so the next run skips both by mtime.
    expect(recordedEntries()).toHaveLength(2);
  });
});

describe('scanWorktree — re-scan resolver', () => {
  it('auto-resolves a prior at-rest finding when a re-scan of its file finds nothing there', async () => {
    write('src/a.ts', 'const a = 1; // secret removed');
    openAtRestKeysForPath.mockResolvedValue(['key-a']);
    capture.mockResolvedValue({ action: 'log', text: 'const a = 1;', findings: [] });

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(openAtRestKeysForPath).toHaveBeenCalledWith(join(tmp, 'src/a.ts'));
    expect(insertedResolutions()).toHaveLength(1);
    const call = insertedResolutions()[0];
    expect(call).toMatchObject({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
    });
    expect(typeof call?.resolvedAt).toBe('number');
    const evidence = JSON.parse(call?.evidence ?? '{}') as { contentHash?: string };
    expect(evidence.contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('leaves an unrelated prior key open when the finding it belongs to still reproduces', async () => {
    write('src/a.ts', 'const secret = "still-here";');
    openAtRestKeysForPath.mockResolvedValue(['key-a']);
    capture.mockResolvedValue({
      action: 'log',
      text: 'const secret = "still-here";',
      findings: [{ ruleId: 'secrets/x', severity: 'high', category: 'secret' }],
      findingKeys: ['key-a'],
    });

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(insertResolution).not.toHaveBeenCalled();
  });

  it('resolves a prior at-rest finding when its file has been deleted, with deleted evidence', async () => {
    const gonePath = join(tmp, 'src/gone.ts');
    scanLedger.mockResolvedValue(
      new Map([[gonePath, { mtime: '2020-01-01T00:00:00.000Z', contentHash: 'deadbeef' }]]),
    );
    openAtRestKeysForPath.mockImplementation((path: string) =>
      Promise.resolve(path === gonePath ? ['key-b'] : []),
    );

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(openAtRestKeysForPath).toHaveBeenCalledWith(gonePath);
    expect(insertedResolutions()).toHaveLength(1);
    const call = insertedResolutions()[0];
    expect(call).toMatchObject({
      findingKey: 'key-b',
      status: 'resolved',
      method: 'fixed-at-source',
    });
    const evidence = JSON.parse(call?.evidence ?? '{}') as { deleted?: boolean };
    expect(evidence).toEqual({ deleted: true });
  });

  it('rotation: resolves the old key and never resolves the newly opened key', async () => {
    write('src/a.ts', 'const secret = "rotated-value";');
    openAtRestKeysForPath.mockResolvedValue(['key-old']);
    capture.mockResolvedValue({
      action: 'log',
      text: 'const secret = "rotated-value";',
      findings: [{ ruleId: 'secrets/x', severity: 'high', category: 'secret' }],
      findingKeys: ['key-new'],
    });

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(insertResolution).toHaveBeenCalledTimes(1);
    expect(insertResolution).toHaveBeenCalledWith(
      expect.objectContaining({ findingKey: 'key-old', method: 'fixed-at-source' }),
    );
    expect(insertResolution).not.toHaveBeenCalledWith(
      expect.objectContaining({ findingKey: 'key-new' }),
    );
  });

  it('re-opens a redetected finding whose key was previously resolved (secret removed, then re-added identically)', async () => {
    write('src/a.ts', 'const secret = "aws-key-value";');
    // Not in the open backlog: its latest disposition was 'resolved' (a prior
    // scan saw the secret gone and marked it fixed-at-source) — but this scan
    // detects it again at the same path with the same finding_key.
    openAtRestKeysForPath.mockResolvedValue([]);
    resolvedAtRestKeysForPath.mockResolvedValue(['key-a']);
    capture.mockResolvedValue({
      action: 'log',
      text: 'const secret = "aws-key-value";',
      findings: [{ ruleId: 'secrets/x', severity: 'high', category: 'secret' }],
      findingKeys: ['key-a'],
    });

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(resolvedAtRestKeysForPath).toHaveBeenCalledWith(join(tmp, 'src/a.ts'));
    expect(insertedResolutions()).toHaveLength(1);
    const call = insertedResolutions()[0];
    expect(call).toMatchObject({
      findingKey: 'key-a',
      status: 'open',
      method: 'redetected',
    });
    expect(typeof call?.resolvedAt).toBe('number');
    const evidence = JSON.parse(call?.evidence ?? '{}') as {
      reason?: string;
      contentHash?: string;
    };
    expect(evidence.reason).toBe('redetected');
    expect(evidence.contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not re-open a brand-new finding_key with no resolution history', async () => {
    write('src/a.ts', 'const secret = "never-seen-before";');
    capture.mockResolvedValue({
      action: 'log',
      text: 'const secret = "never-seen-before";',
      findings: [{ ruleId: 'secrets/x', severity: 'high', category: 'secret' }],
      findingKeys: ['key-fresh'],
    });
    // Default mocks: openAtRestKeysForPath => [], resolvedAtRestKeysForPath => []
    // (never resolved, so nothing to re-open — it's already implicitly open).

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(insertResolution).not.toHaveBeenCalled();
  });

  it('does no resolver work for a file skipped as unchanged (tier-1 mtime match)', async () => {
    write('src/a.ts', 'const a = 1;');
    const first = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });
    expect(first.scanned).toBe(1);
    const prior = new Map(
      recordedEntries().map((e) => [e.path, { mtime: e.mtime, contentHash: e.contentHash }]),
    );
    scanLedger.mockResolvedValue(prior);
    openAtRestKeysForPath.mockClear();
    resolvedAtRestKeysForPath.mockClear();
    insertResolution.mockClear();

    const second = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(second.skipped).toBe(1);
    expect(openAtRestKeysForPath).not.toHaveBeenCalled();
    expect(resolvedAtRestKeysForPath).not.toHaveBeenCalled();
    expect(insertResolution).not.toHaveBeenCalled();
  });

  it('content-hash dedup (tier 3) does not starve the resolver: a changed file whose new content matches a known hash is still scanned while it has open keys', async () => {
    // a.ts's secret was deleted, leaving content byte-identical to an already
    // recorded clean file — its hash is in knownContentHashes, so without the
    // open-key check the tier-3 dedup would skip capture() AND the resolver,
    // stranding key-a open forever.
    const cleaned = 'const a = 1;';
    write('src/a.ts', cleaned);
    knownContentHashes.mockImplementation(() => Promise.resolve(new Set([contentHashOf(cleaned)])));
    openAtRestKeysForPath.mockResolvedValue(['key-a']);
    capture.mockResolvedValue({ action: 'log', text: cleaned, findings: [] });

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(summary.scanned).toBe(1);
    expect(capture).toHaveBeenCalledTimes(1);
    expect(insertedResolutions()).toHaveLength(1);
    expect(insertedResolutions()[0]).toMatchObject({
      findingKey: 'key-a',
      status: 'resolved',
      method: 'fixed-at-source',
    });
  });

  it('content-hash dedup (tier 3) still skips a known-content file with no open keys', async () => {
    const clean = 'const a = 1;';
    write('src/a.ts', clean);
    knownContentHashes.mockImplementation(() => Promise.resolve(new Set([contentHashOf(clean)])));
    // Default openAtRestKeysForPath => [] — nothing open on this path.

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    expect(summary.skipped).toBe(1);
    expect(capture).not.toHaveBeenCalled();
    expect(insertResolution).not.toHaveBeenCalled();
  });
});

describe('scanAllRepos', () => {
  it('stamps discovered-repo captures with the caller-supplied sourceTool', async () => {
    write('repo/src/a.ts', 'const a = 1;');
    mkdirSync(join(tmp, 'repo/.git'), { recursive: true });

    const summary = await scanAllRepos(config, {
      searchRoots: [tmp],
      sourceTool: 'cursor',
    });

    expect(summary.repos.map((r) => r.rootDir)).toEqual([join(tmp, 'repo')]);
    const inputs = capturedInputs();
    expect(inputs).toHaveLength(1);
    expect(inputs[0]?.sourceTool).toBe('cursor');
  });

  it('records ledger updates per repo (partial progress on a long sweep)', async () => {
    write('repo-a/src/a.ts', 'const a = 1;');
    write('repo-b/src/b.ts', 'const b = 2;');
    mkdirSync(join(tmp, 'repo-a/.git'), { recursive: true });
    mkdirSync(join(tmp, 'repo-b/.git'), { recursive: true });

    await scanAllRepos(config, { searchRoots: [tmp], sourceTool: 'claude-code' });

    // One recordScanned call per repo, not one for the whole sweep.
    expect(recordScanned).toHaveBeenCalledTimes(2);
    expect(recordedEntries()).toHaveLength(2);
  });

  it('skips unchanged repos entirely on a re-run', async () => {
    write('repo/src/a.ts', 'const a = 1;');
    mkdirSync(join(tmp, 'repo/.git'), { recursive: true });
    await scanAllRepos(config, { searchRoots: [tmp], sourceTool: 'claude-code' });
    scanLedger.mockResolvedValue(
      new Map(
        recordedEntries().map((e) => [e.path, { mtime: e.mtime, contentHash: e.contentHash }]),
      ),
    );
    capture.mockClear();

    const summary = await scanAllRepos(config, { searchRoots: [tmp], sourceTool: 'claude-code' });

    expect(capture).not.toHaveBeenCalled();
    expect(summary.totalScanned).toBe(0);
    expect(summary.totalSkipped).toBe(1);
  });
});

describe('record dedupe marker', () => {
  it("captures with dedupe: 'content-hash' so re-runs don't duplicate recorded content", async () => {
    write('src/a.ts', 'const a = 1;');

    await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    const opts = capture.mock.calls[0]?.[1] as { persist?: string; dedupe?: string } | undefined;
    expect(opts?.persist).toBe('with-findings');
    expect(opts?.dedupe).toBe('content-hash');
  });
});

describe('gitignored provenance', () => {
  it('stamps captures from gitignored files with metadata.gitignored and counts them', async () => {
    capture.mockResolvedValue({
      action: 'log',
      text: null,
      findings: [{ ruleId: 'secrets/x', severity: 'high', category: 'secret' }],
    });
    write('.gitignore', 'scratch.ts\n');
    write('scratch.ts', 'const local = 1;');
    write('src/app.ts', 'const app = 1;');

    const summary = await scanWorktree(config, { rootDir: tmp, sourceTool: 'claude-code' });

    const inputs = capturedInputs();
    const scratch = inputs.find((i) => i.metadata?.filePath?.endsWith('scratch.ts'));
    const app = inputs.find((i) => i.metadata?.filePath?.endsWith('app.ts'));
    expect(scratch?.metadata?.gitignored).toBe(true);
    // Omitted (not false) for tracked files.
    expect(app?.metadata?.gitignored).toBeUndefined();
    expect(summary.findings).toBe(2);
    expect(summary.gitignoredFindings).toBe(1);
  });
});
