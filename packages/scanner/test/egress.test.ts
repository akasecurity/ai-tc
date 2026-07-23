import { mkdirSync, mkdtempSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import type { PluginConfig, RecordProjectEgressInput } from '@akasecurity/plugin-sdk';
import { loadConfig, manifestKindOf, resolveNonGitProject, toPosix } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scanWorktree } from '../src/scan.ts';

const {
  capture,
  close,
  rulesetFingerprint,
  knownContentHashes,
  scanLedger,
  recordScanned,
  openAtRestKeysForPath,
  resolvedAtRestKeysForPath,
  insertResolution,
  recordProjectEgress,
  versionMaterial,
} = vi.hoisted(() => ({
  capture: vi.fn(),
  close: vi.fn(),
  rulesetFingerprint: vi.fn(),
  knownContentHashes: vi.fn(),
  scanLedger: vi.fn(),
  recordScanned: vi.fn(),
  openAtRestKeysForPath: vi.fn(),
  resolvedAtRestKeysForPath: vi.fn(),
  insertResolution: vi.fn(),
  recordProjectEgress: vi.fn(),
  // Mutable so a test can simulate an extractor/registry change between scans.
  versionMaterial: { value: 'extractor-1\n[]' },
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
  // A getter, so `versionMaterial.value` is re-read on every scan rather than
  // frozen at module-mock time.
  get EGRESS_VERSION_MATERIAL() {
    return versionMaterial.value;
  },
}));

// Mirrors the real scan_ledger: ONE row per path, whose ruleset hash is
// overwritten on every write, and reads filtered to one ruleset hash. A
// multi-version fake would hide exactly the staleness this suite must prove.
interface LedgerRow {
  mtime: string;
  contentHash: string;
  rulesetHash: string;
}
let ledgerRows: Map<string, LedgerRow>;

let tmp: string;
let repo: string;
let home: string;

const ORIGIN_URL = 'https://github.com/acme/payments-api.git';

function gitRepo(dir: string, url = ORIGIN_URL): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n`,
  );
}

function write(root: string, rel: string, content: string): void {
  const full = join(root, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

// A settings.json under a temp ~/.aka base, read back through the real loader
// so the toggle cases exercise the production read path.
function configWith(dataSharesInPlace: boolean): PluginConfig {
  write(home, join('settings', 'settings.json'), JSON.stringify({ dataSharesInPlace }));
  return loadConfig(home);
}

function egressInputs(): RecordProjectEgressInput[] {
  return recordProjectEgress.mock.calls.map(([input]) => input as RecordProjectEgressInput);
}

function lastEgressInput(): RecordProjectEgressInput {
  const inputs = egressInputs();
  const last = inputs.at(-1);
  if (!last) throw new Error('recordProjectEgress was never called');
  return last;
}

function scannedFilesOf(input: RecordProjectEgressInput): string[] {
  if (input.reconcile.mode !== 'ledger')
    throw new Error(`expected ledger mode, got ${input.reconcile.mode}`);
  return [...input.reconcile.scannedFiles].sort();
}

// Ledger rows are keyed on absolute native paths. Compare them as repo-relative
// posix keys — stripping a hardcoded '/' prefix cannot produce those on a
// backslash-separator host.
function ledgerKeys(): string[] {
  return [...ledgerRows.keys()].map((p) => toPosix(relative(repo, p)));
}

function deletedFilesOf(input: RecordProjectEgressInput): string[] {
  if (input.reconcile.mode !== 'ledger')
    throw new Error(`expected ledger mode, got ${input.reconcile.mode}`);
  return [...input.reconcile.deletedFiles].sort();
}

beforeEach(() => {
  vi.clearAllMocks();
  versionMaterial.value = 'extractor-1\n[]';
  ledgerRows = new Map();

  capture.mockResolvedValue({ action: 'allow', text: null, findings: [] });
  close.mockResolvedValue(undefined);
  rulesetFingerprint.mockResolvedValue('ruleset-v1');
  knownContentHashes.mockImplementation(() => Promise.resolve(new Set<string>()));
  openAtRestKeysForPath.mockResolvedValue([]);
  resolvedAtRestKeysForPath.mockResolvedValue([]);
  insertResolution.mockResolvedValue(undefined);
  recordProjectEgress.mockResolvedValue({
    destinations: 0,
    endpoints: 0,
    callSites: 0,
    truncated: false,
    droppedFiles: [],
  });

  scanLedger.mockImplementation((rulesetHash: string) =>
    Promise.resolve(
      new Map(
        [...ledgerRows]
          .filter(([, row]) => row.rulesetHash === rulesetHash)
          .map(([path, row]) => [path, { mtime: row.mtime, contentHash: row.contentHash }]),
      ),
    ),
  );
  recordScanned.mockImplementation((entries: LedgerRow[] & { path: string }[]) => {
    for (const entry of entries) {
      ledgerRows.set(entry.path, {
        mtime: entry.mtime,
        contentHash: entry.contentHash,
        rulesetHash: entry.rulesetHash,
      });
    }
    return Promise.resolve();
  });

  tmp = mkdtempSync(join(tmpdir(), 'aka-egress-test-'));
  repo = join(tmp, 'repo');
  home = join(tmp, 'home');
  mkdirSync(repo, { recursive: true });
  mkdirSync(home, { recursive: true });
  gitRepo(repo);
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

const STRIPE_CALL = "await fetch('https://api.stripe.com/v1/charges', { method: 'POST' });\n";
const STRIPE_MANIFEST = JSON.stringify({ dependencies: { stripe: '^14.0.0' } }, null, 2);

describe('scanWorktree — egress extraction (fresh scan)', () => {
  it('records code hits, manifest SDK hits and repo-relative posix keys in one ledger-mode call', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);
    // Skipped by the shared SKIP_DIRS floor on BOTH walks — the source walk and
    // the manifest walk.
    write(repo, 'node_modules/evil/index.js', "fetch('https://api.openai.com/v1/chat')\n");
    write(
      repo,
      'node_modules/evil/package.json',
      JSON.stringify({ dependencies: { openai: '^4' } }),
    );

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(1);
    const input = lastEgressInput();

    expect(input.projectKey).toBe(`git:${ORIGIN_URL}`);
    expect(input.project).toBe('payments-api');
    expect(input.projectId).toBeNull();
    expect(input.reconcile.mode).toBe('ledger');

    expect(scannedFilesOf(input)).toEqual(['pkg/package.json', 'src/pay.ts']);
    expect(deletedFilesOf(input)).toEqual([]);

    expect(
      input.hits.some((h) => h.site.file === 'src/pay.ts' && h.host === 'api.stripe.com'),
    ).toBe(true);
    expect(input.hits.some((h) => h.site.file === 'pkg/package.json' && h.method === 'SDK')).toBe(
      true,
    );
    // Nothing under node_modules reached either the ledger or the hit list.
    expect(input.hits.some((h) => h.site.file.includes('node_modules'))).toBe(false);
  });
});

describe('scanWorktree — egress relativization', () => {
  it('keys a subdirectory-rooted scan exactly like a root scan (worktree root, not the scan root)', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);
    const config = configWith(true);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    const rootKeys = new Set(scannedFilesOf(lastEgressInput()));
    const rootHitFiles = new Set(lastEgressInput().hits.map((h) => h.site.file));

    // Fresh ledger + fresh dedup state, then scan rooted INSIDE the repo.
    ledgerRows = new Map();
    recordProjectEgress.mockClear();
    await scanWorktree(config, { rootDir: join(repo, 'src'), sourceTool: 'claude-code' });

    const subInput = lastEgressInput();
    expect(subInput.projectKey).toBe(`git:${ORIGIN_URL}`);
    // 'src/pay.ts', never 'pay.ts' — the key is relative to the worktree root.
    expect(scannedFilesOf(subInput)).toContain('src/pay.ts');
    for (const key of scannedFilesOf(subInput)) expect(rootKeys).toContain(key);
    for (const hit of subInput.hits) expect(rootHitFiles).toContain(hit.site.file);
  });

  it('confines the manifest walk to the scan root, like the source walk and the sweep', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/package.json', STRIPE_MANIFEST);
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);

    await scanWorktree(configWith(true), { rootDir: join(repo, 'src'), sourceTool: 'claude-code' });

    const keys = scannedFilesOf(lastEgressInput());
    // In-scope manifest is collected, still keyed on the worktree root.
    expect(keys).toContain('src/package.json');
    // A manifest outside the scan target is neither read nor reconciled: the
    // deletion sweep is scoped to rootDir, so it could never clear those rows
    // later, and a ledger-mode write would treat them as an unvisited universe.
    expect(keys).not.toContain('pkg/package.json');
  });
});

describe('scanWorktree — egress ledger reuse', () => {
  it('makes no egress call when every file is unchanged since the last scan', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);
  });

  it('carries a deleted file in deletedFiles on the scan that first sees it gone', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);

    unlinkSync(join(repo, 'src', 'pay.ts'));
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    const input = lastEgressInput();
    expect(deletedFilesOf(input)).toEqual(['src/pay.ts']);
    expect(scannedFilesOf(input)).toEqual([]);
  });
});

describe('scanWorktree — egress at the read point', () => {
  it('records BOTH duplicate-content files, including the one tier-3 dedup skips for capture', async () => {
    write(repo, 'src/a.ts', STRIPE_CALL);
    write(repo, 'src/b.ts', STRIPE_CALL);

    const summary = await scanWorktree(configWith(true), {
      rootDir: repo,
      sourceTool: 'claude-code',
    });

    // The second file never reaches capture — identical content, no open
    // at-rest keys — yet its egress must still be recorded.
    expect(summary.scanned).toBe(1);
    expect(summary.skipped).toBe(1);

    const input = lastEgressInput();
    expect(scannedFilesOf(input)).toEqual(['src/a.ts', 'src/b.ts']);
    const hitFiles = new Set(input.hits.map((h) => h.site.file));
    expect(hitFiles).toContain('src/a.ts');
    expect(hitFiles).toContain('src/b.ts');
  });
});

describe('scanWorktree — egress write failure ordering', () => {
  it('skips the ledger commit when the egress write fails, and retries on the next scan', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);
    recordProjectEgress.mockRejectedValueOnce(new Error('SQLITE_BUSY'));

    await expect(
      scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' }),
    ).resolves.toBeDefined();

    expect(recordProjectEgress).toHaveBeenCalledTimes(1);
    // The ledger must NOT advance — otherwise the file is never re-read and its
    // egress is lost forever.
    expect(recordScanned).not.toHaveBeenCalled();
    expect(ledgerRows.size).toBe(0);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    expect(scannedFilesOf(lastEgressInput())).toEqual(['src/pay.ts']);
    expect(recordScanned).toHaveBeenCalledTimes(1);
  });

  // A write can succeed while still declining part of its input. A file whose
  // hits the cap dropped keeps its stored rows, so ledgering it would tier-1
  // skip it on every later scan and its egress would never be written at all.
  it('withholds the ledger entry for a file the write dropped, and re-reads it next scan', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/big.ts', STRIPE_CALL);
    const config = configWith(true);

    recordProjectEgress.mockResolvedValueOnce({
      destinations: 1,
      endpoints: 1,
      callSites: 1,
      truncated: true,
      droppedFiles: ['src/big.ts'],
    });

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    // The recorded file advances; the dropped one does not.
    expect(ledgerKeys()).toEqual(['src/pay.ts']);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    // Second scan re-reads only the withheld file — the ledgered one tier-1 skips.
    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    expect(scannedFilesOf(lastEgressInput())).toEqual(['src/big.ts']);
  });

  it('advances the whole ledger batch when the write drops nothing', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/big.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(ledgerKeys().sort()).toEqual(['src/big.ts', 'src/pay.ts']);
  });
});

describe('scanWorktree — egress-versioned ledger key', () => {
  it('re-extracts every previously ledgered file when the extraction version material changes', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);

    // Nothing on disk changes — only the extractor/registry material.
    versionMaterial.value = 'extractor-2\n[]';
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    expect(scannedFilesOf(lastEgressInput())).toEqual(['src/pay.ts']);
  });
});

describe('scanWorktree — manifest walk honors .akaignore', () => {
  it("a manifest inside an .akaignore'd directory produces no egress hit and no scannedFiles entry", async () => {
    write(repo, '.akaignore', 'ignored/\n');
    write(repo, 'ignored/package.json', STRIPE_MANIFEST);
    // Kept non-ignored so the run still calls recordProjectEgress at all —
    // otherwise an empty run short-circuits before the assertion means anything.
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    const input = lastEgressInput();
    expect(scannedFilesOf(input)).toEqual(['src/pay.ts']);
    expect(input.hits.some((h) => h.site.file.startsWith('ignored/'))).toBe(false);
  });

  it('an !vendor/ negation re-includes a vendor/ manifest, matching the source walk', async () => {
    write(repo, '.akaignore', '!vendor/\n');
    write(repo, 'vendor/firstparty/package.json', STRIPE_MANIFEST);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    const input = lastEgressInput();
    expect(scannedFilesOf(input)).toContain('vendor/firstparty/package.json');
    expect(
      input.hits.some(
        (h) => h.site.file === 'vendor/firstparty/package.json' && h.method === 'SDK',
      ),
    ).toBe(true);
  });

  it('a manifest outside any ignore rule is still collected (guard against over-broad ignoring)', async () => {
    write(repo, '.akaignore', 'ignored/\n');
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    const input = lastEgressInput();
    expect(scannedFilesOf(input)).toContain('pkg/package.json');
    expect(input.hits.some((h) => h.site.file === 'pkg/package.json' && h.method === 'SDK')).toBe(
      true,
    );
  });
});

describe('scanWorktree — non-git project boundary (subtree convergence)', () => {
  it('keys a subtree scan exactly like a root scan for a non-git, manifest-anchored project', async () => {
    // A non-git tree (no .git) anchored by package.json. The plugin scanner and
    // the CLI/web-ui pipeline both derive this from the shared resolveNonGitProject,
    // so their key and relative paths match byte for byte.
    const proj = join(tmp, 'proj');
    mkdirSync(proj, { recursive: true });
    write(proj, 'package.json', STRIPE_MANIFEST);
    write(proj, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);

    const expectedKey = `path:${realpathSync(proj)}`;
    expect(resolveNonGitProject(proj, manifestKindOf).projectKey).toBe(expectedKey);

    await scanWorktree(config, { rootDir: proj, sourceTool: 'claude-code' });
    const rootInput = lastEgressInput();
    expect(rootInput.projectKey).toBe(expectedKey);
    expect(rootInput.hits.some((h) => h.site.file === 'src/pay.ts')).toBe(true);

    // Fresh ledger + call log, then scan rooted INSIDE the project at src/.
    ledgerRows = new Map();
    recordProjectEgress.mockClear();
    await scanWorktree(config, { rootDir: join(proj, 'src'), sourceTool: 'claude-code' });

    const subInput = lastEgressInput();
    // Same key as the root scan — the subtree no longer mints `path:.../src`.
    expect(subInput.projectKey).toBe(expectedKey);
    // 'src/pay.ts', never a bare 'pay.ts': relative to the resolved project root.
    expect(subInput.hits.some((h) => h.site.file === 'src/pay.ts')).toBe(true);
    expect(subInput.hits.every((h) => h.site.file !== 'pay.ts')).toBe(true);
  });
});

describe('scanWorktree — Data Shares kill-switch', () => {
  it('skips the egress write but still advances the ledger when the toggle is off', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(false), { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).not.toHaveBeenCalled();
    // A deliberate skip must never freeze the ledger — that would re-read every
    // file on every scan for as long as the toggle stays off.
    expect(recordScanned).toHaveBeenCalledTimes(1);
    expect(ledgerRows.size).toBe(1);
  });

  it('re-extracts previously ledgered files when the toggle is turned back on', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);

    // Ledger keeps advancing while the toggle is off.
    await scanWorktree(configWith(false), { rootDir: repo, sourceTool: 'claude-code' });
    expect(recordProjectEgress).toHaveBeenCalledTimes(1);
    expect(ledgerRows.size).toBe(1);

    // Nothing on disk touched: the toggle state is folded into the ledger
    // fingerprint, so the re-enabled scan re-reads and records anyway.
    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    expect(scannedFilesOf(lastEgressInput())).toEqual(['src/pay.ts']);
  });
});
