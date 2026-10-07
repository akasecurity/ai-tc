import type * as NodeFs from 'node:fs';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import type {
  PluginConfig,
  ProjectEgressContext,
  RecordProjectEgressInput,
} from '@akasecurity/plugin-sdk';
import {
  contentHashOf,
  loadConfig,
  manifestKindOf,
  resolveNonGitProject,
  resolveRepoAttribution,
  toPosix,
} from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scanWorktree } from '../src/scan.ts';

const {
  capture,
  close,
  rulesetFingerprint,
  scanIsolationDegraded,
  knownContentHashes,
  scanLedger,
  scanLedgerPaths,
  scanLedgerPathKeys,
  gatewayShape,
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
  scanIsolationDegraded: vi.fn(() => false),
  knownContentHashes: vi.fn(),
  scanLedger: vi.fn(),
  scanLedgerPaths: vi.fn(),
  scanLedgerPathKeys: vi.fn(),
  // Whether the gateway offers the optional port method that lists each
  // ledgered path with its recorded repository.
  gatewayShape: { pathKeys: true },
  recordScanned: vi.fn(),
  openAtRestKeysForPath: vi.fn(),
  resolvedAtRestKeysForPath: vi.fn(),
  insertResolution: vi.fn(),
  recordProjectEgress: vi.fn(),
  // Mutable so a test can simulate an extractor/registry change between scans.
  versionMaterial: { value: 'extractor-1\n[]' },
}));

// A removal that lands between two reads. While `armed` names a path, the first
// `existsSync` that the scope-key lookup makes on it removes it from disk
// straight after answering true, as the last rmdir of a removal does between that
// lookup's check and its read. Only the lookup's own check counts: the scan
// checks the same `.git` for other reasons earlier, and a removal landing there
// is an ordinary one, not the race.
const race = vi.hoisted(() => ({ armed: undefined as string | undefined, fired: 0 }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof NodeFs>();
  const existsSync = (path: NodeFs.PathLike): boolean => {
    const exists = actual.existsSync(path);
    if (
      exists &&
      race.armed !== undefined &&
      String(path) === race.armed &&
      new Error('probe').stack?.includes('scope-key.ts')
    ) {
      race.armed = undefined;
      race.fired++;
      actual.rmSync(String(path), { recursive: true, force: true });
    }
    return exists;
  };
  return { ...actual, default: { ...actual, existsSync }, existsSync };
});

vi.mock('@akasecurity/plugin-runtime', () => ({
  resolveDataGateway: vi.fn(() => ({
    knownContentHashes,
    scanLedger,
    scanLedgerPaths,
    ...(gatewayShape.pathKeys ? { scanLedgerPathKeys } : {}),
    recordScanned,
    openAtRestKeysForPath,
    resolvedAtRestKeysForPath,
    insertResolution,
    recordProjectEgress,
  })),
}));

vi.mock('@akasecurity/plugin-sdk', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  createPluginRuntime: vi.fn(() => ({ capture, close, rulesetFingerprint, scanIsolationDegraded })),
  // A getter, so `versionMaterial.value` is re-read on every scan rather than
  // frozen at module-mock time.
  get EGRESS_VERSION_MATERIAL() {
    return versionMaterial.value;
  },
}));

// Mirrors the real scan_ledger: ONE row per path, whose ruleset hash is
// overwritten on every write, entry reads filtered to one ruleset hash, and a
// path read that is not. A multi-version fake would hide exactly the staleness
// this suite must prove.
interface LedgerRow {
  mtime: string;
  contentHash: string;
  rulesetHash: string;
  // The repository the file was in when it was last read, replaced on every
  // write like the real column.
  scopeKey: string | undefined;
  // The directory of that repository, replaced on every write like the key.
  scopeRoot: string | undefined;
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
  race.armed = undefined;
  race.fired = 0;
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
          .map(([path, row]) => [
            path,
            {
              mtime: row.mtime,
              contentHash: row.contentHash,
              ...(row.scopeKey !== undefined ? { scopeKey: row.scopeKey } : {}),
              ...(row.scopeRoot !== undefined ? { scopeRoot: row.scopeRoot } : {}),
            },
          ]),
      ),
    ),
  );
  scanLedgerPaths.mockImplementation(() => Promise.resolve([...ledgerRows.keys()]));
  gatewayShape.pathKeys = true;
  scanLedgerPathKeys.mockImplementation(() =>
    Promise.resolve(new Map([...ledgerRows].map(([path, row]) => [path, row.scopeKey]))),
  );
  recordScanned.mockImplementation((entries: (LedgerRow & { path: string })[]) => {
    for (const entry of entries) {
      ledgerRows.set(entry.path, {
        mtime: entry.mtime,
        contentHash: entry.contentHash,
        rulesetHash: entry.rulesetHash,
        scopeKey: entry.scopeKey,
        scopeRoot: entry.scopeRoot,
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

  it('sweeps a file deleted just before the version material changes', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/other.ts', STRIPE_CALL);
    const config = configWith(true);

    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
    unlinkSync(join(repo, 'src', 'pay.ts'));

    // The file's ledger row still carries the old hash when the new one lands.
    versionMaterial.value = 'extractor-2\n[]';
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    const input = lastEgressInput();
    expect(deletedFilesOf(input)).toEqual(['src/pay.ts']);
    expect(scannedFilesOf(input)).toEqual(['src/other.ts']);
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

describe('scanWorktree — repositories nested in the scanned project', () => {
  // The walks descend into a nested clone or submodule and fold its files into
  // this project's register. What the scanner hands the gateway BESIDE the
  // register is the scope key of every such repository the walk passed
  // through. The gateway decides with it; this suite pins what is reported.
  const PERSONAL_URL = 'https://github.com/me/personal.git';
  // An scp-style remote's userinfo reads as an email address to a scanner, so
  // it is built from parts.
  const AT = String.fromCharCode(64);
  const gitUser = `git${AT}`;
  const LIB_URL = `${gitUser}github.com:acme/lib.git`;
  const NOTIFY_CALL = "await fetch('https://api.github.com/repos/me/personal/dispatches');\n";

  function nestedKeysOfLastCall(): readonly (string | undefined)[] | undefined {
    const call = recordProjectEgress.mock.calls.at(-1) as
      [RecordProjectEgressInput, ProjectEgressContext | undefined] | undefined;
    if (call === undefined) throw new Error('recordProjectEgress was never called');
    return call[1]?.nestedScopeKeys;
  }

  // A repository whose config names no remote.
  function remotelessRepo(dir: string): void {
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), '[core]\n\tbare = false\n');
  }

  it("reports a nested clone's key, and leaves the register as it was", async () => {
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'tools/mine/notify.ts', NOTIFY_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual(['github.com/me/personal']);
    // Still folded in: the register is unchanged, and what decides whether it
    // may leave the machine travels beside it.
    expect(scannedFilesOf(lastEgressInput())).toContain('tools/mine/notify.ts');
    expect(lastEgressInput().projectKey).toBe(`git:${ORIGIN_URL}`);
  });

  it('reports a nested repository with no remote as keyless', async () => {
    remotelessRepo(join(repo, 'scratch'));
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'scratch/try.ts', NOTIFY_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual([undefined]);
  });

  it('keys a submodule by its own remote: a `.git` file marks a repository too', async () => {
    const modules = join(repo, '.git', 'modules', 'lib');
    mkdirSync(modules, { recursive: true });
    writeFileSync(join(modules, 'config'), `[remote "origin"]\n\turl = ${LIB_URL}\n`);
    write(repo, 'lib/index.ts', NOTIFY_CALL);
    writeFileSync(join(repo, 'lib', '.git'), 'gitdir: ../.git/modules/lib\n');
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual(['github.com/acme/lib']);
  });

  it('reports an empty list, never no list, for a project with nothing nested in it', async () => {
    // A scoped gateway reads a MISSING list as a register nobody vouched for,
    // so every scan says what it found, even when that is nothing.
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual([]);
  });

  it('reports a nested repository this run walked but did not read', async () => {
    // Walked, not read: the answer depends on the tree, not on which files
    // changed since the last scan. The second run re-reads only the new root
    // file, and the clone is still reported.
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'tools/mine/notify.ts', NOTIFY_CALL);
    const config = configWith(true);
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    write(repo, 'src/refund.ts', "await fetch('https://api.stripe.com/v1/refunds');\n");
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });

    expect(recordProjectEgress).toHaveBeenCalledTimes(2);
    expect(scannedFilesOf(lastEgressInput())).toEqual(['src/refund.ts']);
    expect(nestedKeysOfLastCall()).toEqual(['github.com/me/personal']);
  });

  it('reports a repository only the manifest walk reaches, whose manifest joins the register', async () => {
    // The host's excludePatterns narrow the SOURCE walk. The manifest walk
    // still lists the excluded directory and reads its manifests into this
    // register, so a repository in it is reported like any other.
    gitRepo(join(repo, 'legacy', 'old'), PERSONAL_URL);
    write(repo, 'legacy/old/package.json', STRIPE_MANIFEST);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), {
      rootDir: repo,
      sourceTool: 'claude-code',
      excludePatterns: ['legacy/'],
    });

    expect(scannedFilesOf(lastEgressInput())).toContain('legacy/old/package.json');
    expect(nestedKeysOfLastCall()).toEqual(['github.com/me/personal']);
  });

  it('reports nothing under a directory both walks skip', async () => {
    gitRepo(join(repo, 'node_modules', 'dep'), PERSONAL_URL);
    write(repo, 'node_modules/dep/index.js', NOTIFY_CALL);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual([]);
  });

  it('reports a repository nested inside a nested one, each by its own remote', async () => {
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    gitRepo(join(repo, 'tools', 'mine', 'deps', 'lib'), LIB_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    const keys = nestedKeysOfLastCall();
    expect(keys).toHaveLength(2);
    expect(keys).toContain('github.com/me/personal');
    expect(keys).toContain('github.com/acme/lib');
  });

  it("never reports the scan root's own repository, even one nested in another", async () => {
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    write(repo, 'tools/mine/notify.ts', NOTIFY_CALL);

    await scanWorktree(configWith(true), {
      rootDir: join(repo, 'tools', 'mine'),
      sourceTool: 'claude-code',
    });

    expect(lastEgressInput().projectKey).toBe(`git:${PERSONAL_URL}`);
    expect(nestedKeysOfLastCall()).toEqual([]);
  });

  it('reads no nested repository until the gateway asks for its key', async () => {
    // Only a scoped gateway reads the list. A standalone or machine-wide
    // gateway never does, so the scan must not read a nested repository's
    // config on their behalf. No file of the clone is captured here, so
    // nothing else looks it up. Its remote is changed AFTER the scan returns,
    // and the key read afterwards is the new one: nothing was resolved
    // before it was asked for.
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });
    gitRepo(join(repo, 'tools', 'mine'), LIB_URL);

    expect(nestedKeysOfLastCall()).toEqual(['github.com/acme/lib']);
  });

  it("keys a nested directory whose `.git` is a dangling link as keyless, never by the project's", async (ctx) => {
    // The walk names `tools/mine` off its `.git` entry. A link that points
    // nowhere is no repository at all, and the lookup the captures use would
    // climb past it to the checkout around it and answer with that checkout's
    // key. A scoped gateway would then see an enrolled key and forward a
    // register that carries this directory's call sites.
    const dir = join(repo, 'tools', 'mine');
    mkdirSync(dir, { recursive: true });
    try {
      symlinkSync(join(repo, 'no-such-git-dir'), join(dir, '.git'));
    } catch (err) {
      // Creating one needs a privilege on Windows. `ctx.skip` rather than a
      // return: a return reports as a pass, which is a claim the run never made.
      ctx.skip(`symlink unavailable on this host: ${err instanceof Error ? err.message : ''}`);
    }
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'tools/mine/notify.ts', NOTIFY_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual([undefined]);
  });

  it("keys a nested clone whose `.git` went away after the walk as keyless, never by the project's", async () => {
    // Removed between the scan and the moment a gateway reads the keys. The
    // directory was a repository when the walk named it and is not one now, so
    // it has no key of its own, and the checkout around it cannot supply one.
    gitRepo(join(repo, 'tools', 'mine'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });
    rmSync(join(repo, 'tools', 'mine', '.git'), { recursive: true, force: true });

    expect(nestedKeysOfLastCall()).toEqual([undefined]);
  });

  it('keys a nested clone by its own remote though the resolver once answered for that directory when it was not a repository', async () => {
    // The resolver remembers each directory it has answered for, for the life of
    // the process. Asked about `tools/mine` while it was an ordinary directory
    // of the checkout, it remembered the checkout's own answer under that path
    // string. The directory then became a clone with a different remote. Its key
    // is the clone's, read now, never what the resolver remembered for the path.
    const dir = join(repo, 'tools', 'mine');
    mkdirSync(dir, { recursive: true });
    write(repo, 'src/pay.ts', STRIPE_CALL);
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/acme/payments-api');
    gitRepo(dir, PERSONAL_URL);
    // The precondition, checked as late as it can be: the resolver still answers
    // for this directory with the checkout's key though it now holds a clone.
    // Without it the case would pass whenever the memory happened to be gone.
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/acme/payments-api');

    await scanWorktree(configWith(true), { rootDir: repo, sourceTool: 'claude-code' });

    expect(nestedKeysOfLastCall()).toEqual(['github.com/me/personal']);
  });

  it('reports a repository only the source walk reaches, when the host re-includes a skipped directory', async () => {
    // A `!` pattern from the host sends the SOURCE walk into `vendor/`, which
    // both walks skip by default. The manifest walk takes no host patterns, so
    // it never lists the clone, yet the clone's files reach this register. The
    // roots reported are what either walk passed through.
    gitRepo(join(repo, 'vendor', 'lib'), PERSONAL_URL);
    write(repo, 'vendor/lib/notify.ts', NOTIFY_CALL);
    write(repo, 'src/pay.ts', STRIPE_CALL);

    await scanWorktree(configWith(true), {
      rootDir: repo,
      sourceTool: 'claude-code',
      excludePatterns: ['!vendor/'],
    });

    expect(scannedFilesOf(lastEgressInput())).toContain('vendor/lib/notify.ts');
    expect(nestedKeysOfLastCall()).toEqual(['github.com/me/personal']);
  });
});

describe('scanWorktree — the scope key of each deleted path', () => {
  // The sweep lists every ledgered path under the root that is gone from disk,
  // whichever repository it was in, and the ledger never forgets a path. What
  // decides whether a scoped gateway may send one travels beside the register:
  // one key per `reconcile.deletedFiles` entry, in the same order.
  //
  // A deleted path is keyed by the repository it was in when it was last READ,
  // which the ledger recorded then. The disk cannot say, because a directory can
  // be replaced or reused after the file is gone: a removed clone's directory
  // recreated by the project, a personal checkout replaced by an enrolled one,
  // a nested repository emptied and refilled. A row recorded without a key, as
  // every row was before keys were kept, has none.
  const PERSONAL_URL = 'https://github.com/me/personal.git';
  const OTHER_URL = 'https://github.com/acme/tools.git';
  const PROJECT_KEY = 'github.com/acme/payments-api';
  const PERSONAL_KEY = 'github.com/me/personal';
  const OTHER_KEY = 'github.com/acme/tools';
  const NOTIFY_CALL = "await fetch('https://api.github.com/repos/me/personal/dispatches');\n";

  // A repository whose config names no remote.
  function remotelessRepo(dir: string): void {
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), '[core]\n\tbare = false\n');
  }

  function lastCall(): [RecordProjectEgressInput, ProjectEgressContext | undefined] {
    const call = recordProjectEgress.mock.calls.at(-1) as
      [RecordProjectEgressInput, ProjectEgressContext | undefined] | undefined;
    if (call === undefined) throw new Error('recordProjectEgress was never called');
    return call;
  }

  // Each deleted path of the last register with the key the scan supplied for
  // it. Built by position, so a list out of step with the register fails here.
  async function deletedWithKeys(): Promise<{ file: string; key: string | undefined }[]> {
    const [input, context] = lastCall();
    if (input.reconcile.mode !== 'ledger') throw new Error('expected ledger mode');
    const { deletedFiles } = input.reconcile;
    const keys = await context?.deletedFileKeys?.();
    if (keys === undefined) throw new Error('the scan supplied no keys for its deleted paths');
    expect(keys).toHaveLength(deletedFiles.length);
    return deletedFiles
      .map((file, at) => ({ file, key: keys[at] }))
      .sort((a, b) => a.file.localeCompare(b.file));
  }

  // The key the ledger holds for a project-relative path.
  function recordedKey(rel: string): string | undefined {
    const row = ledgerRows.get(join(repo, ...rel.split('/')));
    if (row === undefined) throw new Error(`${rel} is not in the ledger`);
    return row.scopeKey;
  }

  async function scan(config: PluginConfig, excludePatterns?: string[]): Promise<void> {
    await scanWorktree(config, {
      rootDir: repo,
      sourceTool: 'claude-code',
      ...(excludePatterns === undefined ? {} : { excludePatterns }),
    });
  }

  it('records the repository a file was in when it was read, manifests included', async () => {
    gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
    write(repo, 'personal-clone/package.json', STRIPE_MANIFEST);
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);

    await scan(configWith(true));

    expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);
    expect(recordedKey('pkg/package.json')).toBe(PROJECT_KEY);
    expect(recordedKey('personal-clone/top.ts')).toBe(PERSONAL_KEY);
    expect(recordedKey('personal-clone/package.json')).toBe(PERSONAL_KEY);
  });

  it('keys the files of a removed clone by the clone, the repository they were in', async () => {
    gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
    write(repo, 'personal-clone/src/notify.ts', `${NOTIFY_CALL}// nested\n`);
    write(repo, 'personal-clone/package.json', STRIPE_MANIFEST);
    const config = configWith(true);
    await scan(config);
    // The precondition: the clone's files are in the ledger, so the sweep lists
    // them once the clone is gone.
    expect(ledgerKeys()).toEqual(
      expect.arrayContaining(['personal-clone/top.ts', 'personal-clone/src/notify.ts']),
    );

    rmSync(join(repo, 'personal-clone'), { recursive: true, force: true });
    await scan(config);

    expect(await deletedWithKeys()).toEqual([
      { file: 'personal-clone/package.json', key: PERSONAL_KEY },
      { file: 'personal-clone/src/notify.ts', key: PERSONAL_KEY },
      { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
    ]);
  });

  it('keys a deleted file of a clone that an ignore file now hides by the clone', async () => {
    // The clone is still on disk and the walk no longer enters it, so the nested
    // list is empty and cannot vouch for it. The record still says what it was.
    gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'personal-clone/src/a.ts', `${NOTIFY_CALL}// a\n`);
    write(repo, 'personal-clone/src/b.ts', `${NOTIFY_CALL}// b\n`);
    const config = configWith(true);
    await scan(config);

    write(repo, '.akaignore', 'personal-clone/\n');
    rmSync(join(repo, 'personal-clone', 'src', 'a.ts'));
    await scan(config);

    expect(lastCall()[1]?.nestedScopeKeys).toEqual([]);
    expect(await deletedWithKeys()).toEqual([
      { file: 'personal-clone/src/a.ts', key: PERSONAL_KEY },
    ]);
  });

  it('keys a deleted file of a clone under a directory the walk skips by the clone', async () => {
    gitRepo(join(repo, 'vendor', 'lib'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'vendor/lib/x.ts', `${NOTIFY_CALL}// x\n`);
    write(repo, 'vendor/lib/y.ts', `${NOTIFY_CALL}// y\n`);
    const config = configWith(true);
    // Read once with the skipped directory re-included, so the clone's files are
    // in the ledger; the second run skips it as it does by default.
    await scan(config, ['!vendor/']);
    expect(ledgerKeys()).toContain('vendor/lib/x.ts');

    rmSync(join(repo, 'vendor', 'lib', 'x.ts'));
    await scan(config);

    expect(lastCall()[1]?.nestedScopeKeys).toEqual([]);
    expect(await deletedWithKeys()).toEqual([{ file: 'vendor/lib/x.ts', key: PERSONAL_KEY }]);
  });

  it("gives a deleted file of a hidden clone with no remote no key, never the project's", async () => {
    remotelessRepo(join(repo, 'scratch'));
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'scratch/a.ts', `${NOTIFY_CALL}// a\n`);
    write(repo, 'scratch/b.ts', `${NOTIFY_CALL}// b\n`);
    const config = configWith(true);
    await scan(config);
    expect(recordedKey('scratch/a.ts')).toBeUndefined();

    write(repo, '.akaignore', 'scratch/\n');
    rmSync(join(repo, 'scratch', 'a.ts'));
    await scan(config);

    expect(await deletedWithKeys()).toEqual([{ file: 'scratch/a.ts', key: undefined }]);
  });

  it("keys a project file deleted from a directory that still exists by the project's remote", async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
    write(repo, 'top.ts', `${STRIPE_CALL}// top\n`);
    const config = configWith(true);
    await scan(config);

    rmSync(join(repo, 'src', 'old.ts'));
    rmSync(join(repo, 'top.ts'));
    await scan(config);

    expect(await deletedWithKeys()).toEqual([
      { file: 'src/old.ts', key: PROJECT_KEY },
      { file: 'top.ts', key: PROJECT_KEY },
    ]);
  });

  it("keys the files of a project directory removed whole by the project's remote", async () => {
    // Nothing on disk is needed to say which repository they were in, so these
    // are no longer left on the deployment: the record names the project.
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/legacy/a.ts', `${STRIPE_CALL}// a\n`);
    write(repo, 'src/legacy/deep/b.ts', `${STRIPE_CALL}// b\n`);
    const config = configWith(true);
    await scan(config);

    rmSync(join(repo, 'src', 'legacy'), { recursive: true, force: true });
    await scan(config);

    expect(await deletedWithKeys()).toEqual([
      { file: 'src/legacy/a.ts', key: PROJECT_KEY },
      { file: 'src/legacy/deep/b.ts', key: PROJECT_KEY },
    ]);
  });

  it('supplies one key per deleted path, in the order of the register, whichever repository each was in', async () => {
    gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
    write(repo, 'src/legacy/a.ts', `${STRIPE_CALL}// a\n`);
    write(repo, 'personal-clone/src/a.ts', `${NOTIFY_CALL}// a\n`);
    write(repo, 'personal-clone/src/b.ts', `${NOTIFY_CALL}// b\n`);
    const config = configWith(true);
    await scan(config);

    write(repo, '.akaignore', 'personal-clone/\n');
    rmSync(join(repo, 'src', 'old.ts'));
    rmSync(join(repo, 'src', 'legacy'), { recursive: true, force: true });
    rmSync(join(repo, 'personal-clone', 'src', 'a.ts'));
    await scan(config);

    expect(await deletedWithKeys()).toEqual([
      { file: 'personal-clone/src/a.ts', key: PERSONAL_KEY },
      { file: 'src/legacy/a.ts', key: PROJECT_KEY },
      { file: 'src/old.ts', key: PROJECT_KEY },
    ]);
  });

  it('answers from the record, not from the disk as it is when the gateway asks', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
    const config = configWith(true);
    await scan(config);
    rmSync(join(repo, 'src', 'old.ts'));
    await scan(config);

    // The checkout's remote and its directory both change after the scan returns.
    gitRepo(repo, PERSONAL_URL);
    rmSync(join(repo, 'src'), { recursive: true, force: true });

    expect(await deletedWithKeys()).toEqual([{ file: 'src/old.ts', key: PROJECT_KEY }]);
  });

  it('answers one list, however often it is read', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
    const config = configWith(true);
    await scan(config);
    rmSync(join(repo, 'src', 'old.ts'));
    await scan(config);

    const context = lastCall()[1];
    const first = await context?.deletedFileKeys?.();
    expect(first).toEqual([PROJECT_KEY]);
    expect(await context?.deletedFileKeys?.()).toBe(first);
  });

  describe('the recorded keys are read only when a gateway asks', () => {
    // The standalone gateway and a machine-wide attachment never ask, so a scan
    // must not read every ledger row's key on their behalf.
    it('reads nothing during the scan, and once however often the gateway asks', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
      const config = configWith(true);
      await scan(config);
      rmSync(join(repo, 'src', 'old.ts'));
      await scan(config);

      expect(scanLedgerPathKeys).not.toHaveBeenCalled();
      const context = lastCall()[1];
      await context?.deletedFileKeys?.();
      await context?.deletedFileKeys?.();
      expect(await deletedWithKeys()).toEqual([{ file: 'src/old.ts', key: PROJECT_KEY }]);
      expect(scanLedgerPathKeys).toHaveBeenCalledTimes(1);
    });

    it('reads nothing for a scan that deleted nothing, though asked', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      const config = configWith(true);
      await scan(config);

      expect(await lastCall()[1]?.deletedFileKeys?.()).toEqual([]);
      expect(scanLedgerPathKeys).not.toHaveBeenCalled();
    });
  });

  describe('a directory that is reused after the files in it were read', () => {
    it("keeps a removed clone's names under the clone when the project makes the same directory", async () => {
      gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
      write(repo, 'personal-clone/src/notify.ts', `${NOTIFY_CALL}// nested\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'personal-clone'), { recursive: true, force: true });
      write(repo, 'personal-clone/new.ts', `${STRIPE_CALL}// new\n`);
      await scan(config);

      // The directory exists again, holds a file the walk reaches, and is the
      // project's now. The names the clone had are still the clone's.
      expect(recordedKey('personal-clone/new.ts')).toBe(PROJECT_KEY);
      expect(await deletedWithKeys()).toEqual([
        { file: 'personal-clone/src/notify.ts', key: PERSONAL_KEY },
        { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
      ]);
    });

    it('keeps the old names of a personal checkout under it when an enrolled one replaces it', async () => {
      gitRepo(join(repo, 'tools'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'tools/old.ts', `${NOTIFY_CALL}// old\n`);
      write(repo, 'tools/same.ts', `${NOTIFY_CALL}// same\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'tools'), { recursive: true, force: true });
      gitRepo(join(repo, 'tools'), OTHER_URL);
      write(repo, 'tools/same.ts', `${STRIPE_CALL}// same, now the other repository's\n`);
      await scan(config);

      expect(await deletedWithKeys()).toEqual([{ file: 'tools/old.ts', key: PERSONAL_KEY }]);
      // A name read again belongs to the repository it was read in this time.
      expect(recordedKey('tools/same.ts')).toBe(OTHER_KEY);
    });

    it('keeps the names of a nested repository that was emptied, whatever appears in its directory', async () => {
      // What `git submodule deinit` leaves: the `.git` and every file go and the
      // empty directory stays. A file the walk reaches then appears in it.
      gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
      write(repo, 'personal-clone/src/notify.ts', `${NOTIFY_CALL}// nested\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'personal-clone', '.git'), { recursive: true, force: true });
      rmSync(join(repo, 'personal-clone', 'top.ts'));
      rmSync(join(repo, 'personal-clone', 'src'), { recursive: true, force: true });
      expect(existsSync(join(repo, 'personal-clone'))).toBe(true);
      write(repo, 'personal-clone/new.ts', `${STRIPE_CALL}// new\n`);
      await scan(config);

      expect(await deletedWithKeys()).toEqual([
        { file: 'personal-clone/src/notify.ts', key: PERSONAL_KEY },
        { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
      ]);
    });

    it('keeps the names of a nested repository emptied but for a file the walk never reaches', async () => {
      gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'personal-clone', '.git'), { recursive: true, force: true });
      rmSync(join(repo, 'personal-clone', 'top.ts'));
      // A file the source walk does not take: no source extension.
      write(repo, 'personal-clone/.DS_Store', 'noise');
      await scan(config);

      expect(await deletedWithKeys()).toEqual([
        { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
      ]);
    });

    it('keeps the deleted siblings of a clone that lost its `.git` but kept some files under the clone', async () => {
      gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
      write(repo, 'personal-clone/keep.ts', `${NOTIFY_CALL}// keep\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'personal-clone', '.git'), { recursive: true, force: true });
      rmSync(join(repo, 'personal-clone', 'top.ts'));
      await scan(config);

      // `top.ts` is gone, and is still the clone's: that is what it was when it was
      // read. `keep.ts` is unchanged and skipped unread. It now climbs to the
      // project, which is around the repository its row recorded, and the scan
      // cannot tell a removal in progress from a permanent one, so its row keeps
      // the clone.
      expect(await deletedWithKeys()).toEqual([
        { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
      ]);
      expect(recordedKey('personal-clone/keep.ts')).toBe(PERSONAL_KEY);
    });

    it('keys a clone emptied in place, whose `.git` is still there, by the clone', async () => {
      gitRepo(join(repo, 'personal-clone'), PERSONAL_URL);
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'personal-clone/top.ts', `${NOTIFY_CALL}// top\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'personal-clone', 'top.ts'));
      await scan(config);

      expect(await deletedWithKeys()).toEqual([
        { file: 'personal-clone/top.ts', key: PERSONAL_KEY },
      ]);
    });
  });

  describe('a deleted path the record cannot place', () => {
    it('has no key when its ledger row recorded none, as every row did before keys were kept', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
      const config = configWith(true);
      await scan(config);
      for (const row of ledgerRows.values()) row.scopeKey = undefined;

      rmSync(join(repo, 'src', 'old.ts'));
      await scan(config);

      expect(await deletedWithKeys()).toEqual([{ file: 'src/old.ts', key: undefined }]);
    });

    it("has no key when the read of the keys fails at the gateway's ask, though the scan completed", async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'src', 'old.ts'));
      scanLedgerPathKeys.mockRejectedValueOnce(new Error('the ledger could not be read'));
      // The scan reads no keys, so the rejection is consumed after it returns,
      // when `deletedWithKeys` asks the way a scoped gateway would.
      await scan(config);

      expect(await deletedWithKeys()).toEqual([{ file: 'src/old.ts', key: undefined }]);
      expect(scanLedgerPathKeys).toHaveBeenCalledTimes(1);
    });

    it('has no key from a gateway that cannot list the keys', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
      const config = configWith(true);
      await scan(config);

      rmSync(join(repo, 'src', 'old.ts'));
      gatewayShape.pathKeys = false;
      await scan(config);

      expect(scanLedgerPathKeys).not.toHaveBeenCalled();
      expect(await deletedWithKeys()).toEqual([{ file: 'src/old.ts', key: undefined }]);
    });
  });
});

describe('scanWorktree — a file the ledger skips as unchanged', () => {
  // Every row was written under the key its file had when it was last READ.
  // A file the scan skips has not been read since, but the directory it is in
  // can have changed hands without touching the file: made into a repository in
  // place, or left with no key by a ledger that predates keys. The scan already
  // reads the row to decide the skip, and compares the key the file has now.
  const PERSONAL_URL = 'https://github.com/me/personal.git';
  const PROJECT_KEY = 'github.com/acme/payments-api';
  const PERSONAL_KEY = 'github.com/me/personal';

  function recordedKey(rel: string): string | undefined {
    const row = ledgerRows.get(join(repo, ...rel.split('/')));
    if (row === undefined) throw new Error(`${rel} is not in the ledger`);
    return row.scopeKey;
  }

  async function lastDeleted(): Promise<{ file: string; key: string | undefined }[]> {
    const [input, context] = recordProjectEgress.mock.calls.at(-1) as [
      RecordProjectEgressInput,
      ProjectEgressContext | undefined,
    ];
    if (input.reconcile.mode !== 'ledger') throw new Error('expected ledger mode');
    const keys = await context?.deletedFileKeys?.();
    if (keys === undefined) throw new Error('the scan supplied no keys for its deleted paths');
    return input.reconcile.deletedFiles
      .map((file, at) => ({ file, key: keys[at] }))
      .sort((a, b) => a.file.localeCompare(b.file));
  }

  async function scan(config: PluginConfig): Promise<void> {
    await scanWorktree(config, { rootDir: repo, sourceTool: 'claude-code' });
  }

  it('takes the key of a repository its directory was made into in place', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'tools/a.ts', `${STRIPE_CALL}// a\n`);
    write(repo, 'tools/package.json', STRIPE_MANIFEST);
    const config = configWith(true);
    await scan(config);
    expect(recordedKey('tools/a.ts')).toBe(PROJECT_KEY);

    // `git init` and a remote inside the project: no file changes.
    gitRepo(join(repo, 'tools'), PERSONAL_URL);
    await scan(config);

    expect(recordedKey('tools/a.ts')).toBe(PERSONAL_KEY);
    expect(recordedKey('tools/package.json')).toBe(PERSONAL_KEY);
    expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);

    // The directory is later removed: its files were the personal repository's.
    rmSync(join(repo, 'tools'), { recursive: true, force: true });
    await scan(config);
    expect(await lastDeleted()).toEqual([
      { file: 'tools/a.ts', key: PERSONAL_KEY },
      { file: 'tools/package.json', key: PERSONAL_KEY },
    ]);
  });

  it('fills a row that recorded no key from the key its file has now', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
    const config = configWith(true);
    await scan(config);
    // Rows written before keys were kept.
    for (const row of ledgerRows.values()) row.scopeKey = undefined;

    await scan(config);
    expect(recordedKey('src/old.ts')).toBe(PROJECT_KEY);
    expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);

    rmSync(join(repo, 'src', 'old.ts'));
    await scan(config);
    expect(await lastDeleted()).toEqual([{ file: 'src/old.ts', key: PROJECT_KEY }]);
  });

  it('changes only the key of the row: its mtime, hash and ruleset stand', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    const config = configWith(true);
    await scan(config);
    const path = join(repo, 'src', 'pay.ts');
    const row = ledgerRows.get(path);
    if (row === undefined) throw new Error('src/pay.ts is not in the ledger');
    const before = { ...row };
    row.scopeKey = undefined;

    await scan(config);

    const after = ledgerRows.get(path);
    expect(after).toEqual({ ...before, scopeKey: PROJECT_KEY });
  });

  it('rewrites no row whose key is unchanged', async () => {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);
    const config = configWith(true);
    await scan(config);
    recordScanned.mockClear();

    await scan(config);

    expect(recordScanned.mock.calls.flatMap(([entries]) => entries as unknown[])).toEqual([]);
  });
});

describe('scanWorktree — a recorded repository moves only to one at or below it', () => {
  // A row records the repository its file was read in, as a key and the
  // directory holding that repository's `.git`. A later scan may move the row to
  // the repository the file climbs to now only when that is the recorded
  // repository or one made inside it. When the file climbs to a repository AROUND
  // the recorded one, or to none, the recorded repository's `.git` is gone, and a
  // scan cannot tell a removal in progress from a permanent one: the removal of a
  // clone takes its `.git` first and its files after, so a scan that lands
  // between the two sees every file of the clone in the project around it. The
  // reading that cannot leak is that the file still belongs to the repository it
  // was read in.
  const PERSONAL_URL = 'https://github.com/me/personal.git';
  const OTHER_URL = 'https://github.com/acme/tools.git';
  const MOVED_URL = 'https://github.com/acme/payments-moved.git';
  const PROJECT_KEY = 'github.com/acme/payments-api';
  const PERSONAL_KEY = 'github.com/me/personal';
  const OTHER_KEY = 'github.com/acme/tools';
  const MOVED_KEY = 'github.com/acme/payments-moved';
  const CLONE = 'personal-clone';
  const NOTIFY_CALL = "await fetch('https://api.github.com/repos/me/personal/dispatches');\n";
  // What the clone holds, relative to the clone.
  const CLONE_FILES = ['package.json', 'src/keep.ts', 'src/notify.ts', 'top.ts'];

  const cloneDir = (): string => join(repo, CLONE);
  const absOf = (rel: string): string => join(repo, ...rel.split('/'));

  function removeGit(dir: string): void {
    rmSync(join(dir, '.git'), { recursive: true, force: true });
  }

  // A repository whose config names no remote.
  function remotelessRepo(dir: string): void {
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), '[core]\n\tbare = false\n');
  }

  function rowOf(rel: string): LedgerRow {
    const row = ledgerRows.get(absOf(rel));
    if (row === undefined) throw new Error(`${rel} is not in the ledger`);
    return row;
  }
  const recordedKey = (rel: string): string | undefined => rowOf(rel).scopeKey;
  const recordedRoot = (rel: string): string | undefined => rowOf(rel).scopeRoot;

  // Moves a file's modification time forward, so a scan cannot read a rewrite
  // made in the same millisecond as the original as no change.
  function later(rel: string): void {
    const at = new Date(statSync(absOf(rel)).mtimeMs + 60_000);
    utimesSync(absOf(rel), at, at);
  }

  async function scan(config: PluginConfig, rootDir = repo): Promise<void> {
    await scanWorktree(config, { rootDir, sourceTool: 'claude-code' });
  }

  async function lastDeleted(): Promise<{ file: string; key: string | undefined }[]> {
    const [input, context] = recordProjectEgress.mock.calls.at(-1) as [
      RecordProjectEgressInput,
      ProjectEgressContext | undefined,
    ];
    if (input.reconcile.mode !== 'ledger') throw new Error('expected ledger mode');
    const keys = await context?.deletedFileKeys?.();
    if (keys === undefined) throw new Error('the scan supplied no keys for its deleted paths');
    return input.reconcile.deletedFiles
      .map((file, at) => ({ file, key: keys[at] }))
      .sort((a, b) => a.file.localeCompare(b.file));
  }

  // The project with a personal clone inside it, each holding files and the
  // clone a manifest.
  function seedProjectWithClone(): void {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    gitRepo(cloneDir(), PERSONAL_URL);
    write(repo, `${CLONE}/top.ts`, `${NOTIFY_CALL}// top\n`);
    write(repo, `${CLONE}/src/keep.ts`, `${NOTIFY_CALL}// keep\n`);
    write(repo, `${CLONE}/src/notify.ts`, `${NOTIFY_CALL}// notify\n`);
    write(repo, `${CLONE}/package.json`, STRIPE_MANIFEST);
  }

  it('records the directory of the repository beside its key, the clone for a clone file', async () => {
    seedProjectWithClone();
    write(repo, 'pkg/package.json', STRIPE_MANIFEST);

    await scan(configWith(true));

    expect(recordedRoot('src/pay.ts')).toBe(repo);
    expect(recordedRoot('pkg/package.json')).toBe(repo);
    for (const rel of CLONE_FILES) {
      expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      expect(recordedKey(`${CLONE}/${rel}`)).toBe(PERSONAL_KEY);
    }
  });

  describe('a clone whose `.git` is gone while its files are still there', () => {
    // The middle of `rm -rf`, `git clean -ffdx`, `git submodule deinit` or
    // `git worktree remove`: the `.git` sorts first and goes first.
    it('keeps the clone as the repository of every unchanged file, and a later deletion keys by the clone', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);

      rmSync(join(cloneDir(), 'top.ts'));
      removeGit(cloneDir());
      await scan(config);

      for (const rel of ['package.json', 'src/keep.ts', 'src/notify.ts']) {
        expect(recordedKey(`${CLONE}/${rel}`)).toBe(PERSONAL_KEY);
        expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      }

      // The removal finishes.
      rmSync(cloneDir(), { recursive: true, force: true });
      write(repo, 'src/new.ts', `${STRIPE_CALL}// new\n`);
      await scan(config);

      expect(await lastDeleted()).toEqual(
        CLONE_FILES.map((rel) => ({ file: `${CLONE}/${rel}`, key: PERSONAL_KEY })),
      );
    });

    it('keeps the clone for a file read in that window, and the capture still takes the disk as it is', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);
      capture.mockClear();

      const changed = `${NOTIFY_CALL}// keep, changed\n`;
      write(repo, `${CLONE}/src/keep.ts`, changed);
      later(`${CLONE}/src/keep.ts`);
      removeGit(cloneDir());
      await scan(config);

      const row = rowOf(`${CLONE}/src/keep.ts`);
      // The row is the new read's, and still the clone's.
      expect(row.contentHash).toBe(contentHashOf(changed));
      expect(row.scopeKey).toBe(PERSONAL_KEY);
      expect(row.scopeRoot).toBe(cloneDir());
      // The event is keyed by the capture lookup, which reads the disk as it is:
      // with the `.git` gone that is the project around the clone.
      const input = capture.mock.calls
        .map(([i]) => i as { metadata: { filePath: string }; scopeKey?: string })
        .find((i) => i.metadata.filePath === absOf(`${CLONE}/src/keep.ts`));
      expect(input?.scopeKey).toBe(PROJECT_KEY);
    });

    it('keeps the clone for a file that was only touched, its content unchanged', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);
      const before = rowOf(`${CLONE}/src/keep.ts`).mtime;

      later(`${CLONE}/src/keep.ts`);
      removeGit(cloneDir());
      await scan(config);

      const row = rowOf(`${CLONE}/src/keep.ts`);
      // The row was rewritten by the touch, which is the path under test.
      expect(row.mtime).not.toBe(before);
      expect(row.scopeKey).toBe(PERSONAL_KEY);
      expect(row.scopeRoot).toBe(cloneDir());
    });

    it('keeps the clone for a file whose new content another file already recorded', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);
      capture.mockClear();

      const recorded = `${NOTIFY_CALL}// recorded elsewhere\n`;
      knownContentHashes.mockImplementation(() =>
        Promise.resolve(new Set([contentHashOf(recorded)])),
      );
      write(repo, `${CLONE}/src/keep.ts`, recorded);
      later(`${CLONE}/src/keep.ts`);
      removeGit(cloneDir());
      await scan(config);

      // Skipped at the content-hash dedup, never captured.
      expect(
        capture.mock.calls.some(
          ([i]) =>
            (i as { metadata: { filePath: string } }).metadata.filePath ===
            absOf(`${CLONE}/src/keep.ts`),
        ),
      ).toBe(false);
      const row = rowOf(`${CLONE}/src/keep.ts`);
      expect(row.contentHash).toBe(contentHashOf(recorded));
      expect(row.scopeKey).toBe(PERSONAL_KEY);
      expect(row.scopeRoot).toBe(cloneDir());
    });

    it("keeps the clone for the clone's manifest, changed or not", async () => {
      seedProjectWithClone();
      write(repo, `${CLONE}/pkg/package.json`, STRIPE_MANIFEST);
      const config = configWith(true);
      await scan(config);

      write(
        repo,
        `${CLONE}/package.json`,
        JSON.stringify({ dependencies: { stripe: '^15.0.0' } }, null, 2),
      );
      later(`${CLONE}/package.json`);
      removeGit(cloneDir());
      await scan(config);

      for (const rel of ['package.json', 'pkg/package.json']) {
        expect(recordedKey(`${CLONE}/${rel}`)).toBe(PERSONAL_KEY);
        expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      }
    });

    it('keeps a clone with no forge remote keyless, never the project around it', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      remotelessRepo(cloneDir());
      write(repo, `${CLONE}/top.ts`, `${NOTIFY_CALL}// top\n`);
      const config = configWith(true);
      await scan(config);
      expect(recordedKey(`${CLONE}/top.ts`)).toBeUndefined();
      expect(recordedRoot(`${CLONE}/top.ts`)).toBe(cloneDir());

      removeGit(cloneDir());
      await scan(config);

      expect(recordedKey(`${CLONE}/top.ts`)).toBeUndefined();
      expect(recordedRoot(`${CLONE}/top.ts`)).toBe(cloneDir());
    });

    it('keeps the inner clone, not the repository around it, when a clone nested in a nested repository loses its `.git`', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      gitRepo(join(repo, 'tools'), OTHER_URL);
      gitRepo(join(repo, 'tools', 'inner'), PERSONAL_URL);
      write(repo, 'tools/a.ts', `${STRIPE_CALL}// a\n`);
      write(repo, 'tools/inner/b.ts', `${NOTIFY_CALL}// b\n`);
      write(repo, 'tools/inner/src/c.ts', `${NOTIFY_CALL}// c\n`);
      const config = configWith(true);
      await scan(config);
      expect(recordedKey('tools/a.ts')).toBe(OTHER_KEY);
      expect(recordedKey('tools/inner/b.ts')).toBe(PERSONAL_KEY);

      removeGit(join(repo, 'tools', 'inner'));
      await scan(config);

      for (const rel of ['tools/inner/b.ts', 'tools/inner/src/c.ts']) {
        expect(recordedKey(rel)).toBe(PERSONAL_KEY);
        expect(recordedRoot(rel)).toBe(join(repo, 'tools', 'inner'));
      }
      // The repository around it keeps its own file.
      expect(recordedKey('tools/a.ts')).toBe(OTHER_KEY);
      expect(recordedRoot('tools/a.ts')).toBe(join(repo, 'tools'));
    });
  });

  describe('a scan rooted at the clone itself', () => {
    it('keeps the clone when its `.git` is removed between two scans from the same directory, with a project around it', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config, cloneDir());
      expect(recordedKey(`${CLONE}/src/keep.ts`)).toBe(PERSONAL_KEY);
      expect(recordedRoot(`${CLONE}/src/keep.ts`)).toBe(cloneDir());

      removeGit(cloneDir());
      await scan(config, cloneDir());

      // From the clone's own directory the files climb to the scan root, whose
      // key now comes from the project above it. The repository they sat in is
      // gone, and the project is around it.
      for (const rel of ['src/keep.ts', 'src/notify.ts', 'top.ts', 'package.json']) {
        expect(recordedKey(`${CLONE}/${rel}`)).toBe(PERSONAL_KEY);
        expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      }
    });

    it('keeps the clone when it is a repository of its own with nothing around it', async () => {
      const solo = join(tmp, 'solo');
      gitRepo(solo, PERSONAL_URL);
      write(solo, 'a.ts', `${NOTIFY_CALL}// a\n`);
      write(solo, 'package.json', STRIPE_MANIFEST);
      const config = configWith(true);
      await scan(config, solo);
      expect(ledgerRows.get(join(solo, 'a.ts'))?.scopeKey).toBe(PERSONAL_KEY);
      expect(ledgerRows.get(join(solo, 'a.ts'))?.scopeRoot).toBe(solo);

      removeGit(solo);
      await scan(config, solo);

      expect(ledgerRows.get(join(solo, 'a.ts'))?.scopeKey).toBe(PERSONAL_KEY);
      expect(ledgerRows.get(join(solo, 'a.ts'))?.scopeRoot).toBe(solo);
    });
  });

  describe('a row that moves', () => {
    it("takes the new key when the project's remote changes and no file does", async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'pkg/package.json', STRIPE_MANIFEST);
      const config = configWith(true);
      await scan(config);
      expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);

      gitRepo(repo, MOVED_URL);
      await scan(config);

      expect(recordedKey('src/pay.ts')).toBe(MOVED_KEY);
      expect(recordedKey('pkg/package.json')).toBe(MOVED_KEY);
      expect(recordedRoot('src/pay.ts')).toBe(repo);
    });

    it('takes the key and directory of a repository made inside the recorded one, in place', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'tools/a.ts', `${STRIPE_CALL}// a\n`);
      const config = configWith(true);
      await scan(config);
      expect(recordedRoot('tools/a.ts')).toBe(repo);

      gitRepo(join(repo, 'tools'), PERSONAL_URL);
      await scan(config);

      expect(recordedKey('tools/a.ts')).toBe(PERSONAL_KEY);
      expect(recordedRoot('tools/a.ts')).toBe(join(repo, 'tools'));
      expect(recordedRoot('src/pay.ts')).toBe(repo);
    });

    it('takes the key of a clone replaced at the same path by another, whose files are read again', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);

      rmSync(cloneDir(), { recursive: true, force: true });
      gitRepo(cloneDir(), OTHER_URL);
      for (const rel of CLONE_FILES.filter((f) => f !== 'package.json')) {
        write(repo, `${CLONE}/${rel}`, `${NOTIFY_CALL}// ${rel}, another clone's\n`);
        later(`${CLONE}/${rel}`);
      }
      await scan(config);

      for (const rel of CLONE_FILES.filter((f) => f !== 'package.json')) {
        expect(recordedKey(`${CLONE}/${rel}`)).toBe(OTHER_KEY);
        expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      }
    });

    it('takes the key of a clone replaced at the same path by another whose files kept their times', async () => {
      seedProjectWithClone();
      const config = configWith(true);
      await scan(config);
      const times = new Map(CLONE_FILES.map((rel) => [rel, rowOf(`${CLONE}/${rel}`).mtime]));

      rmSync(cloneDir(), { recursive: true, force: true });
      gitRepo(cloneDir(), OTHER_URL);
      for (const rel of CLONE_FILES) {
        write(repo, `${CLONE}/${rel}`, rel === 'package.json' ? STRIPE_MANIFEST : `// ${rel}\n`);
        const at = new Date(times.get(rel) ?? 0);
        utimesSync(absOf(`${CLONE}/${rel}`), at, at);
      }
      await scan(config);

      // Skipped unread, and the repository around the same names is the other one.
      for (const rel of CLONE_FILES) {
        expect(recordedKey(`${CLONE}/${rel}`)).toBe(OTHER_KEY);
        expect(recordedRoot(`${CLONE}/${rel}`)).toBe(cloneDir());
      }
    });

    it('fills a row that has a key and no directory from the disk as it is, and a row with neither', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      write(repo, 'src/old.ts', `${STRIPE_CALL}// old\n`);
      const config = configWith(true);
      await scan(config);
      // As a store made by a build that kept the key and not the directory has it.
      rowOf('src/pay.ts').scopeRoot = undefined;
      rowOf('src/pay.ts').scopeKey = OTHER_KEY;
      // As a row written before either was kept.
      rowOf('src/old.ts').scopeRoot = undefined;
      rowOf('src/old.ts').scopeKey = undefined;

      await scan(config);

      for (const rel of ['src/pay.ts', 'src/old.ts']) {
        expect(recordedKey(rel)).toBe(PROJECT_KEY);
        expect(recordedRoot(rel)).toBe(repo);
      }
    });

    it('gives a row with the right key and no directory its directory, without reading the file', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      const config = configWith(true);
      await scan(config);
      // A store made by a build that kept the key and not the directory.
      rowOf('src/pay.ts').scopeRoot = undefined;
      expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);
      capture.mockClear();

      await scan(config);

      // The key was already right, so only the directory differs, and that alone
      // rewrites the row. The file is skipped unread.
      expect(recordedRoot('src/pay.ts')).toBe(repo);
      expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);
      expect(capture).not.toHaveBeenCalled();
    });
  });

  describe('a file whose repository is gone and that now sits in none', () => {
    it('keeps the key and directory it was recorded under', async () => {
      write(repo, 'src/pay.ts', STRIPE_CALL);
      // A manifest anchors the project once there is no repository around it.
      write(repo, 'package.json', STRIPE_MANIFEST);
      const config = configWith(true);
      await scan(config);
      expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);

      removeGit(repo);
      await scan(config);

      expect(recordedKey('src/pay.ts')).toBe(PROJECT_KEY);
      expect(recordedRoot('src/pay.ts')).toBe(repo);
    });
  });
});

describe("scanWorktree — a `.git` removed while a scan reads the clone's repository", () => {
  // The last rmdir of a removal (`rm -rf`, `git clean -ffdx`, `git submodule
  // deinit`, `git worktree remove`) can land between the scan's check that a
  // directory holds a `.git` and its read of that repository's key. The read then
  // climbs and answers with the repository AROUND the clone, and the lookup must
  // not pair that key with the clone's directory: every row of the clone would
  // take the project's key under the clone's own root, and be sent once the
  // removal finishes. The answer for the directory is neither a root nor a key,
  // so a row that has a recorded repository keeps it.
  const PERSONAL_URL = 'https://github.com/me/personal.git';
  const PERSONAL_KEY = 'github.com/me/personal';
  const CLONE = 'personal-clone';
  const NOTIFY_CALL = "await fetch('https://api.github.com/repos/me/personal/dispatches');\n";
  const CLONE_FILES = ['package.json', 'src/keep.ts', 'src/notify.ts', 'top.ts'];

  const cloneDir = (): string => join(repo, CLONE);
  const absOf = (rel: string): string => join(repo, ...rel.split('/'));

  function rowOf(rel: string): LedgerRow {
    const row = ledgerRows.get(absOf(rel));
    if (row === undefined) throw new Error(`${rel} is not in the ledger`);
    return row;
  }

  async function scan(config: PluginConfig, rootDir = repo): Promise<void> {
    await scanWorktree(config, { rootDir, sourceTool: 'claude-code' });
  }

  async function lastDeleted(): Promise<{ file: string; key: string | undefined }[]> {
    const [input, context] = recordProjectEgress.mock.calls.at(-1) as [
      RecordProjectEgressInput,
      ProjectEgressContext | undefined,
    ];
    if (input.reconcile.mode !== 'ledger') throw new Error('expected ledger mode');
    const keys = await context?.deletedFileKeys?.();
    if (keys === undefined) throw new Error('the scan supplied no keys for its deleted paths');
    return input.reconcile.deletedFiles
      .map((file, at) => ({ file, key: keys[at] }))
      .sort((a, b) => a.file.localeCompare(b.file));
  }

  function seedProjectWithClone(): void {
    write(repo, 'src/pay.ts', STRIPE_CALL);
    gitRepo(cloneDir(), PERSONAL_URL);
    write(repo, `${CLONE}/top.ts`, `${NOTIFY_CALL}// top\n`);
    write(repo, `${CLONE}/src/keep.ts`, `${NOTIFY_CALL}// keep\n`);
    write(repo, `${CLONE}/src/notify.ts`, `${NOTIFY_CALL}// notify\n`);
    write(repo, `${CLONE}/package.json`, STRIPE_MANIFEST);
  }

  it('keeps every clone row, and keys its later deletions by the clone, when a scan races the removal', async () => {
    seedProjectWithClone();
    const config = configWith(true);
    await scan(config);

    race.armed = join(cloneDir(), '.git');
    await scan(config);
    // Without this the case passes on a scan that never met the race.
    expect(race.fired).toBe(1);

    for (const rel of CLONE_FILES) {
      expect(rowOf(`${CLONE}/${rel}`).scopeKey).toBe(PERSONAL_KEY);
      expect(rowOf(`${CLONE}/${rel}`).scopeRoot).toBe(cloneDir());
    }

    // The removal finishes.
    rmSync(cloneDir(), { recursive: true, force: true });
    write(repo, 'src/new.ts', `${STRIPE_CALL}// new\n`);
    await scan(config);

    expect(await lastDeleted()).toEqual(
      CLONE_FILES.map((rel) => ({ file: `${CLONE}/${rel}`, key: PERSONAL_KEY })),
    );
  });

  it("keeps a clone's rows when the scan is rooted at the clone and the race lands there", async () => {
    seedProjectWithClone();
    const config = configWith(true);
    await scan(config, cloneDir());
    expect(rowOf(`${CLONE}/src/keep.ts`).scopeKey).toBe(PERSONAL_KEY);

    race.armed = join(cloneDir(), '.git');
    await scan(config, cloneDir());
    expect(race.fired).toBe(1);

    for (const rel of CLONE_FILES) {
      expect(rowOf(`${CLONE}/${rel}`).scopeKey).toBe(PERSONAL_KEY);
      expect(rowOf(`${CLONE}/${rel}`).scopeRoot).toBe(cloneDir());
    }
  });

  it('records nothing for a file first seen in that window, to be filled by a later scan', async () => {
    seedProjectWithClone();
    const config = configWith(true);
    await scan(config);

    // A file new to the ledger, in the clone, read while the race lands.
    write(repo, `${CLONE}/src/fresh.ts`, `${NOTIFY_CALL}// fresh\n`);
    race.armed = join(cloneDir(), '.git');
    await scan(config);
    expect(race.fired).toBe(1);

    // No repository is recorded for it, and certainly not the project's.
    expect(rowOf(`${CLONE}/src/fresh.ts`).scopeKey).toBeUndefined();
    expect(rowOf(`${CLONE}/src/fresh.ts`).scopeRoot).toBeUndefined();
  });
});
