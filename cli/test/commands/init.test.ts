import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { dataDir, dbPath, settingsDir } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { looseStorePaths, runInit } from '../../src/commands/init.ts';

// Force the offer's non-interactive branch to emit: report no installed plugin so
// offerPluginInstall reaches the print path, independent of the host's ~/.claude.
vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return { ...actual, installedPluginVersions: vi.fn(() => new Map<string, string>()) };
});

let dir: string;
let stdinTTY: PropertyDescriptor | undefined;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-init-'));
  // The interactive offer is TTY-gated; force the non-TTY branch so runInit
  // prints the offer copy without blocking on a confirm prompt.
  stdinTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  if (stdinTTY) Object.defineProperty(process.stdin, 'isTTY', stdinTTY);
  else delete (process.stdin as { isTTY?: boolean }).isTTY;
  vi.restoreAllMocks();
});

describe('plugin-install offer identity', () => {
  it('emits offer copy carrying the canonical product name and tagline', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('AKA Security');
    expect(out).toContain('We secure agent harnesses at the source.');
  });
});

describe('runInit contract', () => {
  it('still scaffolds ~/.aka and asks no posture questions', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);

    // Scaffolding: the settings file and the SQLite store both land under the home.
    expect(existsSync(join(settingsDir(dir), 'settings.json'))).toBe(true);
    expect(existsSync(dbPath(dir))).toBe(true);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`Initialized AKA at ${dir}`);
    // init never interrogates the user about detection posture or historical access.
    expect(out).not.toMatch(/posture/i);
    expect(out).not.toMatch(/historical access/i);
  });

  it('leaves ~/.aka owner-only: 0700 dirs (base, settings/, data/) and 0600 files (settings.json, aka.db)', async () => {
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // Start from a loose home so this proves init TIGHTENS it, not merely that a
    // fresh mkdir happens to land at 0700. These modes are the store's only
    // at-rest control (see the "Data at rest" note in SECURITY.md).
    if (process.platform !== 'win32') chmodSync(dir, 0o777);

    await runInit(['--home', dir]);

    if (process.platform === 'win32') return;
    const mode = (p: string): number => statSync(p).mode & 0o777;
    expect(mode(dir)).toBe(0o700);
    expect(mode(settingsDir(dir))).toBe(0o700);
    expect(mode(dataDir(dir))).toBe(0o700);
    expect(mode(join(settingsDir(dir), 'settings.json'))).toBe(0o600);
    expect(mode(dbPath(dir))).toBe(0o600);
  });

  it('re-tightens a pre-existing loose settings.json on re-run (tighten is not gated on creating it)', async () => {
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    if (process.platform === 'win32') return;
    // Simulate a user who hit the pre-fix leftover-.tmp bug: settings.json exists
    // at 0666, so `settingsCreated` is false and the write block is skipped. The
    // re-run must still repair the mode — settings.json self-heals like the dirs,
    // the key, and the db.
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{"specVersion":1,"runMode":"standalone","policy":"warn"}');
    chmodSync(file, 0o666);

    await runInit(['--home', dir]);

    expect(statSync(file).mode & 0o777).toBe(0o600);
    // ...and it did not clobber the user's saved answers.
    expect(readFileSync(file, 'utf8')).toContain('"policy":"warn"');
  });

  it('a second init preserves an existing settings.json (never clobbers onboarding answers)', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runInit(['--home', dir]);
    const file = join(settingsDir(dir), 'settings.json');
    const first = readFileSync(file, 'utf8');
    stdout.mockClear();

    await runInit(['--home', dir]);

    // A re-run re-applies no migration and must not overwrite the user's answers.
    expect(readFileSync(file, 'utf8')).toBe(first);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(kept existing)');
  });
});

describe('looseStorePaths', () => {
  it('reports the store paths that are not owner-only, and none when all are tight', () => {
    if (process.platform === 'win32') return;
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{}');

    // All owner-only → nothing reported.
    for (const p of [dir, settings, dataDir(dir), file]) chmodSync(p, p === file ? 0o600 : 0o700);
    expect(looseStorePaths(dir)).toEqual([]);

    // Loosen settings.json → it (and only it) is reported.
    chmodSync(file, 0o644);
    expect(looseStorePaths(dir)).toEqual([file]);
  });

  it('makes `aka init` print a warning when a mode could not be applied', async () => {
    // macOS-only fault injection: chflags freezes the settings dir so init's
    // tighten of settings.json fails, and init must surface that (data/ stays
    // writable, so the store still initializes). No macOS CI, so this runs local.
    if (process.platform !== 'darwin') return;
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    writeFileSync(join(settings, 'settings.json'), '{}');
    chmodSync(join(settings, 'settings.json'), 0o644);
    execFileSync('chflags', ['uchg', settings]);
    try {
      await runInit(['--home', dir]);
      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).toContain('could not enforce owner-only permissions');
    } finally {
      execFileSync('chflags', ['nouchg', settings]); // so afterEach can clean up
    }
  });
});
