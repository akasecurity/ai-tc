import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { dataDir, dbPath, settingsDir } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { looseStorePaths, runInit, symlinkedStorePaths } from '../../src/commands/init.ts';

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

  it('does not report a symlinked path as loose (that mode was never ours to apply)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // statSync follows links, so a symlink to a 0755 dir looks group-readable.
    // Reporting it here would blame the filesystem for rejecting a chmod that was
    // deliberately skipped — the symlink warning is the accurate diagnosis.
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    expect(looseStorePaths(home)).toEqual([]);
  });
});

describe('symlinkedStorePaths', () => {
  it('reports each symlinked store path with what it resolves to, and none when all are real', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // A real home reports nothing.
    mkdirSync(settingsDir(dir), { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    expect(symlinkedStorePaths(dir)).toEqual([]);

    // Each store directory a symlink can stand in for — ~/.aka is covered by the
    // runInit case below; here the two layout leaves plus keys/, at a second
    // home. Each is named with the directory the store actually lands in, fully
    // resolved, so a chain of links still names the real destination (on macOS
    // the tmpdir is itself reached through /var -> /private/var).
    const home = join(dir, 'home2');
    mkdirSync(home);
    const elsewhereSettings = join(dir, 'elsewhere-settings');
    const elsewhereData = join(dir, 'elsewhere-data');
    const elsewhereKeys = join(dir, 'elsewhere-keys');
    for (const victim of [elsewhereSettings, elsewhereData, elsewhereKeys]) mkdirSync(victim);
    // Distinct modes, none of them 0700: the inherited permission is reported
    // per path, so a shared literal would not show it is read from the target.
    chmodSync(elsewhereSettings, 0o755);
    chmodSync(elsewhereData, 0o777);
    chmodSync(elsewhereKeys, 0o700);
    symlinkSync(elsewhereSettings, settingsDir(home));
    symlinkSync(elsewhereData, dataDir(home));
    symlinkSync(elsewhereKeys, join(home, 'keys'));

    // Reported in store-layout order: settings/, data/, keys/ — each with the
    // mode the store inherits from that target, which is what init warns about.
    expect(symlinkedStorePaths(home)).toEqual([
      { path: settingsDir(home), target: realpathSync(elsewhereSettings), mode: 0o755 },
      { path: dataDir(home), target: realpathSync(elsewhereData), mode: 0o777 },
      { path: join(home, 'keys'), target: realpathSync(elsewhereKeys), mode: 0o700 },
    ]);
  });

  it('still reports a link that resolves nowhere, naming an absolute target', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // realpath has nothing to resolve on a dangling link; falling through to
    // readlink keeps the report rather than dropping it as absent. There is
    // nothing to stat either, so the mode reads as unknown rather than as
    // owner-only — an absent mode must not be reported as a safe one.
    const home = join(dir, 'home3');
    mkdirSync(home);
    const missing = join(dir, 'unmounted-volume');
    symlinkSync(missing, join(home, 'keys'));

    expect(symlinkedStorePaths(home)).toEqual([
      { path: join(home, 'keys'), target: missing, mode: undefined },
    ]);
  });

  it('resolves a RELATIVE dangling target against the link, not the cwd', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // readlink returns whatever was stored, so a relative link reports a path
    // that names nothing on its own — the reader cannot tell where the corpus
    // would land. Resolve it against the link's own directory.
    const home = join(dir, 'home4');
    mkdirSync(home);
    symlinkSync('../unmounted-volume', join(home, 'keys'));

    expect(symlinkedStorePaths(home)).toEqual([
      { path: join(home, 'keys'), target: join(dir, 'unmounted-volume'), mode: undefined },
    ]);
  });
});

describe('runInit on a symlinked home', () => {
  it('leaves the victim directory mode unchanged and names the link', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // End-to-end through the real command: a symlink planted at the home path
    // used to be followed — the target was chmod'd to 0700 and the whole store
    // written inside it, with no warning. init must now leave the target's mode
    // alone and say where the store went.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    expect(statSync(victim).mode & 0o777).toBe(0o755); // victim NOT tightened
    expect(lstatSync(home).isSymbolicLink()).toBe(true); // link left as-is

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain(`${home} is a symlink to ${realpathSync(victim)}`);
    expect(out).toContain('prompt corpus');
    // The wrong diagnosis must not also fire: nothing here rejected a chmod.
    expect(out).not.toContain('could not enforce owner-only permissions');
  });

  it('names the mode the store inherits, and says when it is NOT owner-only', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // looseStorePaths skips a symlinked path (the chmod was declined, not
    // rejected), so this warning is the ONLY place the store's real at-rest
    // permission is stated. Without the mode a reader is told the target's
    // permissions were kept, but never that they are readable by everyone —
    // which is the whole point of the warning.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(currently 0755, NOT owner-only)');
  });

  it('does not cry wolf when the symlink target is already owner-only', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The other half of the same property: a deliberately symlinked home that is
    // already 0700 still gets the redirection warning (the corpus does land
    // elsewhere) but must not be labelled loose, or the label stops meaning
    // anything.
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-private');
    mkdirSync(victim);
    chmodSync(victim, 0o700);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('(currently 0700)');
    expect(out).not.toContain('NOT owner-only');
  });

  it('still initializes the store through the link (surfaced, not refused)', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // The pinned decision: a home a user deliberately symlinked keeps working,
    // and the directories init creates inside it are still held owner-only.
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    await runInit(['--home', home]);

    expect(existsSync(join(victim, 'settings', 'settings.json'))).toBe(true);
    expect(existsSync(join(victim, 'data', 'aka.db'))).toBe(true);
    expect(statSync(join(victim, 'data')).mode & 0o777).toBe(0o700);
    expect(statSync(join(victim, 'settings', 'settings.json')).mode & 0o777).toBe(0o600);
  });
});
