import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { dataDir, dbPath, settingsDir } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  looseStorePaths,
  runInit,
  symlinkedStorePaths,
  symlinkWarnings,
} from '../../src/commands/init.ts';

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

// Every path under `home`, the home itself included. A hardcoded list of the
// paths init writes cannot cover what a later change adds — the migration's
// `aka.db.pre-drop.<ts>.bak`, a byte-for-byte copy of the store, is already one
// such file and no list here names it.
function storeTree(home: string): string[] {
  const entries = readdirSync(home, { withFileTypes: true, recursive: true });
  return [home, ...entries.map((e) => join(e.parentPath, e.name))];
}

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

  it('holds every path under ~/.aka owner-only whatever umask the caller has', async (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    // What this pins is narrower than it looks, so state it exactly. No umask
    // can loosen 0700/0600 — a umask only ever CLEARS bits, and neither mode has
    // a group or other bit left to clear — so this case does NOT stand behind
    // the chmod; the loose-home case above is what does. What it stands behind
    // is that the modes never come from the caller's umask happening to be
    // tight: anything created here with no explicit mode lands 0777/0666, where
    // a default `umask 022` host would have shown the same bug as a milder
    // 0755/0644, and a `umask 077` host would have hidden it outright.
    //
    // The walk is the other half — see storeTree.
    //
    // The umask is process-global and restored in the `finally`; vitest runs a
    // file's tests in sequence, so the window is this case only. It also needs
    // the default `forks` pool — setting the umask raises
    // ERR_WORKER_UNSUPPORTED_OPERATION on a worker thread, so a switch to
    // `pool: 'threads'` fails this case loudly rather than skipping it.
    const outside = mkdtempSync(join(tmpdir(), 'aka-umask-control-'));
    const control = join(outside, 'no-mode');

    try {
      const previousUmask = process.umask(0o000);
      try {
        writeFileSync(control, ''); // no explicit mode — the precondition below
        await runInit(['--home', dir]);
      } finally {
        process.umask(previousUmask);
      }

      // Precondition: a no-mode file lands 0666 only under a genuinely
      // permissive umask. Without it the case passes vacuously wherever the
      // umask is ignored.
      expect(statSync(control).mode & 0o777).toBe(0o666);

      const tree = storeTree(dir);
      // ...and the walk has to have reached the store, or "nothing is loose"
      // holds vacuously over an empty tree.
      expect(tree).toContain(dbPath(dir));
      expect(tree).toContain(join(settingsDir(dir), 'settings.json'));
      expect(tree.filter((p) => (statSync(p).mode & 0o077) !== 0)).toEqual([]);

      // The user-facing signal has to agree with the disk.
      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).not.toContain('could not enforce owner-only permissions');
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
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

  it('reports a loose artifact beside the store that no enumerated target names', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The layout is a fixed list; what sits beside the store is not. The legacy
    // drop leaves an `aka.db.pre-drop.<ts>.<rand>.bak` — a byte-for-byte copy of
    // the prompt corpus — on every run, and the SQLite sidecars appear with
    // whichever journal mode is active. tightenFile/tightenPerms hold all of
    // them at 0600, so one left group-readable is a rejected chmod, which is
    // exactly what this warning exists to surface. Before this walk the store's
    // only at-rest control could fail on the largest file in the directory and
    // the user would never be told.
    const settings = settingsDir(dir);
    mkdirSync(settings, { recursive: true });
    mkdirSync(dataDir(dir), { recursive: true });
    const file = join(settings, 'settings.json');
    writeFileSync(file, '{}');
    for (const p of [dir, settings, dataDir(dir), file]) chmodSync(p, p === file ? 0o600 : 0o700);
    expect(looseStorePaths(dir)).toEqual([]); // precondition: nothing enumerated is loose

    const backup = join(dataDir(dir), 'aka.db.pre-drop.1785500790653.545ee74f.bak');
    writeFileSync(backup, 'prompt corpus');
    chmodSync(backup, 0o644);
    const sidecar = join(dataDir(dir), 'aka.db-wal');
    writeFileSync(sidecar, '');
    chmodSync(sidecar, 0o644);

    expect(looseStorePaths(dir).sort()).toEqual([backup, sidecar].sort());
  });

  it('does not report a `.partial` (loose by design mid-copy, not a rejected chmod)', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // snapshotStore tightens its staging copy only just before the rename, so
    // the file exists at the caller's umask for the whole VACUUM INTO and a copy
    // cut short by a kill leaves a 0644 `.partial` behind on purpose. Naming it
    // here would blame the filesystem for a mode nothing tried to apply — the
    // same wrong diagnosis the symlink case below avoids.
    mkdirSync(dataDir(dir), { recursive: true });
    mkdirSync(settingsDir(dir), { recursive: true });
    for (const p of [dir, settingsDir(dir), dataDir(dir)]) chmodSync(p, 0o700);
    const partial = join(dataDir(dir), 'aka.db.pre-drop.1.aaaaaaaa.bak.partial');
    writeFileSync(partial, 'half a copy');
    chmodSync(partial, 0o644);

    expect(looseStorePaths(dir)).toEqual([]);
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
      {
        path: settingsDir(home),
        target: realpathSync(elsewhereSettings),
        holds: 'your settings file',
        missing: false,
        mode: 0o755,
      },
      {
        path: dataDir(home),
        target: realpathSync(elsewhereData),
        holds: 'the store database (including the prompt corpus)',
        missing: false,
        mode: 0o777,
      },
      {
        path: join(home, 'keys'),
        target: realpathSync(elsewhereKeys),
        holds: 'the vault key',
        missing: false,
        mode: 0o700,
      },
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
      {
        path: join(home, 'keys'),
        target: missing,
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
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
      {
        path: join(home, 'keys'),
        target: join(dir, 'unmounted-volume'),
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
    ]);
  });
});

describe('symlinkWarnings', () => {
  // The redirection is the whole warning on Windows: no mode is ever applied
  // there, so there is no inherited permission to describe — but the prompt
  // corpus still lands wherever the junction points, and a junction needs no
  // elevation to create. Driven through the injected platform so both copies are
  // pinned from any host; the DEFAULT binding is pinned by the runInit cases
  // above, which read the real process.platform.
  const link = {
    path: '/home/u/.aka',
    target: '/srv/shared',
    holds: 'the store (including the prompt corpus in aka.db)',
    missing: false,
    mode: 0o755,
  };

  it('states the inherited permission on POSIX', () => {
    const out = symlinkWarnings([link], 'linux');
    expect(out).toContain('(currently 0755, NOT owner-only)');
    expect(out).toContain("under that target's own permissions");
    expect(out).toContain('prompt corpus');
  });

  it('drops the permissions clause on Windows but keeps the redirection', () => {
    const out = symlinkWarnings([{ ...link, mode: undefined }], 'win32');
    expect(out).toContain('/home/u/.aka is a symlink to /srv/shared');
    expect(out).toContain('prompt corpus');
    // No mode is applied on Windows at all, so claiming the target's own is
    // kept would describe a control that does not exist there.
    expect(out).not.toContain("under that target's own permissions");
    expect(out).not.toContain('currently');
  });

  // P1-a: the body is emitted once per store path, and aka.db only ever lands
  // under data/. A single generic sentence claimed the prompt corpus goes to
  // every one of them, which would send a reader to the wrong directory.
  it('names what actually lands at each path, not the corpus everywhere', () => {
    const out = symlinkWarnings(
      [
        { ...link, path: '/home/u/.aka/keys', holds: 'the vault key' },
        { ...link, path: '/home/u/.aka/settings', holds: 'your settings file' },
      ],
      'linux',
    );

    expect(out).toContain('/home/u/.aka/keys is a symlink to /srv/shared');
    expect(out).toContain('the vault key is written there');
    expect(out).toContain('your settings file is written there');
    // Neither path ever receives aka.db, so neither line may claim it does.
    expect(out).not.toContain('prompt corpus');
    expect(out).not.toContain('aka.db');
  });

  // P1-b: a link resolving nowhere inherits nothing and has received nothing.
  // Claiming it keeps the target's permissions is false twice over.
  it('says a link resolving nowhere has no target rather than inheriting one', () => {
    const out = symlinkWarnings(
      [
        {
          path: '/home/u/.aka/keys',
          target: '/mnt/unmounted',
          holds: 'the vault key',
          missing: true,
          mode: undefined,
        },
      ],
      'linux',
    );

    expect(out).toContain('is a symlink to /mnt/unmounted, which does not exist');
    expect(out).toContain('the vault key cannot be written there');
    expect(out).toContain('create that target or remove the link');
    // The two claims that are wrong for a target that is not there.
    expect(out).not.toContain("under that target's own permissions");
    expect(out).not.toContain('is written there');
  });

  it('reports no mode on Windows even where one is readable', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // statSync would happily return a mode on this host — the win32 branch must
    // decline to read it rather than report a permission Windows never applies.
    const victim = join(dir, 'victim-shared');
    mkdirSync(victim);
    chmodSync(victim, 0o755);
    const home = join(dir, 'linkhome');
    symlinkSync(victim, home);

    expect(symlinkedStorePaths(home, 'win32')).toEqual([
      {
        path: home,
        target: realpathSync(victim),
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: undefined,
      },
    ]);
    expect(symlinkedStorePaths(home, 'linux')).toEqual([
      {
        path: home,
        target: realpathSync(victim),
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: 0o755,
      },
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

  // Each of the three directories init creates through. `it.each` cannot carry
  // the test context a Windows skip needs, so the cases are generated by hand.
  for (const [label, at] of [
    ['the base', (home: string) => home],
    ['settings/', (home: string) => settingsDir(home)],
    ['data/', (home: string) => dataDir(home)],
  ] as const) {
    it(`diagnoses a BROKEN link at ${label} instead of raising a bare ENOENT`, async (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
        return;
      }
      // mkdir on a dangling link raises `ENOENT ... mkdir '<path>'` at a path
      // that does exist, which reads as a missing parent. It also throws before
      // the symlink report runs, so the diagnosis never prints.
      vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      const home = join(dir, 'linkhome');
      mkdirSync(home);
      const missing = join(dir, 'unmounted-volume');
      const link = at(home);
      if (link === home) rmSync(home, { recursive: true });
      else mkdirSync(dirname(link), { recursive: true });
      symlinkSync(missing, link);

      await expect(runInit(['--home', home])).rejects.toThrow(
        `${link} is a symlink to ${missing}, which does not exist`,
      );
    });
  }

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
