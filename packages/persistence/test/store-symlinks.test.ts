// The store-symlink detection: which store paths are links, where they resolve,
// and the mode the store inherits by following them. Rendering lives with each
// caller (`aka init` prints a report, the hooks emit one stderr line); only these
// facts are shared, so only these are pinned here.
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { dataDir, settingsDir } from '../src/local-layout.ts';
import { symlinkedStorePaths } from '../src/store-symlinks.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-store-symlinks-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
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

    // Each store directory a symlink can stand in for: the two layout leaves plus
    // keys/, at a second home. Each is named with the directory the store actually
    // lands in, fully resolved, so a chain of links still names the real
    // destination (on macOS the tmpdir is itself reached through /var ->
    // /private/var).
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
    // mode the store inherits from that target, which is what a caller warns about.
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
