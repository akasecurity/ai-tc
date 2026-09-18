import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { CURRENT_LINK_REACH, stablePath, versionPin } from '../../src/lib/stable-path.ts';

// Every case builds the layout it names on disk with real directory links, so
// what is asserted is what realpath reports rather than a model of it. A
// junction on Windows, which needs no privilege, where POSIX takes a symlink.
function linkDir(target: string, path: string): void {
  mkdirSync(dirname(path), { recursive: true });
  symlinkSync(target, path, process.platform === 'win32' ? 'junction' : 'dir');
}

function file(path: string): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, '');
  return path;
}

let root: string;

beforeEach(() => {
  // Resolved up front: macOS's tmpdir sits behind /var -> /private/var, and a
  // root spelled through that link would make every path here a link-reached
  // one before the layout under test adds any.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'aka-stable-path-')));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('stablePath', () => {
  it('spells a Homebrew keg through its opt link', () => {
    const exe = file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

    expect(stablePath(exe)).toBe(join(root, 'opt', 'aka', 'libexec', 'aka'));
  });

  it("spells a Homebrew-installed Node through the formula's own opt link", () => {
    const node = file(join(root, 'Cellar', 'node@24', '24.18.0', 'bin', 'node'));
    linkDir(join(root, 'Cellar', 'node@24', '24.18.0'), join(root, 'opt', 'node@24'));

    expect(stablePath(node)).toBe(join(root, 'opt', 'node@24', 'bin', 'node'));
  });

  it('spells an installer binroot through the current link beside its version dirs', () => {
    // install.sh and install.ps1: <dir>/<version>/aka-<triple>/aka, with
    // <dir>/current pointing at the binroot rather than at the version dir.
    const exe = file(join(root, 'aka', '1.2.3', 'aka-darwin-arm64', 'aka'));
    linkDir(join(root, 'aka', '1.2.3', 'aka-darwin-arm64'), join(root, 'aka', 'current'));

    expect(stablePath(exe)).toBe(join(root, 'aka', 'current', 'aka'));
  });

  it('spells a Scoop app through its current link', () => {
    const exe = file(join(root, 'apps', 'aka', '1.2.3', 'aka.exe'));
    linkDir(join(root, 'apps', 'aka', '1.2.3'), join(root, 'apps', 'aka', 'current'));

    expect(stablePath(exe)).toBe(join(root, 'apps', 'aka', 'current', 'aka.exe'));
  });

  it('answers the same for a path that already goes through a link', () => {
    // The shape `aka` has when started from PATH: bin/aka -> the keg. What is
    // recorded is the opt spelling, whichever spelling the caller started from.
    file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3', 'libexec'), join(root, 'binlink'));

    expect(stablePath(join(root, 'binlink', 'aka'))).toBe(
      join(root, 'opt', 'aka', 'libexec', 'aka'),
    );
  });

  it('keeps the versioned path when the current link points at another version', () => {
    // The running file is what gets recorded. A link that reaches a DIFFERENT
    // file is not a spelling of this one, however it is named.
    const exe = file(join(root, 'aka', '1.2.3', 'aka-darwin-arm64', 'aka'));
    file(join(root, 'aka', '1.2.4', 'aka-darwin-arm64', 'aka'));
    linkDir(join(root, 'aka', '1.2.4', 'aka-darwin-arm64'), join(root, 'aka', 'current'));

    expect(stablePath(exe)).toBe(exe);
  });

  it('keeps the path when `current` is a real directory rather than a link', () => {
    const exe = file(join(root, 'aka', '1.2.3', 'aka-darwin-arm64', 'aka'));
    file(join(root, 'aka', 'current', 'aka'));

    expect(stablePath(exe)).toBe(exe);
  });

  it('keeps a hand-placed binary where it is', () => {
    const exe = file(join(root, 'tools', 'aka'));

    expect(stablePath(exe)).toBe(exe);
  });

  it('returns a path that resolves to nothing unchanged', () => {
    const missing = join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka');

    expect(stablePath(missing)).toBe(missing);
  });

  // Whatever stablePath returns is what Chrome runs on every connection, so a
  // link it accepts decides that for as long as the registration stands. Only
  // the links the three layouts keep may be taken, and only where they keep them.
  describe('which links it takes', () => {
    it('does not take a `current` link at a far ancestor of the install', () => {
      // The shape of an npm global install on Windows, with a junction planted
      // at the drive root that reaches the same file today and can be
      // re-pointed at anything afterwards.
      const install = ['AppData', 'npm', 'node_modules', '@akasecurity', 'cli', 'native-host'];
      const host = file(join(root, 'Users', 'victim', ...install, 'host.js'));
      linkDir(join(root, 'Users'), join(root, 'current'));
      // The link really does reach the file, so refusing it is a decision, not
      // a failed lookup.
      expect(realpathSync(join(root, 'current', 'victim', ...install, 'host.js'))).toBe(host);

      expect(stablePath(host)).toBe(host);
    });

    it('takes an installer `current` link for the native host beside the binary', () => {
      const host = file(join(root, 'aka', '1.2.3', 'aka-darwin-arm64', 'native-host', 'host.js'));
      linkDir(join(root, 'aka', '1.2.3', 'aka-darwin-arm64'), join(root, 'aka', 'current'));

      expect(stablePath(host)).toBe(join(root, 'aka', 'current', 'native-host', 'host.js'));
    });

    it('takes a `current` link up to CURRENT_LINK_REACH segments above the file, and no further', () => {
      const binroot = join(root, 'aka', '1.2.3', 'aka-darwin-arm64');
      linkDir(binroot, join(root, 'aka', 'current'));
      const within = file(join(binroot, 'a', 'b', 'at-reach'));
      const beyond = file(join(binroot, 'a', 'b', 'c', 'past-reach'));
      expect(relative(binroot, within).split(sep)).toHaveLength(CURRENT_LINK_REACH);

      expect(stablePath(within)).toBe(join(root, 'aka', 'current', 'a', 'b', 'at-reach'));
      expect(stablePath(beyond)).toBe(beyond);
    });

    it('takes no `current` link beside a version directory that is not an installer binroot', () => {
      // The installers' version directory is always aka-<triple>.
      const exe = file(join(root, 'aka', '1.2.3', 'bin', 'aka'));
      linkDir(join(root, 'aka', '1.2.3', 'bin'), join(root, 'aka', 'current'));

      expect(stablePath(exe)).toBe(exe);
    });

    it('takes no `current` link beside an app directory outside `apps`', () => {
      // Scoop keeps every app under <root>/apps/<app>.
      const exe = file(join(root, 'tools', 'aka', '1.2.3', 'aka.exe'));
      linkDir(join(root, 'tools', 'aka', '1.2.3'), join(root, 'tools', 'aka', 'current'));

      expect(stablePath(exe)).toBe(exe);
    });

    it('takes an opt link at any depth below the keg, since Cellar names it', () => {
      const deep = file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'a', 'b', 'c', 'host.js'));
      linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

      expect(stablePath(deep)).toBe(join(root, 'opt', 'aka', 'libexec', 'a', 'b', 'c', 'host.js'));
    });
  });
});

describe('versionPin', () => {
  it('reports a keg path Homebrew links to as this file', () => {
    const exe = file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

    expect(versionPin(exe)).toEqual({ link: join(root, 'opt', 'aka'), reaches: 'this-file' });
  });

  it('reports an older installer version the current link has moved on from', () => {
    // The layout install.sh leaves after an upgrade: the old version is still
    // on disk and still runs, and `current` points at the new one.
    const old = file(join(root, 'aka', '0.9.1', 'aka-darwin-arm64', 'native-host', 'host.js'));
    file(join(root, 'aka', '0.9.2', 'aka-darwin-arm64', 'native-host', 'host.js'));
    linkDir(join(root, 'aka', '0.9.2', 'aka-darwin-arm64'), join(root, 'aka', 'current'));

    expect(versionPin(old)).toEqual({
      link: join(root, 'aka', 'current'),
      reaches: 'another-version',
    });
  });

  it('reports an older Scoop version the current link has moved on from', () => {
    const old = file(join(root, 'apps', 'aka', '0.9.1', 'aka.exe'));
    file(join(root, 'apps', 'aka', '0.9.2', 'aka.exe'));
    linkDir(join(root, 'apps', 'aka', '0.9.2'), join(root, 'apps', 'aka', 'current'));

    expect(versionPin(old)).toEqual({
      link: join(root, 'apps', 'aka', 'current'),
      reaches: 'another-version',
    });
  });

  it('reports nothing when `current` is a real directory rather than a link', () => {
    const exe = file(join(root, 'aka', '1.2.3', 'aka-darwin-arm64', 'aka'));
    file(join(root, 'aka', 'current', 'aka'));

    expect(versionPin(exe)).toBeNull();
  });

  it('reports nothing for a `current` link at a far ancestor of the install', () => {
    const host = file(join(root, 'Users', 'victim', 'npm', 'native-host', 'host.js'));
    linkDir(join(root, 'Users'), join(root, 'current'));

    expect(versionPin(host)).toBeNull();
  });

  it("reports nothing for a path spelled through Scoop's own current link", () => {
    // The spelling stablePath records for a Scoop install. Its unresolved form
    // sits exactly where the layout's link does, so only the check that a
    // pinned path is a DIRECT spelling keeps it from reading as superseded.
    file(join(root, 'apps', 'aka', '1.2.3', 'aka.exe'));
    linkDir(join(root, 'apps', 'aka', '1.2.3'), join(root, 'apps', 'aka', 'current'));

    expect(versionPin(join(root, 'apps', 'aka', 'current', 'aka.exe'))).toBeNull();
  });

  it('reports nothing for the opt spelling of the same file', () => {
    file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

    expect(versionPin(join(root, 'opt', 'aka', 'libexec', 'aka'))).toBeNull();
  });

  it('reports nothing for a path that reaches the file through some other link', () => {
    // bin/aka follows upgrades too, it is just not the spelling stablePath
    // prefers. Anything reached through a link is not a versioned path.
    file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3', 'libexec'), join(root, 'binlink'));

    expect(versionPin(join(root, 'binlink', 'aka'))).toBeNull();
  });

  it('reports nothing for a file no layout links to', () => {
    // Pinned in the sense of naming a version, but there is nothing better to
    // name, so it is not reported as a registration that needs rewriting.
    expect(versionPin(file(join(root, 'versions', '1.2.3', 'aka')))).toBeNull();
  });

  it('reports nothing for a path that names nothing', () => {
    expect(versionPin(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'))).toBeNull();
  });
});
