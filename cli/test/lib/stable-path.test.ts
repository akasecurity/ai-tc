import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { isVersionPinned, stablePath } from '../../src/lib/stable-path.ts';

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
});

describe('isVersionPinned', () => {
  it('is true for a keg path Homebrew links to', () => {
    const exe = file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

    expect(isVersionPinned(exe)).toBe(true);
  });

  it('is false for the opt spelling of the same file', () => {
    file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));

    expect(isVersionPinned(join(root, 'opt', 'aka', 'libexec', 'aka'))).toBe(false);
  });

  it('is false for a path that reaches the file through some other link', () => {
    // bin/aka follows upgrades too, it is just not the spelling stablePath
    // prefers. Anything reached through a link is not a versioned path.
    file(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3'), join(root, 'opt', 'aka'));
    linkDir(join(root, 'Cellar', 'aka', '1.2.3', 'libexec'), join(root, 'binlink'));

    expect(isVersionPinned(join(root, 'binlink', 'aka'))).toBe(false);
  });

  it('is false for a file no layout links to', () => {
    // Pinned in the sense of naming a version, but there is nothing better to
    // name, so it is not reported as a registration that needs rewriting.
    expect(isVersionPinned(file(join(root, 'versions', '1.2.3', 'aka')))).toBe(false);
  });

  it('is false for a path that names nothing', () => {
    expect(isVersionPinned(join(root, 'Cellar', 'aka', '1.2.3', 'libexec', 'aka'))).toBe(false);
  });
});
