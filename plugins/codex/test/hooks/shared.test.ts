import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import type * as PluginSdk from '@akasecurity/plugin-sdk';
import { readHookFailOpens, resolveRepo, resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { baseMetadata, captureScopeKey, countFailOpen } from '../../src/hooks/shared.ts';

// A hook calls countFailOpen() with no base, so the home directory is resolved
// on its own path — and `os.homedir()` throws when the platform cannot name
// one. The toggle makes that refusal reachable; every other call in this file
// gets the real function.
const osHome = vi.hoisted(() => ({ refuse: false }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.refuse) throw new Error('no home directory');
      return actual.homedir();
    },
  };
});

// The two repo resolvers WRAPPED, not replaced: every call still does the real
// walk. The wrappers exist for the one-walk case at the bottom of this file.
vi.mock('@akasecurity/plugin-sdk', async (importActual) => {
  const actual = await importActual<typeof PluginSdk>();
  return {
    ...actual,
    resolveRepo: vi.fn((cwd: string) => actual.resolveRepo(cwd)),
    resolveRepoAttribution: vi.fn((cwd: string) => actual.resolveRepoAttribution(cwd)),
  };
});

describe('countFailOpen', () => {
  // Called from inside every hook entry's top-level catch. Two things have to
  // hold there and nowhere else matters as much: it must never throw (a throw
  // inside that catch escapes as an uncaught exception and turns a silent
  // allow into a non-zero exit), and it must never print (Codex reads an empty
  // stdout as "no opinion", and one byte would change that).
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-codex-count-fail-open-'));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  it('counts one exit per call under the home it is given, and prints nothing', () => {
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      countFailOpen(base);
      countFailOpen(base);
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      writeSpy.mockRestore();
    }
    expect(readHookFailOpens(join(base, 'data'))).toMatchObject({ failOpens: 2 });
  });

  it('never throws, even where nothing under the home can be written', () => {
    const blocker = join(base, 'not-a-dir');
    writeFileSync(blocker, '');
    expect(() => {
      countFailOpen(join(blocker, 'home'));
    }).not.toThrow();
  });

  it('never throws when the home directory itself cannot be resolved', () => {
    // The production call passes no base, so `dataDir()` asks `os.homedir()`,
    // and that question is asked BEFORE `recordHookFailOpen`'s own guard runs.
    osHome.refuse = true;
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      expect(() => {
        countFailOpen();
      }).not.toThrow();
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      osHome.refuse = false;
      writeSpy.mockRestore();
    }
  });
});

describe('captureScopeKey', () => {
  // Fixture checkouts are fake `.git/config` files: the resolver reads files and
  // never spawns git.
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-codex-scope-key-'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  /** A checkout at `root/<name>` whose origin is `remote`, or with no remote. */
  function checkout(name: string, remote: string | undefined): string {
    const dir = join(root, name);
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(
      join(dir, '.git', 'config'),
      remote === undefined ? '[core]\n\tbare = false\n' : `[remote "origin"]\n\turl = ${remote}\n`,
    );
    return dir;
  }

  it('keys an event by the canonical form of its checkout origin', () => {
    const repo = checkout('work', 'git@GitHub.com:acme/work-repo.git');
    expect(captureScopeKey({ session_id: 's', cwd: repo })).toBe('github.com/acme/work-repo');
  });

  it.each([
    ['a checkout with no remote', () => checkout('scratch', undefined)],
    ['a checkout whose remote is a local path', () => checkout('mirror', '/srv/git/work.git')],
    [
      'a directory outside any checkout',
      () => {
        const dir = join(root, 'plain');
        mkdirSync(dir, { recursive: true });
        return dir;
      },
    ],
  ])('passes no key for %s', (_label, make) => {
    expect(captureScopeKey({ session_id: 's', cwd: make() })).toBeUndefined();
  });

  it('falls back to the hook process cwd exactly as baseMetadata does', () => {
    // Codex's SessionStart resolves the session root from the same
    // `cwd ?? process.cwd()`, so the fallback keeps an event's key equal to its
    // root's.
    const repo = checkout('work', 'git@github.com:acme/work-repo.git');
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(repo);
    try {
      expect(captureScopeKey({ session_id: 's' })).toBe('github.com/acme/work-repo');
      expect(baseMetadata({ session_id: 's' })?.repo).toBe('work-repo');
    } finally {
      spy.mockRestore();
    }
  });

  it('answers no key, rather than throwing, when the working directory is gone', () => {
    const spy = vi.spyOn(process, 'cwd').mockImplementation(() => {
      throw new Error('ENOENT: no such file or directory, uv_cwd');
    });
    try {
      expect(captureScopeKey({ session_id: 's' })).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });

  it('reads the same directory through the same resolver as baseMetadata: one walk', () => {
    const repo = checkout('work', 'git@github.com:acme/work-repo.git');
    vi.mocked(resolveRepoAttribution).mockClear();
    vi.mocked(resolveRepo).mockClear();
    baseMetadata({ session_id: 's', cwd: repo });
    captureScopeKey({ session_id: 's', cwd: repo });
    expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[repo], [repo]]);
    expect(resolveRepo).not.toHaveBeenCalled();
  });

  // An event that names a file is keyed by that file's checkout, whatever the
  // session's cwd.
  describe('with a file path', () => {
    const WORK = 'git@github.com:acme/work-repo.git';
    const WORK_KEY = 'github.com/acme/work-repo';

    it('keys a file in a second checkout by that checkout, not by the session cwd', () => {
      const work = checkout('work', WORK);
      const personal = checkout('personal', 'https://github.com/someone/dotfiles.git');
      vi.mocked(resolveRepoAttribution).mockClear();
      expect(captureScopeKey({ session_id: 's', cwd: work }, join(personal, 'notes.md'))).toBe(
        'github.com/someone/dotfiles',
      );
      expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[personal]]);
    });

    it('passes no key for a file outside any checkout, rather than the cwd key', () => {
      const work = checkout('work', WORK);
      const loose = join(root, 'loose');
      mkdirSync(loose, { recursive: true });
      expect(
        captureScopeKey({ session_id: 's', cwd: work }, join(loose, 'notes.md')),
      ).toBeUndefined();
    });

    it('passes no key for a file in a checkout with no remote, rather than the cwd key', () => {
      const work = checkout('work', WORK);
      const scratch = checkout('scratch', undefined);
      expect(captureScopeKey({ cwd: work }, join(scratch, 'notes.md'))).toBeUndefined();
    });

    it.each([
      ['an empty path', ''],
      ['no path', undefined],
    ])('keys %s by the cwd, as an event that names no file', (_label, filePath) => {
      const work = checkout('work', WORK);
      expect(captureScopeKey({ session_id: 's', cwd: work }, filePath)).toBe(WORK_KEY);
    });

    // A relative path names a location, read against the event's cwd. The cwd's
    // key is not a stand-in for it: a `..` leaves the checkout the session is in.
    describe('that is relative', () => {
      it('keys a file under the cwd checkout by it, walking up from the resolved file', () => {
        const work = checkout('work', WORK);
        vi.mocked(resolveRepoAttribution).mockClear();
        expect(captureScopeKey({ session_id: 's', cwd: work }, join('src', 'index.ts'))).toBe(
          WORK_KEY,
        );
        expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[join(work, 'src')]]);
      });

      it('keys a path that escapes into a sibling checkout by that checkout', () => {
        const work = checkout('work', WORK);
        checkout('personal', 'https://github.com/someone/dotfiles.git');
        expect(
          captureScopeKey({ session_id: 's', cwd: work }, join('..', 'personal', 'notes.md')),
        ).toBe('github.com/someone/dotfiles');
      });

      it('passes no key for a path that escapes into no checkout, rather than the cwd key', () => {
        const work = checkout('work', WORK);
        mkdirSync(join(root, 'loose'), { recursive: true });
        expect(
          captureScopeKey({ session_id: 's', cwd: work }, join('..', 'loose', 'notes.md')),
        ).toBeUndefined();
      });

      it('passes no key when the cwd is not absolute, or is empty', () => {
        // Resolved against the hook's own directory it would name whatever
        // repository the process happens to run in.
        const work = checkout('work', WORK);
        const home = process.cwd();
        process.chdir(work);
        try {
          expect(captureScopeKey({ session_id: 's', cwd: '.' }, 'notes.md')).toBeUndefined();
          expect(captureScopeKey({ session_id: 's', cwd: '' }, 'notes.md')).toBeUndefined();
          // The control: the same checkout, named absolutely, keys.
          expect(captureScopeKey({ session_id: 's', cwd: work }, 'notes.md')).toBe(WORK_KEY);
        } finally {
          process.chdir(home);
        }
      });

      it('reads the path against the hook process cwd when the payload names none', () => {
        const work = checkout('work', WORK);
        checkout('personal', 'https://github.com/someone/dotfiles.git');
        const spy = vi.spyOn(process, 'cwd').mockReturnValue(work);
        try {
          expect(captureScopeKey({ session_id: 's' }, 'notes.md')).toBe(WORK_KEY);
          expect(captureScopeKey({ session_id: 's' }, join('..', 'personal', 'notes.md'))).toBe(
            'github.com/someone/dotfiles',
          );
        } finally {
          spy.mockRestore();
        }
      });
    });

    it('keys a file inside the cwd checkout like the cwd, walking up from the file', () => {
      const work = checkout('work', WORK);
      const deep = join(work, 'src', 'deep');
      vi.mocked(resolveRepoAttribution).mockClear();
      expect(captureScopeKey({ session_id: 's', cwd: work }, join(deep, 'index.ts'))).toBe(
        WORK_KEY,
      );
      expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[deep]]);
    });

    it('keys a file in a checkout nested inside the cwd checkout by the nested one', () => {
      const work = checkout('work', WORK);
      const nested = checkout(join('work', 'vendor', 'lib'), 'https://github.com/someone/lib.git');
      expect(captureScopeKey({ cwd: work }, join(nested, 'index.ts'))).toBe(
        'github.com/someone/lib',
      );
    });

    it('does not climb back into a checkout that a `..` segment left', () => {
      const work = checkout('work', WORK);
      mkdirSync(join(root, 'loose'), { recursive: true });
      // Spelled with a literal `..`: join() would normalise it away.
      const filePath = [work, '..', 'loose', 'notes.md'].join(sep);
      expect(captureScopeKey({ cwd: work }, filePath)).toBeUndefined();
    });
  });
});
