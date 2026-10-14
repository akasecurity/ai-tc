import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import type * as PluginSdk from '@akasecurity/plugin-sdk';
import { readHookFailOpens, resolveRepo, resolveRepoAttribution } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseMetadata,
  captureScopeKey,
  countFailOpen,
  emit,
  readStdin,
  searchRootScopeKey,
} from '../../src/hooks/shared.ts';

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
// walk. The wrappers exist for the one-walk case at the bottom of this file,
// which asserts which resolver the metadata and the key ask, and with which
// directory.
vi.mock('@akasecurity/plugin-sdk', async (importActual) => {
  const actual = await importActual<typeof PluginSdk>();
  return {
    ...actual,
    resolveRepo: vi.fn((cwd: string) => actual.resolveRepo(cwd)),
    resolveRepoAttribution: vi.fn((cwd: string) => actual.resolveRepoAttribution(cwd)),
  };
});

describe('readStdin', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('resolves with the accumulated chunks once stdin ends normally', async () => {
    const promise = readStdin();
    process.stdin.emit('data', 'hello ');
    process.stdin.emit('data', 'world');
    process.stdin.emit('end');
    await expect(promise).resolves.toBe('hello world');
  });

  it('resolves with whatever was read so far instead of throwing on a stdin error', async () => {
    const promise = readStdin();
    process.stdin.emit('data', 'partial');
    process.stdin.emit('error', new Error('simulated stdin failure'));
    await expect(promise).resolves.toBe('partial');
  });

  it('resolves with whatever was read so far after a 5s stall, instead of hanging forever', async () => {
    vi.useFakeTimers();
    const promise = readStdin();
    process.stdin.emit('data', 'stalled');
    vi.advanceTimersByTime(5_000);
    await expect(promise).resolves.toBe('stalled');
  });

  it('removes its data/end listeners once settled, but keeps guarding against a later error', async () => {
    const before = {
      data: process.stdin.listenerCount('data'),
      end: process.stdin.listenerCount('end'),
      error: process.stdin.listenerCount('error'),
    };

    const promise = readStdin();
    process.stdin.emit('data', 'value');
    process.stdin.emit('end');
    await expect(promise).resolves.toBe('value');

    // data/end are genuinely done with — no reason to keep listening.
    expect(process.stdin.listenerCount('data')).toBe(before.data);
    expect(process.stdin.listenerCount('end')).toBe(before.end);
    // error is deliberately NOT removed (see shared.ts) — one more listener
    // than before, and a late error must not re-resolve or throw.
    expect(process.stdin.listenerCount('error')).toBe(before.error + 1);
    expect(() => process.stdin.emit('error', new Error('late, after settle'))).not.toThrow();
    await expect(promise).resolves.toBe('value');
  });

  it('clears its own pending timer once settled (no leaked timer past a normal end)', async () => {
    vi.useFakeTimers();
    const promise = readStdin();
    process.stdin.emit('end');
    await promise;
    // If the timeout were still pending, advancing past it would throw were
    // `finish` not idempotent — this just proves it's already been cleared.
    expect(() => vi.advanceTimersByTime(5_000)).not.toThrow();
  });
});

describe('emit', () => {
  it('resolves once the underlying write flushes', async () => {
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((
      _chunk: string,
      cb: () => void,
    ) => {
      cb();
      return true;
    }) as typeof process.stdout.write);

    await expect(emit({ systemMessage: 'ok' })).resolves.toBeUndefined();
    expect(writeSpy).toHaveBeenCalledWith(
      JSON.stringify({ systemMessage: 'ok' }),
      expect.any(Function),
    );

    writeSpy.mockRestore();
  });

  it('resolves instead of throwing when stdout emits an error before the write callback fires', async () => {
    const writeSpy = vi
      .spyOn(process.stdout, 'write')
      // A broken pipe (EPIPE) surfaces as an 'error' event, not a write callback.
      .mockImplementation(() => true);

    const promise = emit({ systemMessage: 'ok' });
    process.stdout.emit('error', new Error('EPIPE'));

    await expect(promise).resolves.toBeUndefined();
    writeSpy.mockRestore();
  });

  it('keeps its error listener attached after settling, so a later error still can not crash the process', async () => {
    const before = process.stdout.listenerCount('error');
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((
      _chunk: string,
      cb: () => void,
    ) => {
      cb();
      return true;
    }) as typeof process.stdout.write);

    await emit({ systemMessage: 'ok' });

    // Deliberately NOT removed (see shared.ts) — one more listener than
    // before, guarding against any stdout error between resolving and exit.
    expect(process.stdout.listenerCount('error')).toBe(before + 1);
    writeSpy.mockRestore();
  });
});

describe('countFailOpen', () => {
  // Called from inside every hook entry's top-level catch. Two things have to
  // hold there and nowhere else matters as much: it must never throw (a throw
  // inside that catch escapes as an uncaught exception and turns a silent
  // allow into a non-zero exit), and it must never print (the host reads an
  // empty stdout as "no opinion", and one byte would change that).
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-count-fail-open-'));
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
  // Fixture checkouts are fake `.git/config` files, the layout plugin-sdk's own
  // repo tests use: the resolver reads files and never spawns git.
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-scope-key-'));
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
    // Scheme, userinfo and `.git` dropped, host lowercased, path case kept.
    const repo = checkout('work', 'git@GitHub.com:acme/work-repo.git');
    expect(captureScopeKey({ session_id: 's', cwd: repo })).toBe('github.com/acme/work-repo');
  });

  it('keys a subdirectory of a checkout like the checkout itself', () => {
    const repo = checkout('work', 'https://github.com/acme/work-repo.git');
    const sub = join(repo, 'src', 'deep');
    mkdirSync(sub, { recursive: true });
    expect(captureScopeKey({ cwd: sub })).toBe('github.com/acme/work-repo');
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
    // No key keeps the event on a scoped machine: the fail-closed answer for an
    // identity that is machine-local or absent.
    expect(captureScopeKey({ session_id: 's', cwd: make() })).toBeUndefined();
  });

  it('falls back to the hook process cwd exactly as baseMetadata does', () => {
    // SessionStart resolves the session root from the same `cwd ?? process.cwd()`,
    // so the fallback is what keeps an event's key equal to its root's.
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
    // `process.cwd()` throws on a deleted directory. Escaping here would reach
    // the hook's outer catch and cost the capture, not just its key.
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
    // One resolver, one directory. The resolver memoises per directory, so the
    // second call is a lookup rather than a second `.git` walk.
    expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[repo], [repo]]);
    expect(resolveRepo).not.toHaveBeenCalled();
  });

  // An event that names an ABSOLUTE file is keyed by that file's checkout,
  // whatever the session's cwd. A session that starts in a work repo and writes
  // into a personal one must have each write keyed where it landed.
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
      // One walk, from the named file itself. The cwd is not walked for the key.
      expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[join(personal, 'notes.md')]]);
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

    // A relative path names a location, read against the cwd. The cwd's key is
    // not a stand-in for it: a `..` leaves the checkout the session is in.
    describe('that is relative', () => {
      it('keys a file under the cwd checkout by it, walking up from the resolved file', () => {
        const work = checkout('work', WORK);
        vi.mocked(resolveRepoAttribution).mockClear();
        expect(captureScopeKey({ session_id: 's', cwd: work }, join('src', 'index.ts'))).toBe(
          WORK_KEY,
        );
        expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([
          [join(work, 'src', 'index.ts')],
        ]);
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
      // The directory need not exist: a Write may create it, and the walk climbs
      // by name until it meets the checkout's `.git`.
      const deep = join(work, 'src', 'deep');
      vi.mocked(resolveRepoAttribution).mockClear();
      expect(captureScopeKey({ session_id: 's', cwd: work }, join(deep, 'index.ts'))).toBe(
        WORK_KEY,
      );
      expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[join(deep, 'index.ts')]]);
    });

    it('keys a file in a checkout nested inside the cwd checkout by the nested one', () => {
      // Why there is no "the file is under the cwd root, reuse its key" shortcut.
      const work = checkout('work', WORK);
      const nested = checkout(join('work', 'vendor', 'lib'), 'https://github.com/someone/lib.git');
      expect(captureScopeKey({ cwd: work }, join(nested, 'index.ts'))).toBe(
        'github.com/someone/lib',
      );
    });

    // A named path is walked from the path ITSELF, so one rule serves a file, a
    // directory and a checkout's top level. The walk probes `<path>/.git` first:
    // a file has none of its own, and a path not yet created has none to find.
    describe('that is a directory', () => {
      it('keys a checkout top level nested inside the cwd checkout by the nested one', () => {
        const work = checkout('work', WORK);
        const nested = checkout(
          join('work', 'vendor', 'lib'),
          'https://github.com/someone/lib.git',
        );
        vi.mocked(resolveRepoAttribution).mockClear();
        expect(captureScopeKey({ session_id: 's', cwd: work }, nested)).toBe(
          'github.com/someone/lib',
        );
        // One walk, from the named path itself and not from its parent.
        expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[nested]]);
      });

      it('keys another checkout top level by that checkout, though its parent is in none', () => {
        const work = checkout('work', WORK);
        const personal = checkout('personal', 'https://github.com/someone/dotfiles.git');
        expect(captureScopeKey({ session_id: 's', cwd: work }, personal)).toBe(
          'github.com/someone/dotfiles',
        );
      });

      it('keys a relative checkout top level by that checkout, read against the cwd', () => {
        const work = checkout('work', WORK);
        checkout(join('work', 'vendor', 'lib'), 'https://github.com/someone/lib.git');
        checkout('personal', 'https://github.com/someone/dotfiles.git');
        expect(captureScopeKey({ session_id: 's', cwd: work }, join('vendor', 'lib'))).toBe(
          'github.com/someone/lib',
        );
        expect(captureScopeKey({ session_id: 's', cwd: work }, join('..', 'personal'))).toBe(
          'github.com/someone/dotfiles',
        );
      });

      it('keys a directory that is not a checkout top level by the checkout around it', () => {
        const work = checkout('work', WORK);
        const sub = join(work, 'src', 'deep');
        mkdirSync(sub, { recursive: true });
        expect(captureScopeKey({ session_id: 's', cwd: work }, sub)).toBe(WORK_KEY);
        // The control: inside the nested clone, the clone's key.
        const nested = checkout(
          join('work', 'vendor', 'lib'),
          'https://github.com/someone/lib.git',
        );
        mkdirSync(join(nested, 'src'), { recursive: true });
        expect(captureScopeKey({ cwd: work }, join(nested, 'src'))).toBe('github.com/someone/lib');
      });

      it('passes no key for a directory outside any checkout, rather than the cwd key', () => {
        const work = checkout('work', WORK);
        const loose = join(root, 'loose');
        mkdirSync(loose, { recursive: true });
        expect(captureScopeKey({ session_id: 's', cwd: work }, loose)).toBeUndefined();
      });
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

describe('searchRootScopeKey', () => {
  // The key for an event that names a search root (Grep's `path`): a directory
  // or one file, keyed by the nearest checkout of the root ITSELF.
  const WORK = 'git@github.com:acme/work-repo.git';
  const WORK_KEY = 'github.com/acme/work-repo';
  const PERSONAL = 'https://github.com/someone/dotfiles.git';
  const PERSONAL_KEY = 'github.com/someone/dotfiles';
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-search-root-key-'));
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

  it('keys a root that IS the top level of another checkout by that checkout', () => {
    // The case a walk from the parent directory gets wrong: the parent of a
    // checkout's top level is outside the checkout. A named file path is walked
    // from itself by the same rule.
    const work = checkout('work', WORK);
    const personal = checkout('personal', PERSONAL);
    vi.mocked(resolveRepoAttribution).mockClear();
    expect(searchRootScopeKey({ cwd: work }, personal)).toBe(PERSONAL_KEY);
    expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[personal]]);
  });

  it('keys a subdirectory root, and a single-file root, by the checkout they sit in', () => {
    const personal = checkout('personal', PERSONAL);
    mkdirSync(join(personal, 'src'), { recursive: true });
    writeFileSync(join(personal, 'src', 'a.txt'), 'x');
    const work = checkout('work', WORK);
    expect(searchRootScopeKey({ cwd: work }, join(personal, 'src'))).toBe(PERSONAL_KEY);
    expect(searchRootScopeKey({ cwd: work }, join(personal, 'src', 'a.txt'))).toBe(PERSONAL_KEY);
  });

  it('keys a root that is a nested clone inside the cwd checkout by the nested one', () => {
    // Starting from the root's parent would name the enclosing work checkout.
    const work = checkout('work', WORK);
    const nested = checkout(join('work', 'vendor', 'lib'), 'https://github.com/someone/lib.git');
    expect(searchRootScopeKey({ cwd: work }, nested)).toBe('github.com/someone/lib');
  });

  it.each([
    ['a root outside any checkout', () => join(root, 'loose')],
    ['a root in a checkout with no remote', () => checkout('scratch', undefined)],
  ])('passes no key for %s, rather than the cwd key', (_label, make) => {
    const work = checkout('work', WORK);
    mkdirSync(join(root, 'loose'), { recursive: true });
    expect(searchRootScopeKey({ cwd: work }, make())).toBeUndefined();
  });

  it.each([
    ['an empty root', ''],
    ['no root', undefined],
  ])('keys %s by the cwd, as an event that names no search root', (_label, searchRoot) => {
    const work = checkout('work', WORK);
    expect(searchRootScopeKey({ cwd: work }, searchRoot)).toBe(WORK_KEY);
  });

  // A relative root is read against the cwd and keyed from itself, as an
  // absolute one is. The cwd's key does not stand in for it: a `..` leaves the
  // checkout the session is in.
  describe('with a relative root', () => {
    it('keys a subdirectory of the cwd checkout by it, from the resolved root itself', () => {
      const work = checkout('work', WORK);
      vi.mocked(resolveRepoAttribution).mockClear();
      expect(searchRootScopeKey({ cwd: work }, 'src')).toBe(WORK_KEY);
      expect(vi.mocked(resolveRepoAttribution).mock.calls).toEqual([[join(work, 'src')]]);
    });

    it('keys a root that escapes onto the top level of a sibling checkout by that checkout', () => {
      const work = checkout('work', WORK);
      checkout('personal', PERSONAL);
      expect(searchRootScopeKey({ cwd: work }, join('..', 'personal'))).toBe(PERSONAL_KEY);
      expect(searchRootScopeKey({ cwd: work }, join('..', 'personal', 'src'))).toBe(PERSONAL_KEY);
    });

    it('passes no key for a root that escapes into no checkout, rather than the cwd key', () => {
      const work = checkout('work', WORK);
      mkdirSync(join(root, 'loose'), { recursive: true });
      expect(searchRootScopeKey({ cwd: work }, join('..', 'loose'))).toBeUndefined();
    });

    it('passes no key when the cwd is not absolute, or is empty', () => {
      const work = checkout('work', WORK);
      const home = process.cwd();
      process.chdir(work);
      try {
        expect(searchRootScopeKey({ cwd: '.' }, 'src')).toBeUndefined();
        expect(searchRootScopeKey({ cwd: '' }, 'src')).toBeUndefined();
        // The control: the same checkout, named absolutely, keys.
        expect(searchRootScopeKey({ cwd: work }, 'src')).toBe(WORK_KEY);
      } finally {
        process.chdir(home);
      }
    });

    it('reads the root against the hook process cwd when the payload names none', () => {
      const work = checkout('work', WORK);
      checkout('personal', PERSONAL);
      const spy = vi.spyOn(process, 'cwd').mockReturnValue(work);
      try {
        expect(searchRootScopeKey({ session_id: 's' }, 'src')).toBe(WORK_KEY);
        expect(searchRootScopeKey({ session_id: 's' }, join('..', 'personal'))).toBe(PERSONAL_KEY);
      } finally {
        spy.mockRestore();
      }
    });
  });

  it('does not climb back into a checkout that a `..` segment left', () => {
    const work = checkout('work', WORK);
    mkdirSync(join(root, 'loose'), { recursive: true });
    // Spelled with a literal `..`: join() would normalise it away.
    const searchRoot = [work, '..', 'loose'].join(sep);
    expect(searchRootScopeKey({ cwd: work }, searchRoot)).toBeUndefined();
  });

  it('answers no key, rather than throwing, when there is no root and no working directory', () => {
    const spy = vi.spyOn(process, 'cwd').mockImplementation(() => {
      throw new Error('ENOENT: no such file or directory, uv_cwd');
    });
    try {
      expect(searchRootScopeKey({ session_id: 's' })).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });
});
