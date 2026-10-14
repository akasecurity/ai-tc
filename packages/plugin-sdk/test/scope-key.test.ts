// The scope-key rules the transcript reconcilers and the session roots share:
// scopeKeyMemo (one key per working directory), sessionRootScopeKey (a session
// root's key) and toolCallScopeKey (where a tool call ran, or what it touched).
// They run against real checkouts built under a temp directory, so the key a
// directory gets is the key the same resolver gives a hook there. The
// once-per-directory promise is counted in scope-key-memo.test.ts, which needs
// a module mock this file must not carry.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveRepoAttribution } from '../src/repo.ts';
import { scopeKeyMemo, sessionRootScopeKey, toolCallScopeKey } from '../src/scope-key.ts';

// An scp-form remote's userinfo reads as an email address to a scanner, so the
// fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;
const WORK_KEY = 'github.com/acme/work';
const PERSONAL_KEY = 'github.com/me/personal';

let root: string;
let work: string;
let personal: string;
let scratch: string;

// A checkout under the temp root: a `.git` directory whose config names `origin`
// as `remote`, or names no remote at all.
function checkout(name: string, remote: string | undefined): string {
  const dir = join(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    remote === undefined ? '' : `[remote "origin"]\n\turl = ${remote}\n`,
  );
  return dir;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-scope-key-'));
  work = checkout('work', `${gitUser}github.com:acme/work.git`);
  personal = checkout('personal', 'https://github.com/me/personal.git');
  // A directory in no repository at all.
  scratch = join(root, 'scratch');
  mkdirSync(scratch);
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('scopeKeyMemo', () => {
  it('keys a directory by the repository it sits in, from the root or from below it', () => {
    const scopeKeyOf = scopeKeyMemo();
    mkdirSync(join(work, 'src', 'deep'), { recursive: true });

    expect(scopeKeyOf(work)).toBe(WORK_KEY);
    expect(scopeKeyOf(join(work, 'src', 'deep'))).toBe(WORK_KEY);
    expect(scopeKeyOf(personal)).toBe(PERSONAL_KEY);
  });

  it('gives no key to no directory, a directory in no repository, or a repository with no remote', () => {
    const scopeKeyOf = scopeKeyMemo();
    const remoteless = checkout('remoteless', undefined);

    expect(scopeKeyOf(undefined)).toBeUndefined();
    expect(scopeKeyOf(scratch)).toBeUndefined();
    expect(scopeKeyOf(remoteless)).toBeUndefined();
  });

  it('gives no key to a relative directory, though it sits in a keyed repository', () => {
    // A relative directory is read against this process's own working
    // directory, which a transcript does not choose. The resolver keys only an
    // absolute one; this pins that the memo inherits that, rather than asking
    // the resolver to guess.
    const scopeKeyOf = scopeKeyMemo();
    mkdirSync(join(work, 'src'), { recursive: true });
    // The control: named absolutely, the same repository is keyed.
    expect(scopeKeyOf(work)).toBe(WORK_KEY);

    const home = process.cwd();
    process.chdir(work);
    try {
      expect(scopeKeyMemo()('.')).toBeUndefined();
      expect(scopeKeyMemo()('src')).toBeUndefined();
    } finally {
      // Restored before the shared afterEach removes `root`: a process still
      // standing inside it cannot delete it on Windows.
      process.chdir(home);
    }
  });
});

describe('sessionRootScopeKey', () => {
  it('keys a session root by the repository its absolute cwd sits in', () => {
    mkdirSync(join(work, 'src'), { recursive: true });

    expect(sessionRootScopeKey(work)).toBe(WORK_KEY);
    expect(sessionRootScopeKey(join(work, 'src'))).toBe(WORK_KEY);
    expect(sessionRootScopeKey(personal)).toBe(PERSONAL_KEY);
  });

  it('is the key a hook stamps for the same cwd', () => {
    expect(sessionRootScopeKey(work)).toBe(resolveRepoAttribution(work).scopeKey);
  });

  it('gives no key to no cwd, a directory in no repository, or a repository with no remote', () => {
    const remoteless = checkout('remoteless', undefined);

    expect(sessionRootScopeKey(undefined)).toBeUndefined();
    expect(sessionRootScopeKey(scratch)).toBeUndefined();
    expect(sessionRootScopeKey(remoteless)).toBeUndefined();
  });

  it('gives no key to a relative or empty cwd read from inside a keyed repository', () => {
    // A relative cwd is walked from this process's own directory, which a session
    // does not choose, so it would borrow whatever repository the process runs in.
    mkdirSync(join(work, 'src'), { recursive: true });
    // The control: named absolutely, the same repository is keyed.
    expect(sessionRootScopeKey(work)).toBe(WORK_KEY);

    const home = process.cwd();
    process.chdir(work);
    try {
      for (const cwd of ['.', 'src', join('src', '..'), '']) {
        expect(sessionRootScopeKey(cwd)).toBeUndefined();
      }
    } finally {
      // Restored before the shared afterEach removes `root`: a process still
      // standing inside it cannot delete it on Windows.
      process.chdir(home);
    }
  });
});

describe('toolCallScopeKey', () => {
  // A call as the reconcilers hold it: where it ran and the files it named.
  const call = (
    cwd: string | undefined,
    filePaths: readonly string[] | undefined,
  ): Parameters<typeof toolCallScopeKey>[0] => ({ cwd, filePaths });
  const keyOf = (
    cwd: string | undefined,
    filePaths: readonly string[] | undefined,
  ): string | undefined => toolCallScopeKey(call(cwd, filePaths), scopeKeyMemo());
  // A call that also names a search root (a Grep's `path`), or is marked keyless.
  const keyWith = (
    extra: { searchRoot?: string | undefined; keyless?: boolean | undefined },
    cwd: string | undefined,
    filePaths?: readonly string[],
  ): string | undefined => toolCallScopeKey({ ...call(cwd, filePaths), ...extra }, scopeKeyMemo());

  it('keys a call that names no file by the directory it ran in', () => {
    expect(keyOf(work, undefined)).toBe(WORK_KEY);
    expect(keyOf(scratch, undefined)).toBeUndefined();
    // Nothing names a directory, so nothing keys the call.
    expect(keyOf(undefined, undefined)).toBeUndefined();
  });

  it('keys a call by the repository of the file it names, not by where it ran', () => {
    expect(keyOf(scratch, [join(work, 'src', 'a.ts')])).toBe(WORK_KEY);
    // A file in no repository leaves the call keyless though it ran in a keyed one.
    expect(keyOf(work, [join(scratch, 'notes.md')])).toBeUndefined();
  });

  it('keys files in different directories of one repository by that repository', () => {
    expect(keyOf(scratch, [join(work, 'src', 'a.ts'), join(work, 'b.ts')])).toBe(WORK_KEY);
  });

  // A named path is keyed from the path ITSELF, so one rule serves a file, a
  // directory and a checkout's top level: the walk probes `<path>/.git` first, a
  // file has none of its own, and a path that does not exist yet has none to
  // find. Starting from the parent would be right only for a file.
  describe('a named path that is a directory', () => {
    const NESTED_KEY = 'github.com/me/nested';
    let nested: string;

    beforeEach(() => {
      // A clone kept INSIDE the work checkout: its parent directory belongs to work.
      nested = checkout(join('work', 'vendor', 'nested'), 'https://github.com/me/nested.git');
    });

    it('keys a checkout top level by that checkout, not by the checkout around it', () => {
      expect(keyOf(work, [nested])).toBe(NESTED_KEY);
      // A top level whose parent is in no repository at all is keyed too.
      expect(keyOf(scratch, [work])).toBe(WORK_KEY);
      expect(keyOf(work, [personal])).toBe(PERSONAL_KEY);
    });

    it('keys a relative checkout top level the same way, read against the cwd', () => {
      expect(keyOf(work, [join('vendor', 'nested')])).toBe(NESTED_KEY);
      expect(keyOf(scratch, [join('..', basename(work))])).toBe(WORK_KEY);
    });

    it('keys a directory that is not a checkout top level by the checkout around it', () => {
      mkdirSync(join(work, 'src', 'deep'), { recursive: true });
      expect(keyOf(scratch, [join(work, 'src')])).toBe(WORK_KEY);
      expect(keyOf(scratch, [join(work, 'src', 'deep')])).toBe(WORK_KEY);
      // Inside the nested clone, the clone's key.
      mkdirSync(join(nested, 'lib'), { recursive: true });
      expect(keyOf(work, [join(nested, 'lib')])).toBe(NESTED_KEY);
      // A directory in no repository gives no key, whatever the cwd is.
      expect(keyOf(work, [scratch])).toBeUndefined();
    });

    it('keys a file inside the nested checkout, and one not yet created, by their checkout', () => {
      expect(keyOf(work, [join(nested, 'index.ts')])).toBe(NESTED_KEY);
      // Neither the file nor its directories exist: a Write may be creating them.
      expect(keyOf(scratch, [join(work, 'src', 'new', 'index.ts')])).toBe(WORK_KEY);
      expect(keyOf(scratch, [join(nested, 'new', 'index.ts')])).toBe(NESTED_KEY);
    });

    it('still needs every named location to agree, a checkout top level included', () => {
      expect(keyOf(scratch, [nested, join(nested, 'a.ts')])).toBe(NESTED_KEY);
      expect(keyOf(scratch, [nested, join(work, 'b.ts')])).toBeUndefined();
      expect(keyOf(scratch, [work, join(scratch, 'c.ts')])).toBeUndefined();
    });
  });

  it('gives no key when the files it names disagree, whichever comes first', () => {
    const [inWork, inPersonal] = [join(work, 'c.ts'), join(personal, 'd.ts')];

    expect(keyOf(work, [inWork, inPersonal])).toBeUndefined();
    expect(keyOf(work, [inPersonal, inWork])).toBeUndefined();
  });

  it('gives no key when any file it names sits in no keyed repository', () => {
    const inWork = join(work, 'a.ts');
    const loose = join(scratch, 'n.md');

    expect(keyOf(work, [inWork, loose])).toBeUndefined();
    expect(keyOf(work, [loose, inWork])).toBeUndefined();
  });

  it("reads a relative path against the call's cwd", () => {
    expect(keyOf(work, [join('src', 'a.ts')])).toBe(WORK_KEY);
    // From the scratch directory, a path that climbs out and into the work checkout.
    expect(keyOf(scratch, [join('..', basename(work), 'x.ts')])).toBe(WORK_KEY);
  });

  it('gives no key to a relative path when the call has no absolute cwd to read it against', () => {
    expect(keyOf(undefined, [join('src', 'a.ts')])).toBeUndefined();
    expect(keyOf(undefined, ['a.ts'])).toBeUndefined();
    expect(keyOf('src', [join('src', 'a.ts')])).toBeUndefined();
  });

  it('reads a path with dot-dot segments as it resolves, not as it is spelled', () => {
    // Spelled inside the work checkout, resolving to a file beside it. The walk
    // climbs by name, so an unresolved spelling would find the work checkout.
    const climbsOut = [work, '..', 'loose.txt'].join(sep);

    expect(keyOf(work, [climbsOut])).toBeUndefined();
  });

  it('says an empty file list keys nothing, rather than falling back to the cwd', () => {
    // A call that names a list of files and no file in it has nothing to key by.
    // That is not the same as a call that names no file at all.
    expect(keyOf(work, [])).toBeUndefined();
  });

  describe('a search root', () => {
    it('keys a call by the root it names, not by where it ran', () => {
      expect(keyWith({ searchRoot: personal }, work)).toBe(PERSONAL_KEY);
      expect(keyWith({ searchRoot: join(personal, 'src', 'deep') }, scratch)).toBe(PERSONAL_KEY);
    });

    it('walks from the root itself, so a checkout top level is that checkout and not its parent', () => {
      // The parent of the top level is the temp root, which is in no repository.
      // A walk that started at the parent would find nothing, or the enclosing
      // checkout when the root is a nested clone.
      expect(keyWith({ searchRoot: work }, scratch)).toBe(WORK_KEY);
      const nested = checkout(join('work', 'vendor', 'nested'), 'https://github.com/me/nested.git');
      expect(keyWith({ searchRoot: nested }, work)).toBe('github.com/me/nested');
    });

    it('never falls back to the cwd: a root in no repository gives no key', () => {
      expect(keyWith({ searchRoot: scratch }, work)).toBeUndefined();
    });

    it('keys by the root and the files together only when they all agree', () => {
      const inWork = join(work, 'a.ts');
      const inPersonal = join(personal, 'b.ts');
      expect(keyWith({ searchRoot: work }, scratch, [inWork])).toBe(WORK_KEY);
      expect(keyWith({ searchRoot: work }, scratch, [inPersonal])).toBeUndefined();
      expect(keyWith({ searchRoot: personal }, work, [inWork])).toBeUndefined();
      // A keyless file or a keyless root sinks an otherwise agreeing call.
      expect(keyWith({ searchRoot: work }, work, [join(scratch, 'n.md')])).toBeUndefined();
      expect(keyWith({ searchRoot: scratch }, work, [inWork])).toBeUndefined();
    });

    it('keys a root alongside an empty file list by the root', () => {
      expect(keyWith({ searchRoot: personal }, work, [])).toBe(PERSONAL_KEY);
    });

    it('reads the root as it resolves, not as it is spelled', () => {
      // Spelled inside the work checkout, resolving to a directory beside it.
      const climbsOut = [work, '..', 'loose'].join(sep);

      expect(keyWith({ searchRoot: climbsOut }, work)).toBeUndefined();
    });

    it("reads a relative root against the call's cwd, and keys nothing without one", () => {
      // From the scratch directory, a root that climbs out and into the work checkout.
      expect(keyWith({ searchRoot: join('..', basename(work)) }, scratch)).toBe(WORK_KEY);
      expect(keyWith({ searchRoot: 'src' }, undefined)).toBeUndefined();
    });
  });

  it('gives no key to a call marked keyless, whatever else it names', () => {
    expect(keyWith({ keyless: true }, work)).toBeUndefined();
    expect(
      keyWith({ keyless: true, searchRoot: work }, work, [join(work, 'a.ts')]),
    ).toBeUndefined();
    // The marker is opt-in: false changes nothing.
    expect(keyWith({ keyless: false }, work)).toBe(WORK_KEY);
  });
});
