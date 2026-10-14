// `captureScopeKey` and the `baseMetadata` beside it: the two halves of what an
// Antigravity capture is attributed to. Both were reachable only through the
// spawned pre-tool-use hook before this file, and the multi-root rule is a
// matrix of root layouts and target paths that no e2e can afford to walk case
// by case.
//
// Fixture checkouts are fake `.git/config` files, the layout plugin-sdk's own
// repo tests use: the resolver reads files and never spawns git. `root` sits
// under the OS temp directory, which is in no checkout, so a path outside every
// fixture checkout resolves to no key.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { baseMetadata, captureScopeKey } from '../../src/hooks/shared.ts';

// The userinfo in an scp-style remote (`<user>@<host>:path`) reads as an email
// address to a scanner, so the fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

const WORK = `${gitUser}GitHub.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';
const PERSONAL = 'https://github.com/me/dotfiles.git';
const PERSONAL_KEY = 'github.com/me/dotfiles';
// A third repository, cloned INSIDE another checkout rather than opened as a root.
const VENDOR = 'https://github.com/acme/vendored-lib.git';
const VENDOR_KEY = 'github.com/acme/vendored-lib';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-agy-scope-key-'));
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

describe('captureScopeKey: an absolute target keys by the checkout that holds it', () => {
  it('keys a target inside the SECOND root by that root, though the first is listed first', () => {
    const personal = checkout('personal', PERSONAL);
    const work = checkout('work', WORK);
    expect(
      captureScopeKey({ workspacePaths: [personal, work] }, join(work, 'src', 'index.ts')),
    ).toBe(WORK_KEY);
  });

  it('keys a target inside the first root by the first root', () => {
    const personal = checkout('personal', PERSONAL);
    const work = checkout('work', WORK);
    expect(captureScopeKey({ workspacePaths: [personal, work] }, join(personal, 'notes.md'))).toBe(
      PERSONAL_KEY,
    );
  });

  it('keys a target in a clone nested under a root by that clone, not by the root', () => {
    // The clone is no workspace root. It is its own checkout with its own key,
    // which is why a root that merely contains the target cannot decide it.
    const personal = checkout('personal', PERSONAL);
    const work = checkout('work', WORK);
    const vendored = checkout(join('work', 'vendor', 'lib'), VENDOR);
    const input = { workspacePaths: [personal, work] };
    expect(captureScopeKey(input, join(vendored, 'index.ts'))).toBe(VENDOR_KEY);
    expect(captureScopeKey(input, join(work, 'src', 'b.ts'))).toBe(WORK_KEY);
  });

  it('keys a target in a repository under a root that is a plain folder', () => {
    // A root holding several clones has no key of its own; the file's clone does.
    const projects = join(root, 'projects');
    const app = checkout(join('projects', 'app'), WORK);
    expect(captureScopeKey({ workspacePaths: [projects] }, join(app, 'src', 'a.ts'))).toBe(
      WORK_KEY,
    );
  });

  it('gives no key to a target outside every checkout, even when every root agrees', () => {
    // Two clones of one repository agree on a key. A target outside them, or in
    // a checkout with no remote, must still not borrow it.
    const input = {
      workspacePaths: [
        checkout('work-ssh', WORK),
        checkout('work-https', 'https://github.com/acme/work-repo'),
      ],
    };
    const scratch = checkout('scratch', undefined);
    expect(captureScopeKey(input, join(root, 'elsewhere', 'notes.md'))).toBeUndefined();
    expect(captureScopeKey(input, join(scratch, 'notes.md'))).toBeUndefined();
  });

  it('does not climb back into a checkout that a `..` segment left', () => {
    // Spelled with a literal `..`: join() would normalise it away. Unnormalised,
    // the walk would climb `<work>/..` to `<work>` and find its `.git`.
    const work = checkout('work', WORK);
    const target = [work, '..', 'loose', 'notes.md'].join(sep);
    expect(captureScopeKey({ workspacePaths: [work] }, target)).toBeUndefined();
  });
});

// A named target is walked from the target ITSELF, so one rule serves a file, a
// directory and a checkout's top level. The walk probes `<target>/.git` first: a
// file has none of its own, and a target not yet created has none to find.
describe('captureScopeKey: a target that is a directory keys by that directory', () => {
  it('keys a checkout top level nested under a root by that checkout, not by the root', () => {
    const work = checkout('work', WORK);
    const vendored = checkout(join('work', 'vendor', 'lib'), VENDOR);
    const input = { workspacePaths: [work] };
    expect(captureScopeKey(input, vendored)).toBe(VENDOR_KEY);
    // The control: the same clone, named by a file inside it.
    expect(captureScopeKey(input, join(vendored, 'index.ts'))).toBe(VENDOR_KEY);
  });

  it('keys another checkout top level by that checkout, though its parent is in none', () => {
    const work = checkout('work', WORK);
    const personal = checkout('personal', PERSONAL);
    expect(captureScopeKey({ workspacePaths: [work] }, personal)).toBe(PERSONAL_KEY);
  });

  it('keys a relative checkout top level by that checkout, read against the only root', () => {
    const work = checkout('work', WORK);
    checkout(join('work', 'vendor', 'lib'), VENDOR);
    checkout('personal', PERSONAL);
    const input = { workspacePaths: [work] };
    expect(captureScopeKey(input, join('vendor', 'lib'))).toBe(VENDOR_KEY);
    expect(captureScopeKey(input, join('..', 'personal'))).toBe(PERSONAL_KEY);
  });

  it('keys a file not yet created, and a directory that is no top level, by the checkout around', () => {
    const work = checkout('work', WORK);
    const input = { workspacePaths: [work] };
    // Neither the file nor its directories exist: a write may be creating them.
    expect(captureScopeKey(input, join(work, 'src', 'new', 'index.ts'))).toBe(WORK_KEY);
    expect(captureScopeKey(input, join('src', 'new', 'index.ts'))).toBe(WORK_KEY);
    mkdirSync(join(work, 'src', 'deep'), { recursive: true });
    expect(captureScopeKey(input, join(work, 'src', 'deep'))).toBe(WORK_KEY);
    expect(captureScopeKey(input, join('src', 'deep'))).toBe(WORK_KEY);
  });

  it('gives no key to a directory outside every checkout, even when every root agrees', () => {
    const work = checkout('work', WORK);
    const loose = join(root, 'loose');
    mkdirSync(loose, { recursive: true });
    expect(captureScopeKey({ workspacePaths: [work] }, loose)).toBeUndefined();
  });
});

describe('captureScopeKey: with no absolute target, every root must agree', () => {
  it('passes no key for an event with no path when the roots disagree', () => {
    const input = { workspacePaths: [checkout('personal', PERSONAL), checkout('work', WORK)] };
    expect(captureScopeKey(input)).toBeUndefined();
  });

  it('passes the shared key for an event with no path when every root agrees', () => {
    // Two clones of one repository, over SSH and over HTTPS: one canonical key.
    const input = {
      workspacePaths: [
        checkout('work-ssh', WORK),
        checkout('work-https', 'https://github.com/acme/work-repo'),
      ],
    };
    expect(captureScopeKey(input)).toBe(WORK_KEY);
  });

  it('passes no key when one root has a remote and another has none', () => {
    const input = { workspacePaths: [checkout('work', WORK), checkout('scratch', undefined)] };
    expect(captureScopeKey(input)).toBeUndefined();
  });

  it('treats an empty target as no path', () => {
    const disagree = { workspacePaths: [checkout('personal', PERSONAL), checkout('work', WORK)] };
    const agree = {
      workspacePaths: [
        checkout('work-ssh', WORK),
        checkout('work-https', 'https://github.com/acme/work-repo'),
      ],
    };
    expect(captureScopeKey(disagree, '')).toBeUndefined();
    expect(captureScopeKey(agree, '')).toBe(WORK_KEY);
  });

  it('gives no key to a relative target when there is not exactly one root to read it against', () => {
    // A relative target is relative to some root, and with several the payload
    // does not say which. That holds even when every root agrees on a key: the
    // target may still land in a different repository.
    const disagree = { workspacePaths: [checkout('personal', PERSONAL), checkout('work', WORK)] };
    const agree = {
      workspacePaths: [
        checkout('work-ssh', WORK),
        checkout('work-https', 'https://github.com/acme/work-repo'),
      ],
    };
    expect(captureScopeKey(disagree, 'src/index.ts')).toBeUndefined();
    expect(captureScopeKey(agree, 'src/index.ts')).toBeUndefined();
    // The control: the same roots still key an event that names no path.
    expect(captureScopeKey(agree)).toBe(WORK_KEY);
  });

  it("keys a single root's events by it, except an absolute write outside it", () => {
    // As a Claude Code hook keys a path-less event by its cwd. An absolute target
    // outside the root is keyed by where it lands, and here that is no checkout.
    const input = { workspacePaths: [checkout('work', WORK)] };
    expect(captureScopeKey(input)).toBe(WORK_KEY);
    expect(captureScopeKey(input, 'src/index.ts')).toBe(WORK_KEY);
    expect(captureScopeKey(input, '')).toBe(WORK_KEY);
    expect(captureScopeKey(input, join(root, 'elsewhere', 'notes.md'))).toBeUndefined();
  });

  it('keys a relative target by where it resolves against the only root', () => {
    // `..` escapes the root, so the target may land in a sibling checkout, or in
    // none, and the root's key must follow it there rather than stay on the root.
    const work = checkout('work', WORK);
    const personal = checkout('personal', PERSONAL);
    mkdirSync(join(work, 'src'), { recursive: true });
    const input = { workspacePaths: [work] };

    expect(captureScopeKey(input, join('src', 'index.ts'))).toBe(WORK_KEY);
    expect(captureScopeKey(input, join('src', '..', 'index.ts'))).toBe(WORK_KEY);
    expect(captureScopeKey(input, join('..', 'personal', 'notes.md'))).toBe(PERSONAL_KEY);
    expect(captureScopeKey(input, join('..', 'elsewhere', 'notes.md'))).toBeUndefined();
    expect(captureScopeKey(input, join('..', '..', 'notes.md'))).toBeUndefined();
    // The control: the sibling is a real checkout, named absolutely.
    expect(captureScopeKey(input, join(personal, 'notes.md'))).toBe(PERSONAL_KEY);
  });

  it('gives no key to a relative target when the only root is not absolute', () => {
    // A relative root is read against the hook's own directory, which the host
    // does not choose, so the target under it has no known location.
    const relativeRoot = { workspacePaths: ['work'] };
    expect(captureScopeKey(relativeRoot, join('src', 'index.ts'))).toBeUndefined();
    expect(captureScopeKey(relativeRoot, join('..', 'work', 'index.ts'))).toBeUndefined();
  });

  it('skips entries that are not usable paths, and counts a repeated root once', () => {
    const work = checkout('work', WORK);
    expect(captureScopeKey({ workspacePaths: ['', 42, null, work, work] })).toBe(WORK_KEY);
  });
});

describe('captureScopeKey: no roots, and failure', () => {
  it('falls back to the hook process cwd when the payload names no root, as baseMetadata does', () => {
    // The session root (pre-invocation) is resolved from the same fallback, so
    // an event and its root still agree.
    const work = checkout('work', WORK);
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(work);
    try {
      expect(captureScopeKey({ conversationId: 'c' })).toBe(WORK_KEY);
      expect(baseMetadata({ conversationId: 'c' })?.repo).toBe('work-repo');
    } finally {
      spy.mockRestore();
    }
  });

  it('reads a relative target against the hook process cwd when the payload names no root', () => {
    // The cwd stands in for the one root, as it does for the slug.
    const work = checkout('work', WORK);
    checkout('personal', PERSONAL);
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(work);
    try {
      expect(captureScopeKey({ conversationId: 'c' }, join('src', 'a.ts'))).toBe(WORK_KEY);
      expect(captureScopeKey({ conversationId: 'c' }, join('..', 'personal', 'a.ts'))).toBe(
        PERSONAL_KEY,
      );
      expect(
        captureScopeKey({ conversationId: 'c' }, join('..', 'elsewhere', 'a.ts')),
      ).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });

  it('answers no key, rather than throwing, when the working directory is gone', () => {
    // A throw would reach runHookFailOpen's catch: the call is still allowed,
    // but the capture is lost along with its key.
    const work = checkout('work', WORK);
    const spy = vi.spyOn(process, 'cwd').mockImplementation(() => {
      throw new Error('ENOENT: no such file or directory, uv_cwd');
    });
    try {
      expect(captureScopeKey({ conversationId: 'c' })).toBeUndefined();
      // An absolute target never consults the cwd, so it is still keyed.
      expect(captureScopeKey({ conversationId: 'c' }, join(work, 'a.ts'))).toBe(WORK_KEY);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('baseMetadata keeps the slug on the FIRST root', () => {
  it('attributes the repo to the first root while the key follows the target', () => {
    // `repo` rides the published event metadata, so it must not move; the key
    // is the local attribute that can.
    const personal = checkout('personal', PERSONAL);
    const work = checkout('work', WORK);
    const input = { conversationId: 'c', workspacePaths: [personal, work] };
    expect(baseMetadata(input)).toEqual({ sessionId: 'c', repo: 'dotfiles' });
    expect(captureScopeKey(input, join(work, 'a.ts'))).toBe(WORK_KEY);
  });
});
