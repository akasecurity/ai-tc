import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  resolveGitBranch,
  resolveHeadRoot,
  resolveRepo,
  resolveRepoIdentity,
  resolveRepoNwo,
  resolveWorktreeRoot,
} from '../src/repo.ts';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-repo-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

// Lay down a `.git` directory with the given config body at `dir`.
function gitDir(dir: string, config: string): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), config);
}

const ORIGIN = (url: string): string =>
  `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n`;

// The path fallback of resolveRepoIdentity is posix-normalized (see repo.ts) so
// persistence's `/`-separated checkout-path patterns match it; expectations must
// compare against that form, which only differs from the raw path on win32.
const posixPath = (p: string): string => p.split(sep).join('/');

// Lay down a parent repo at `dir` with a LINKED WORKTREE the way git does it:
// the worktree root's `.git` is a file pointing at `<parent>/.git/worktrees/<name>`,
// which points home via `commondir`. Returns the worktree root.
function linkedWorktree(dir: string, config: string, name = 'wt-checkout'): string {
  gitDir(dir, config);
  const gitdir = join(dir, '.git', 'worktrees', name);
  mkdirSync(gitdir, { recursive: true });
  writeFileSync(join(gitdir, 'commondir'), '../..\n');
  const wtRoot = join(dir, '.claude', 'worktrees', name);
  mkdirSync(wtRoot, { recursive: true });
  writeFileSync(join(wtRoot, '.git'), `gitdir: ${gitdir}\n`);
  return wtRoot;
}

// Lay down a BARE repo (config at its top level, no `.git` entry) under
// `root/repos/noremote.git` with a worktree at `root/checkout`, the way
// `git worktree add` does it for bare repos: the worktree's gitdir is
// `<bare>/worktrees/<name>`, pointing home via `commondir`. Returns the
// checkout root.
function bareRepoWorktree(config: string): string {
  const bare = join(root, 'repos', 'noremote.git');
  const gitdir = join(bare, 'worktrees', 'wt');
  mkdirSync(gitdir, { recursive: true });
  writeFileSync(join(bare, 'config'), config);
  writeFileSync(join(gitdir, 'commondir'), '../..\n');
  const checkout = join(root, 'checkout');
  mkdirSync(checkout, { recursive: true });
  writeFileSync(join(checkout, '.git'), `gitdir: ${gitdir}\n`);
  return checkout;
}

describe('resolveRepo', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveRepo(root)).toBeUndefined();
  });

  it('derives the slug from an ssh (scp-like) origin url', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    expect(resolveRepo(root)).toBe('payments-api');
  });

  it('derives the slug from an https origin url, with or without .git', () => {
    gitDir(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepo(root)).toBe('payments-api');

    gitDir(root, ORIGIN('https://github.com/org/payments-api'));
    expect(resolveRepo(root)).toBe('payments-api');
  });

  it('prefers the origin remote over other remotes', () => {
    gitDir(
      root,
      '[remote "upstream"]\n\turl = git@github.com:upstream/other.git\n' +
        '[remote "origin"]\n\turl = git@github.com:org/payments-api.git\n',
    );
    expect(resolveRepo(root)).toBe('payments-api');
  });

  it('falls back to the worktree basename when there is no remote', () => {
    gitDir(root, '[core]\n\tbare = false\n');
    expect(resolveRepo(root)).toBe(basename(root));
  });

  it('falls back to the checkout basename when a .git file points nowhere', () => {
    writeFileSync(join(root, '.git'), 'gitdir: /somewhere/.git/worktrees/x\n');
    expect(resolveRepo(root)).toBe(basename(root));
  });

  it('resolves a linked worktree to the parent repo slug', () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepo(wt)).toBe('payments-api');
  });

  it('walks up from a nested cwd to the repo root', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    const nested = join(root, 'apps', 'backend', 'src');
    mkdirSync(nested, { recursive: true });
    expect(resolveRepo(nested)).toBe('payments-api');
  });
});

describe('resolveRepoIdentity', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveRepoIdentity(root)).toBeUndefined();
  });

  it('returns the origin url (for content-addressing) and slug name', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    expect(resolveRepoIdentity(root)).toEqual({
      url: 'git@github.com:org/payments-api.git',
      name: 'payments-api',
    });
  });

  it('falls back to the worktree root as url and basename as name with no remote', () => {
    gitDir(root, '[core]\n\tbare = false\n');
    expect(resolveRepoIdentity(root)).toEqual({ url: posixPath(root), name: basename(root) });
  });

  it('resolves a linked worktree to the PARENT repo identity (same source_project row)', () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepoIdentity(wt)).toEqual({
      url: 'https://github.com/org/payments-api.git',
      name: 'payments-api',
    });
    // Identical to resolving from the parent itself — one content-addressed id.
    expect(resolveRepoIdentity(wt)).toEqual(resolveRepoIdentity(root));
  });

  it('resolves a linked worktree of a remote-less repo to the parent ROOT path', () => {
    const wt = linkedWorktree(root, '[core]\n\tbare = false\n');
    expect(resolveRepoIdentity(wt)).toEqual({ url: posixPath(root), name: basename(root) });
  });

  it('keeps a submodule (gitdir with its own config) as its own project', () => {
    gitDir(root, ORIGIN('https://github.com/org/parent.git'));
    const modGitdir = join(root, '.git', 'modules', 'lib');
    mkdirSync(modGitdir, { recursive: true });
    writeFileSync(join(modGitdir, 'config'), ORIGIN('https://github.com/org/lib.git'));
    const modRoot = join(root, 'lib');
    mkdirSync(modRoot, { recursive: true });
    // The RELATIVE gitdir form real `git submodule add` writes (resolved
    // against the checkout root), not an absolute path.
    writeFileSync(join(modRoot, '.git'), 'gitdir: ../.git/modules/lib\n');
    expect(resolveRepoIdentity(modRoot)).toEqual({
      url: 'https://github.com/org/lib.git',
      name: 'lib',
    });
  });

  it('anchors a worktree of a remote-less BARE repo on its own checkout, never the bare repo parent dir', () => {
    const checkout = bareRepoWorktree('[core]\n\tbare = true\n');
    // The common dir is the bare repo itself (not a `<checkout>/.git`), so its
    // dirname is the unrelated folder CONTAINING the repo — two bare repos kept
    // in one folder must not collapse into a single path-keyed identity.
    expect(resolveRepoIdentity(checkout)).toEqual({ url: posixPath(checkout), name: 'checkout' });
  });
});

describe('resolveRepoNwo', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveRepoNwo(root)).toBeUndefined();
  });

  it('derives owner/repo from an scp-like origin url', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    expect(resolveRepoNwo(root)).toBe('org/payments-api');
  });

  it('derives owner/repo from an https origin url', () => {
    gitDir(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepoNwo(root)).toBe('org/payments-api');
  });

  it('returns undefined for a remote-less repo (no owner to derive)', () => {
    gitDir(root, '[core]\n\tbare = false\n');
    expect(resolveRepoNwo(root)).toBeUndefined();
  });

  it('keeps the full owner path for a GitLab-style subgroup url', () => {
    gitDir(root, ORIGIN('https://gitlab.com/group/subgroup/payments-api.git'));
    expect(resolveRepoNwo(root)).toBe('group/subgroup/payments-api');
  });

  it('returns undefined for an owner-less url (never mistakes the host for the owner)', () => {
    gitDir(root, ORIGIN('https://example.com/payments-api.git'));
    expect(resolveRepoNwo(root)).toBeUndefined();
  });

  it('resolves a linked worktree to the PARENT repo owner/repo', () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepoNwo(wt)).toBe('org/payments-api');
  });
});

describe('resolveGitBranch', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveGitBranch(root)).toBeUndefined();
  });

  it('reads the current branch from HEAD on a normal clone', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    writeFileSync(join(root, '.git', 'HEAD'), 'ref: refs/heads/feat/idempotency\n');
    expect(resolveGitBranch(root)).toBe('feat/idempotency');
  });

  it('returns undefined for a detached HEAD (a bare sha, not a branch)', () => {
    gitDir(root, ORIGIN('git@github.com:org/payments-api.git'));
    writeFileSync(join(root, '.git', 'HEAD'), '9fceb02a1c2d3e4f5061728394a5b6c7d8e9f0a1\n');
    expect(resolveGitBranch(root)).toBeUndefined();
  });

  it('returns undefined for a malformed .git pointer (no gitdir line), not a cwd-relative HEAD', () => {
    // `.git` is a FILE with no `gitdir:` line — must NOT fall through to reading
    // a process-cwd-relative 'HEAD'.
    writeFileSync(join(root, '.git'), 'not a real gitdir pointer\n');
    expect(resolveGitBranch(root)).toBeUndefined();
  });

  it("reads a linked worktree's OWN branch, not the head worktree's", () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    // Common (head worktree) HEAD is `main`; this worktree's own gitdir HEAD is
    // `feature` — resolveGitBranch must report the worktree's own branch.
    writeFileSync(join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    writeFileSync(
      join(root, '.git', 'worktrees', 'wt-checkout', 'HEAD'),
      'ref: refs/heads/feature\n',
    );
    expect(resolveGitBranch(wt)).toBe('feature');
  });
});

describe('resolveWorktreeRoot', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveWorktreeRoot(root)).toBeUndefined();
  });

  it('returns the CURRENT checkout root, even for a linked worktree', () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    const nested = join(wt, 'src', 'deep');
    mkdirSync(nested, { recursive: true });
    expect(resolveWorktreeRoot(nested)).toBe(wt);
  });
});

describe('resolveHeadRoot', () => {
  it('returns undefined outside a git repo', () => {
    expect(resolveHeadRoot(root)).toBeUndefined();
  });

  it('is the checkout root for a normal clone', () => {
    gitDir(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveHeadRoot(root)).toBe(root);
  });

  it('is the PARENT root from inside a linked worktree', () => {
    const wt = linkedWorktree(root, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveHeadRoot(wt)).toBe(root);
  });

  it('is the CHECKOUT root for a worktree of a bare repo (common dir is not a .git)', () => {
    const checkout = bareRepoWorktree(ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveHeadRoot(checkout)).toBe(checkout);
  });
});
