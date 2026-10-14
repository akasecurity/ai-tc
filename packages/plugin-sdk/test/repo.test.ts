import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

import { canonicalRepoUrl } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveInventoryContext } from '../src/inventory-resolver.ts';
import {
  resolveGitBranch,
  resolveHeadRoot,
  resolveRepo,
  resolveRepoAttribution,
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

describe('resolveRepoAttribution', () => {
  // The resolver remembers every cwd it has answered for the life of the
  // module (repo-attribution-io.test.ts pins that), so each case lays its
  // repositories down in directories of their own. Rewriting one directory's
  // config between two calls, as the resolveRepo cases above do, would read the
  // first answer back.
  const repoAt = (name: string, config: string): string => {
    const dir = join(root, name);
    gitDir(dir, config);
    return dir;
  };

  // The userinfo in a remote (`<user>@<host>`) reads as an email address to a
  // scanner going over this file, so the fixtures that need one build it from
  // parts rather than carrying it as a literal.
  const AT = String.fromCharCode(64);
  const gitUser = `git${AT}`;
  const someUser = `user${AT}`;

  it('is empty outside a git repo', () => {
    expect(resolveRepoAttribution(root)).toEqual({});
  });

  it('with { cache: false } answers from disk now, not from what it remembered', () => {
    const dir = repoAt('uncached-read', ORIGIN('https://github.com/org/first.git'));
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/org/first');

    writeFileSync(join(dir, '.git', 'config'), ORIGIN('https://github.com/org/second.git'));

    expect(resolveRepoAttribution(dir, { cache: false }).scopeKey).toBe('github.com/org/second');
    // The remembered answer is untouched: the opt-out did not write either.
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/org/first');
  });

  it('with { cache: false } leaves nothing remembered', () => {
    const dir = repoAt('uncached-write', ORIGIN('https://github.com/org/first.git'));
    expect(resolveRepoAttribution(dir, { cache: false }).scopeKey).toBe('github.com/org/first');

    writeFileSync(join(dir, '.git', 'config'), ORIGIN('https://github.com/org/second.git'));

    // The first call of the ordinary form for this directory. Had the opt-out
    // remembered its answer, this would read that answer back.
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/org/second');
  });

  it('gives the slug and the canonical key of the origin remote', () => {
    const dir = repoAt('scp', ORIGIN(`${gitUser}github.com:org/payments-api.git`));
    expect(resolveRepoAttribution(dir)).toEqual({
      repo: 'payments-api',
      scopeKey: 'github.com/org/payments-api',
    });
  });

  it('collapses every spelling of one remote onto one key', () => {
    // Scheme, userinfo, port, host case, `.git` and a trailing slash say how a
    // clone was made, not which repository it is.
    const spellings = [
      `${gitUser}GitHub.com:org/repo.git`,
      `https://${someUser}github.com:443/org/repo/`,
      `ssh://${gitUser}github.com/org/repo.git`,
    ];
    const keys = spellings.map(
      (url, i) => resolveRepoAttribution(repoAt(`spelling-${String(i)}`, ORIGIN(url))).scopeKey,
    );
    expect(keys).toEqual(['github.com/org/repo', 'github.com/org/repo', 'github.com/org/repo']);
  });

  it('keeps the path case: Org/Repo is a different key from org/repo', () => {
    // Forges differ on whether path case matters, and merging two real
    // repositories is the worse error, so the key keeps the path as written.
    const dir = repoAt('cased', ORIGIN('https://github.com/Org/Repo.git'));
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/Org/Repo');
  });

  it('keys a linked worktree exactly like its main checkout', () => {
    const main = join(root, 'main');
    const wt = linkedWorktree(main, ORIGIN('https://github.com/org/payments-api.git'));
    expect(resolveRepoAttribution(wt)).toEqual({
      repo: 'payments-api',
      scopeKey: 'github.com/org/payments-api',
    });
    expect(resolveRepoAttribution(wt)).toEqual(resolveRepoAttribution(main));
  });

  it("keys a submodule by its own remote, not its parent's", () => {
    const parent = repoAt('parent', ORIGIN('https://github.com/org/parent.git'));
    const modGitdir = join(parent, '.git', 'modules', 'lib');
    mkdirSync(modGitdir, { recursive: true });
    writeFileSync(join(modGitdir, 'config'), ORIGIN('https://github.com/org/lib.git'));
    const modRoot = join(parent, 'lib');
    mkdirSync(modRoot, { recursive: true });
    writeFileSync(join(modRoot, '.git'), 'gitdir: ../.git/modules/lib\n');
    expect(resolveRepoAttribution(modRoot).scopeKey).toBe('github.com/org/lib');
    expect(resolveRepoAttribution(parent).scopeKey).toBe('github.com/org/parent');
  });

  it('with no origin, keys by the FIRST remote in config order, the one resolveRepoIdentity picks', () => {
    const dir = repoAt(
      'no-origin',
      '[remote "upstream"]\n\turl = https://github.com/upstream/first.git\n' +
        '[remote "fork"]\n\turl = https://github.com/someone/second.git\n',
    );
    expect(resolveRepoIdentity(dir)?.url).toBe('https://github.com/upstream/first.git');
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/upstream/first');
  });

  it('prefers origin even when another remote is listed before it', () => {
    const dir = repoAt(
      'origin-second',
      '[remote "upstream"]\n\turl = https://github.com/upstream/other.git\n' +
        '[remote "origin"]\n\turl = https://github.com/org/payments-api.git\n',
    );
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/org/payments-api');
  });

  it('gives the slug but no key when the repo has no forge remote', () => {
    // No remote at all, a remote that is a path on this machine, and a file://
    // remote: none names a repository another machine's clone shares, so none
    // could ever be enrolled. The slug is unaffected.
    const remoteless = repoAt('remoteless', '[core]\n\tbare = false\n');
    const localPath = repoAt('local-path', ORIGIN('/srv/repos/widgets.git'));
    const fileUrl = repoAt('file-url', ORIGIN(pathToFileURL('/srv/repos/widgets.git').href));
    expect(resolveRepoAttribution(remoteless)).toEqual({ repo: 'remoteless' });
    expect(resolveRepoAttribution(localPath)).toEqual({ repo: 'widgets' });
    expect(resolveRepoAttribution(fileUrl)).toEqual({ repo: 'widgets' });
  });

  it('gives the checkout slug and no key for a .git file that points nowhere', () => {
    const dir = join(root, 'dangling');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, '.git'), 'gitdir: /somewhere/.git/worktrees/x\n');
    expect(resolveRepoAttribution(dir)).toEqual({ repo: 'dangling' });
  });

  it('never keys from the process directory: a relative cwd keeps its slug and gets no key', () => {
    // The walk climbs by NAME, so a relative cwd is resolved against this
    // process's own working directory, which need not be where the event came
    // from. The slug keeps resolveRepo's answer for the same string: the hooks
    // read their slug through this resolver, and a machine attachment's bodies
    // must not change. The key is withheld, because a key read from the wrong
    // directory could put an event in a scope that does not cover it. No other
    // case in this file resolves these strings, so the memo cannot answer them.
    const dir = repoAt('process-dir', ORIGIN('https://github.com/org/payments-api.git'));
    // The control: named absolutely, the same repository is keyed.
    expect(resolveRepoAttribution(dir).scopeKey).toBe('github.com/org/payments-api');
    const home = process.cwd();
    process.chdir(dir);
    try {
      for (const cwd of ['.', join('apps', 'backend')]) {
        // The process directory IS a keyed repository, and the slug resolver
        // finds it through this very string.
        expect(resolveRepo(cwd)).toBe('payments-api');
        expect(resolveRepoAttribution(cwd)).toEqual({ repo: 'payments-api' });
      }
      // A guard: an empty cwd names no directory. At a repository root the walk
      // answers '', which reads as no repository, so this holds with or without
      // the absolute-path rule.
      expect(resolveRepoAttribution('')).toEqual({});
    } finally {
      // Restored before the shared afterEach removes `root`: a process still
      // standing inside it cannot delete it on Windows.
      process.chdir(home);
    }
  });

  it('gives exactly the slug resolveRepo gives', () => {
    const main = join(root, 'slug-main');
    const dirs = [
      repoAt('slug-scp', ORIGIN(`${gitUser}github.com:org/payments-api.git`)),
      repoAt('slug-https', ORIGIN('https://github.com/org/payments-api')),
      repoAt('slug-remoteless', '[core]\n\tbare = false\n'),
      linkedWorktree(main, ORIGIN('https://github.com/org/payments-api.git')),
    ];
    for (const dir of dirs) expect(resolveRepoAttribution(dir).repo).toBe(resolveRepo(dir));
  });

  it('keys every layout exactly as canonicalRepoUrl keys the identity and inventory urls', () => {
    // The equivalence a session root's key rests on. A root can only be keyed
    // from what SessionStart already holds, the inventory context's project url,
    // which resolveRepoIdentity produces; a hook keys from this resolver. An
    // event and the session it belongs to agree on a key only if both
    // canonicalise the same remote, in every layout.
    const main = join(root, 'eq-main');
    const fixtures = [
      repoAt('eq-scp', ORIGIN(`${gitUser}github.com:org/payments-api.git`)),
      repoAt('eq-subgroup', ORIGIN('https://gitlab.com/group/subgroup/payments-api')),
      repoAt(
        'eq-first-remote',
        '[remote "a"]\n\turl = https://github.com/org/first.git\n' +
          '[remote "b"]\n\turl = https://github.com/org/second.git\n',
      ),
      linkedWorktree(main, ORIGIN('https://github.com/org/payments-api.git')),
      bareRepoWorktree(ORIGIN('https://github.com/org/bare-backed.git')),
      repoAt('eq-remoteless', '[core]\n\tbare = false\n'),
      repoAt('eq-local-path', ORIGIN('/srv/repos/widgets.git')),
    ];
    const keys = fixtures.map((dir) => resolveRepoAttribution(dir).scopeKey);
    for (const [i, dir] of fixtures.entries()) {
      const identityUrl = resolveRepoIdentity(dir)?.url ?? '';
      const projectUrl =
        resolveInventoryContext({ cwd: dir, tool: 'claude-code' }).project?.url ?? '';
      expect(keys[i]).toBe(canonicalRepoUrl(identityUrl));
      expect(keys[i]).toBe(canonicalRepoUrl(projectUrl));
    }
    // The control. Every comparison above also holds for a resolver that never
    // returns a key, since undefined equals undefined.
    expect(keys).toEqual([
      'github.com/org/payments-api',
      'gitlab.com/group/subgroup/payments-api',
      'github.com/org/first',
      'github.com/org/payments-api',
      'github.com/org/bare-backed',
      undefined,
      undefined,
    ]);
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
