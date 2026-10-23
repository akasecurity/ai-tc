import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveRepoIdentity, resolveSupersededProjectUrls } from '../src/repo.ts';

// git gives a submodule checked out inside a LINKED WORKTREE an `origin` that
// points at the parent repository's gitdir on local disk, and leaves the real
// forge URL on a second remote. A resolver that takes `origin` unconditionally
// therefore identifies that checkout by a directory that exists on one machine:
// it converges with no other clone, and it renders on the Inventory page as a
// project named after the submodule folder, one row per worktree. These drive
// the real config shape git writes for that layout.

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-local-remote-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

// A checkout whose `.git` is a FILE pointing at `gitdirName` (the submodule
// layout), with `config` as that gitdir's config.
function submoduleCheckout(name: string, gitdirName: string, config: string): string {
  const checkout = join(root, name);
  const gitdir = join(root, gitdirName);
  mkdirSync(checkout, { recursive: true });
  mkdirSync(gitdir, { recursive: true });
  writeFileSync(join(checkout, '.git'), `gitdir: ${gitdir}\n`);
  writeFileSync(join(gitdir, 'config'), config);
  return checkout;
}

const posix = (p: string): string => p.split(sep).join('/');

describe('a remote that names local disk rather than an address', () => {
  it('is not taken as the identity while another remote names a forge', () => {
    const localOrigin = join(root, 'parent', '.git', 'modules', 'oss');
    const checkout = submoduleCheckout(
      'oss',
      'parent/.git/worktrees/wt/modules/oss',
      `[core]\n\tbare = false\n` +
        `[remote "origin"]\n\turl = ${localOrigin}\n` +
        `[remote "github"]\n\turl = git@github.com:acme/app.git\n`,
    );

    const identity = resolveRepoIdentity(checkout);

    // The forge remote, NOT `origin` — and so the display name is the
    // repository's, not the submodule directory's.
    expect(identity).toEqual({ url: 'git@github.com:acme/app.git', name: 'app' });
  });

  it('is still taken when it is the ONLY remote', () => {
    // A preference, not a filter: a local path is a better identity for this
    // checkout than no remote at all, which would fall back to the checkout
    // path and mint a row per clone of it.
    const localOrigin = join(root, 'parent', '.git', 'modules', 'oss');
    const checkout = submoduleCheckout(
      'oss',
      'oss.gitdir',
      `[remote "origin"]\n\turl = ${localOrigin}\n`,
    );

    expect(resolveRepoIdentity(checkout)?.url).toBe(localOrigin);
  });

  it('still prefers `origin` over a later remote when origin names a forge', () => {
    // The ordinary case must not move: `origin` wins whenever it is an address.
    const checkout = submoduleCheckout(
      'app',
      'app.gitdir',
      `[remote "origin"]\n\turl = git@github.com:acme/app.git\n` +
        `[remote "upstream"]\n\turl = git@github.com:upstream/app.git\n`,
    );

    expect(resolveRepoIdentity(checkout)?.url).toBe('git@github.com:acme/app.git');
  });
});

describe('resolveSupersededProjectUrls', () => {
  it('reports the local-disk remote the previous resolver would have stored', () => {
    const localOrigin = join(root, 'parent', '.git', 'modules', 'oss');
    const checkout = submoduleCheckout(
      'oss',
      'parent/.git/worktrees/wt/modules/oss',
      `[remote "origin"]\n\turl = ${localOrigin}\n` +
        `[remote "github"]\n\turl = git@github.com:acme/app.git\n`,
    );

    // Byte-for-byte what the old resolver stored, so a fold keyed on it matches
    // that row or nothing — never another repository's.
    expect(resolveSupersededProjectUrls(checkout)).toEqual([posix(localOrigin)]);
  });

  // P2. The old resolver stored `origin ?? first` and nothing else, so a
  // local-path remote BESIDE that one was never this checkout's identity —
  // and is very likely another repository's, which the sweep would delete.
  it('never reports a local-path remote the old resolver would not have picked', () => {
    const sibling = join(root, 'scratch');
    const checkout = submoduleCheckout(
      'app',
      'app.gitdir',
      `[remote "origin"]\n\turl = git@github.com:acme/app.git\n` +
        `[remote "scratch"]\n\turl = ${sibling}\n`,
    );

    // `origin` is an address, so the old resolver picked it and there is no
    // stale row to fold. The sibling is a live project in its own right.
    expect(resolveSupersededProjectUrls(checkout)).toEqual([]);
  });

  it('never reports a local path that is STILL the identity', () => {
    // Only remote, so `remoteUrl` picks it today too: the row it keys is the
    // one this session writes to, and folding it would delete that project.
    const localOnly = join(root, 'parent', '.git', 'modules', 'oss');
    const checkout = submoduleCheckout(
      'oss',
      'oss.gitdir',
      `[remote "origin"]\n\turl = ${localOnly}\n`,
    );

    expect(resolveRepoIdentity(checkout)?.url).toBe(localOnly);
    expect(resolveSupersededProjectUrls(checkout)).toEqual([]);
  });

  it('reports the first remote when there is no `origin`, matching the old rule', () => {
    const localFirst = join(root, 'parent', '.git', 'modules', 'oss');
    const checkout = submoduleCheckout(
      'oss',
      'oss.gitdir',
      `[remote "alpha"]\n\turl = ${localFirst}\n` +
        `[remote "github"]\n\turl = git@github.com:acme/app.git\n`,
    );

    expect(resolveSupersededProjectUrls(checkout)).toEqual([posix(localFirst)]);
  });

  it('is empty for an ordinary checkout, whose remotes are all addresses', () => {
    const checkout = submoduleCheckout(
      'app',
      'app.gitdir',
      `[remote "origin"]\n\turl = git@github.com:acme/app.git\n`,
    );

    expect(resolveSupersededProjectUrls(checkout)).toEqual([]);
  });

  it('is empty outside a git repo, and never throws', () => {
    expect(resolveSupersededProjectUrls(join(root, 'nope'))).toEqual([]);
  });
});
