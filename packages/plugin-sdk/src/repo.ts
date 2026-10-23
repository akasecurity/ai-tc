import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';

import { canonicalRepoUrl, namesARemoteAddress } from '@akasecurity/persistence';

// Repo attribution for a captured event. The Security dashboard's Top-Sources
// (by repo) and the recommendation engine both group findings by `repo`, but the
// adapters only ever knew the hook's `cwd` — never a repo slug. This derives one.
//
// Runs on the latency-sensitive, fail-open hook path, so it is pure file I/O: it
// never spawns `git` and never throws. A miss returns undefined (the event is
// then attributed to no repo) rather than guessing from an arbitrary directory
// name — the dashboard should only ever group by a real repository.

/**
 * Resolve a stable repo slug for `cwd`:
 *   1. the `origin` remote's slug from the repo's git config (e.g. `payments-api`
 *      from `https://github.com/acme/payments-api.git`), else any remote's slug;
 *   2. otherwise the basename of the HEAD worktree root (a linked worktree
 *      resolves to its parent repo, never its own checkout directory).
 * Returns undefined when `cwd` is not inside a git repo.
 */
export function resolveRepo(cwd: string): string | undefined {
  try {
    const location = locateRepo(cwd);
    return location ? slugOf(location) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * `remote` without the credentials or query a remote URL can carry. An http(s)
 * URL loses its userinfo, query and fragment; an ssh URL keeps a plain login
 * user and loses a password, query and fragment; a `file:` URL loses only its
 * userinfo, and a `?` or `#` in its path is kept. The userinfo runs to the last
 * `@` before the first `/` and is removed before the URL is parsed, whatever it
 * holds; when the first `/` comes before every `@`, the text before it is the
 * host and is kept. A URL-form remote the parser still refuses is rebuilt from
 * the text after its last `@`, without a query or fragment. Anything else that
 * does not parse as a URL (an scp-style remote, a path) is returned as given,
 * and so is a URL with nothing to remove, character for character.
 */
export function remoteWithoutCredentials(remote: string): string {
  const withoutInfo = withoutUserinfo(remote);
  let url: URL;
  try {
    url = new URL(withoutInfo);
  } catch {
    return unparsedWithoutCredentials(withoutInfo);
  }
  if (url.protocol === 'file:') return withoutInfo;
  const keepsUser = url.protocol === 'ssh:' || url.protocol === 'git+ssh:';
  const carries =
    url.password !== '' ||
    (!keepsUser && url.username !== '') ||
    url.search !== '' ||
    url.hash !== '';
  if (!carries) return withoutInfo;
  const user = keepsUser && url.username !== '' ? `${url.username}@` : '';
  return `${url.protocol}//${user}${url.host}${url.pathname}`;
}

/**
 * `remote` with the userinfo of a URL-form remote removed: everything after
 * `://` up to the last `@` before the first `/`. An ssh login user made only of
 * letters, digits and `._~%+-` is kept.
 */
function withoutUserinfo(remote: string): string {
  const match = /^([a-z][a-z0-9+.-]*):\/\/([^/]*)@/i.exec(remote);
  const scheme = match?.[1];
  const userinfo = match?.[2];
  if (match === null || scheme === undefined || userinfo === undefined) return remote;
  const login = /^(?:git\+)?ssh$/i.test(scheme) ? (userinfo.split(':')[0] ?? '') : '';
  const kept = /^[\w.~%+-]+$/.test(login) ? `${login}@` : '';
  return `${scheme}://${kept}${remote.slice(match[0].length)}`;
}

/**
 * A URL-form `remote` the URL parser refused, rebuilt from the text after its
 * last `@` without a query or fragment. Anything not URL-form is returned as
 * given.
 */
function unparsedWithoutCredentials(remote: string): string {
  const scheme = /^[a-z][a-z0-9+.-]*:\/\//i.exec(remote)?.[0];
  if (scheme === undefined) return remote;
  const rest = remote.slice(scheme.length);
  const tail = rest.slice(rest.lastIndexOf('@') + 1);
  return `${scheme}${tail.split(/[?#]/, 1)[0] ?? ''}`;
}

/**
 * Resolve a Source/Project identity for `cwd`: the content-addressing `url`
 * (the `origin` remote URL, so two machines cloning the same repo collapse to
 * one `source_project` row; the HEAD worktree root path is the fallback for a
 * repo with no remote) plus a human `name` (the remote slug, else the HEAD
 * worktree basename). The `url` is the remote exactly as the git config writes
 * it, credentials and query included; the `name` is read from it without them.
 * A linked worktree (`.git` file → `gitdir:`/`commondir`) resolves to its
 * PARENT repo's identity — the checkout is the same project, not a new one — so
 * worktree sessions collapse into the head repo's row.
 * Returns undefined when `cwd` is not inside a git repo. Same pure, fail-open,
 * never-spawns-git contract as resolveRepo.
 */
export function resolveRepoIdentity(cwd: string): { url: string; name: string } | undefined {
  try {
    const location = locateRepo(cwd);
    if (!location) return undefined;
    return {
      // The path fallback is normalized to posix separators (a no-op outside
      // win32) so the persistence layer's `/`-separated checkout-path patterns
      // (the ghost sweep + the read-side worktree filter) match it as written.
      url: location.remote ?? location.headRoot.split(sep).join('/'),
      name: slugOf(location),
    };
  } catch {
    return undefined;
  }
}

/**
 * The project identities a PREVIOUS resolver minted for `cwd` that this one no
 * longer would — the rows a self-heal should fold into the repository's real
 * project.
 *
 * Today that is exactly one shape: the remote the OLD resolver picked, where it
 * names a location on local disk rather than a remote address. `remoteUrl` used
 * to take `origin` unconditionally, and git writes a local-disk `origin` for a
 * submodule checked out inside a linked worktree (it points at the parent
 * repository's gitdir), so such a checkout was recorded under a directory path
 * instead of the repository it is a clone of. Those rows render as a project
 * named after the submodule directory, one per worktree.
 *
 * AT MOST ONE URL, AND ONLY THE ONE THAT WAS PICKED. It is read from the config
 * through the OLD rule — `origin`, else the first remote in config order — and
 * never from the other remotes beside it. That is the whole safety argument: a
 * local-path remote the old resolver did NOT pick was never this checkout's
 * identity, and it can easily be another repository's. A sibling clone added as
 * `git remote add scratch ~/src/scratch` has `~/src/scratch` as its own project
 * identity, because a repository with no address keys on its root path — so
 * returning it here would hand a LIVE row to a sweep that repoints its events
 * and deletes it, on every session in the first repository.
 *
 * NOTHING THAT IS STILL THE IDENTITY either. Where the picked remote is also
 * what `remoteUrl` picks today — a checkout whose only remote is a local path —
 * the row it keys is current rather than superseded, and folding it would
 * delete the project the session is writing to.
 *
 * A path is posix-normalized for the same reason the identity fallback is: the
 * store's path patterns are written with `/`.
 *
 * Empty for an ordinary checkout, whose remotes are all addresses. Same pure,
 * never-spawns-git, never-throws contract as `resolveRepo`.
 */
export function resolveSupersededProjectUrls(cwd: string): string[] {
  try {
    const root = findGitRoot(cwd);
    if (!root) return [];
    const ctx = resolveGitContext(root);
    const config = ctx === undefined ? undefined : safeRead(ctx.configPath);
    if (config === undefined || ctx === undefined) return [];
    const remotes = parseRemoteUrls(config);
    // The OLD rule, spelled out here rather than shared with `remoteUrl`: that
    // function implements the NEW one now, and this has to keep answering what
    // the resolver this heals actually wrote.
    const picked = remotes.origin ?? Object.values(remotes)[0];
    if (picked === undefined || namesARemoteAddress(picked)) return [];
    if (picked === remoteUrl(ctx)) return [];
    return [picked.split(sep).join('/')];
  } catch {
    return [];
  }
}

/**
 * What a captured event needs from its working directory: the repo slug and
 * the event's scope key. Both members are absent outside a git repo; `scopeKey`
 * is also absent when the repo has no forge remote, and whenever the working
 * directory is not an absolute path.
 */
export interface RepoAttribution {
  /** The slug `resolveRepo` gives for the same directory. */
  readonly repo?: string | undefined;
  /**
   * The canonical `host/owner/repo` (see `canonicalRepoUrl`) of the remote
   * `resolveRepoIdentity` picks for the same directory: `origin`, else the
   * first remote in config order.
   */
  readonly scopeKey?: string | undefined;
}

// How many directories resolveRepoAttribution remembers before it starts over.
const ATTRIBUTION_MEMO_LIMIT = 64;
const attributionMemo = new Map<string, RepoAttribution>();
const NO_ATTRIBUTION: RepoAttribution = Object.freeze({});

/**
 * The repo slug `resolveRepo` gives AND the event's scope key, from one `.git`
 * walk and one config read.
 *
 * The scope key is the canonical `host/owner/repo` of the remote
 * `resolveRepoIdentity` picks (`origin`, else the first remote in config
 * order), so for an absolute `cwd`, `canonicalRepoUrl(resolveRepoIdentity(cwd).url)`
 * and this key are equal; repo.test.ts pins that across layouts. Anything
 * keyed from an inventory context's project url, which `resolveRepoIdentity`
 * produces, therefore lands on the same key as an event keyed here. Both read
 * the remote through `locateRepo`, which is what keeps them from drifting.
 *
 * The key is derived from the RAW remote, never from
 * `resolveRepoIdentity(cwd).url`: that value falls back to the worktree path
 * when there is no remote, and nothing downstream could tell the two apart.
 * Here "no remote" is structural: there is no remote string, so there is no
 * key. A remote that names a location on this machine (a filesystem path, a
 * `file://` URL) gets no key either, because `canonicalRepoUrl` answers
 * undefined for anything that is not a forge address. Such a key never
 * converges with another machine's clone, so it could never match an entry
 * anyone enrolled.
 *
 * ONLY AN ABSOLUTE `cwd` IS KEYED. The walk climbs by name, so a relative
 * `cwd` resolves against this process's own working directory, which a hook
 * does not choose and need not share with the event it reports. Such a `cwd`
 * still gets the slug `resolveRepo` gives for the same string, because the
 * slug has always been read that way; it gets no key, because a key read from
 * the wrong directory could put the event in a scope that does not cover it.
 *
 * WHY ONE WALK. This sits on the capture path, where the slug was already being
 * resolved. Calling `resolveRepo` and `resolveRepoIdentity` back to back would
 * repeat the ancestor walk (one `existsSync` per directory up to the repo root)
 * and the config read for every event.
 *
 * WHY THE MEMO. A caller that needs the slug and the key at different points of
 * one event resolves the same directory twice, and the second call should cost
 * nothing. Answers are kept per exact `cwd` string, at most
 * `ATTRIBUTION_MEMO_LIMIT` of them, and the whole map is dropped when it is
 * full rather than evicted entry by entry: a capture touches one directory and
 * a pass over transcripts or scan roots a handful, so the bound exists only to
 * stop a long-running caller from growing without limit, and starting over
 * costs one walk per directory. The price is staleness: a remote edited after
 * the first answer is not seen until the map starts over, so a caller that
 * must notice that should not rely on this. (A relative `cwd` is remembered by
 * its string too; its slug depends on the process's working directory, which
 * a hook never changes.)
 *
 * The memo is also keyed by the path string and not by the repository, so an
 * answer given while `cwd` was an ordinary directory inside a checkout is the
 * checkout's, and it stays the answer for that path if a repository is later
 * made there. `{ cache: false }` is for a caller that must have the answer as
 * of this call and keeps whatever memory it needs itself: it neither reads nor
 * writes the memo, so what it returns was read from disk during the call and
 * nothing it learns is left for another caller. The default is unchanged.
 *
 * Same pure, never-spawns-git, never-throws contract as `resolveRepo`. Outside
 * a git repo the answer is empty (no slug, no key). A failure answers empty too,
 * but is not remembered, so the next call tries again.
 */
export function resolveRepoAttribution(
  cwd: string,
  options?: { readonly cache?: boolean | undefined },
): RepoAttribution {
  try {
    if (options?.cache === false) return attributeRepo(cwd);
    const remembered = attributionMemo.get(cwd);
    if (remembered !== undefined) return remembered;
    const attribution = attributeRepo(cwd);
    if (attributionMemo.size >= ATTRIBUTION_MEMO_LIMIT) attributionMemo.clear();
    attributionMemo.set(cwd, attribution);
    return attribution;
  } catch {
    return NO_ATTRIBUTION;
  }
}

// The uncached resolution behind resolveRepoAttribution. Frozen, because the
// memo hands the same object to every caller for that directory. The remote is
// consulted for a key only when `cwd` is absolute (see the doc comment above).
function attributeRepo(cwd: string): RepoAttribution {
  const location = locateRepo(cwd);
  if (!location) return NO_ATTRIBUTION;
  const remote = isAbsolute(cwd) ? location.remote : undefined;
  const scopeKey = remote === undefined ? undefined : canonicalRepoUrl(remote);
  return Object.freeze({
    repo: slugOf(location),
    ...(scopeKey === undefined ? {} : { scopeKey }),
  });
}

/**
 * The `owner/repo` name-with-owner for `cwd`, derived from the `origin` (else
 * any) remote URL without its credentials or query — the meaningful value for
 * the Activity page's `repo` display field (distinct from `project`, which is
 * the bare slug). undefined when the repo has no remote (a purely-local checkout
 * has no owner) or `cwd` is outside a git repo. Same pure, never-spawns-git,
 * never-throws contract as resolveRepo.
 */
export function resolveRepoNwo(cwd: string): string | undefined {
  try {
    const root = findGitRoot(cwd);
    if (!root) return undefined;
    const ctx = resolveGitContext(root);
    const url = ctx ? remoteUrl(ctx) : undefined;
    return url ? nwoFromUrl(remoteWithoutCredentials(url)) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The root of the checkout containing `cwd` (the CURRENT worktree, not the head
 * repo — a file walk wants the tree the session is actually editing). Undefined
 * outside a git repo. Same pure, never-throws contract as resolveRepo.
 */
export function resolveWorktreeRoot(cwd: string): string | undefined {
  try {
    return findGitRoot(cwd);
  } catch {
    return undefined;
  }
}

/**
 * The HEAD repo root for `cwd`: the main worktree's directory when `cwd` is
 * inside a linked worktree, else the checkout root itself. This is the anchor
 * the stale-worktree-row reconcile sweeps under (`<headRoot>/.claude/worktrees/`).
 * Undefined outside a git repo. Same pure, never-throws contract as resolveRepo.
 */
export function resolveHeadRoot(cwd: string): string | undefined {
  try {
    const root = findGitRoot(cwd);
    if (!root) return undefined;
    return resolveGitContext(root)?.headRoot ?? root;
  } catch {
    return undefined;
  }
}

/**
 * The current branch checked out at `cwd` — read from the CURRENT worktree's own
 * `HEAD` (not the head repo's), so a linked worktree reports its own branch. A
 * detached HEAD (raw sha, no `ref:`) returns undefined rather than a sha, and
 * `cwd` outside a git repo returns undefined. Same pure, never-spawns-git,
 * never-throws contract as `resolveRepo` — it powers the Activity page's per-
 * session branch, written onto the session root at capture time.
 */
export function resolveGitBranch(cwd: string): string | undefined {
  try {
    const root = findGitRoot(cwd);
    if (!root) return undefined;
    const dotGit = join(root, '.git');
    let gitdir: string | undefined;
    try {
      gitdir = statSync(dotGit).isDirectory() ? dotGit : resolveWorktreeGitdir(root, dotGit);
    } catch {
      return undefined;
    }
    // A malformed `.git` pointer yields no gitdir — bail rather than fall through
    // to `join('', 'HEAD')` === 'HEAD', which would read a stray cwd-relative
    // 'HEAD' file (fail-open, but it could match unrelated content).
    if (gitdir === undefined) return undefined;
    const head = safeRead(join(gitdir, 'HEAD'));
    if (!head) return undefined;
    // `ref: refs/heads/<branch>` on a normal checkout; a detached HEAD is a bare
    // sha with no `ref:` prefix, which we deliberately don't surface as a branch.
    return /^ref:\s*refs\/heads\/(.+?)\s*$/m.exec(head)?.[1];
  } catch {
    return undefined;
  }
}

// The worktree's OWN gitdir for a `.git` FILE (linked worktree / submodule): the
// `gitdir: <path>` target holds this checkout's HEAD, unlike `resolveGitContext`
// which follows `commondir` back to the SHARED gitdir (whose HEAD is the head
// worktree's branch, not this one's). Returns undefined (→ no branch upstream)
// when the pointer is missing/malformed, so the caller never reads a bogus path.
function resolveWorktreeGitdir(root: string, dotGitFile: string): string | undefined {
  const target = /^gitdir:\s*(.+?)\s*$/m.exec(safeRead(dotGitFile) ?? '')?.[1];
  if (!target) return undefined;
  return isAbsolute(target) ? target : join(root, target);
}

// Walk up from `start` to the first ancestor containing a `.git` entry (a dir for
// a normal clone, a file for worktrees/submodules). Bounded by the filesystem
// root: dirname stops changing there, which ends the loop.
function findGitRoot(start: string): string | undefined {
  let dir = start;
  for (;;) {
    if (existsSync(join(dir, '.git'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

// Where the repo's git config actually lives, plus the HEAD worktree root, for a
// `.git` that is a directory (normal clone) or a file (linked worktree /
// submodule). A linked worktree follows `gitdir:` → `commondir` back to the
// shared .git, so it inherits the parent repo's remote AND falls back to the
// parent's root path — never minting a per-checkout project identity. A
// submodule's gitdir carries its own config (its own remote), so it stays its
// own project. Fail-open: any unreadable/malformed step yields undefined.
interface GitContext {
  configPath: string;
  headRoot: string;
}

function resolveGitContext(root: string): GitContext | undefined {
  const dotGit = join(root, '.git');
  try {
    if (statSync(dotGit).isDirectory()) {
      return { configPath: join(dotGit, 'config'), headRoot: root };
    }
  } catch {
    return undefined;
  }
  // `.git` FILE: one `gitdir: <path>` line, absolute or relative to the root.
  const target = /^gitdir:\s*(.+?)\s*$/m.exec(safeRead(dotGit) ?? '')?.[1];
  if (!target) return undefined;
  const gitdir = isAbsolute(target) ? target : join(root, target);
  // Submodule gitdirs (.git/modules/<name>) hold their own config.
  if (existsSync(join(gitdir, 'config'))) {
    return { configPath: join(gitdir, 'config'), headRoot: root };
  }
  // Linked worktree gitdirs (.git/worktrees/<name>) point home via `commondir`.
  const commonRaw = safeRead(join(gitdir, 'commondir'))?.trim();
  if (!commonRaw) return undefined;
  const commonGitDir = isAbsolute(commonRaw) ? commonRaw : join(gitdir, commonRaw);
  // dirname(commonDir) is the head CHECKOUT only when the common dir is a
  // `<checkout>/.git` — a worktree of a BARE repo (or of a submodule) has its
  // common dir elsewhere, and dirname would name an unrelated parent directory
  // (two bare repos kept in one folder would collapse into one identity). Those
  // layouts keep the current checkout root as their anchor instead.
  const headRoot = basename(commonGitDir) === '.git' ? dirname(commonGitDir) : root;
  return { configPath: join(commonGitDir, 'config'), headRoot };
}

function safeRead(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * The remote URL to identify this repository by: `origin` where it names a
 * remote ADDRESS, else the first remote in config order that does, else
 * `origin`, else the first remote. Undefined when the config has no remote.
 *
 * WHY `origin` IS NOT TAKEN BLINDLY. git writes an `origin` that points at
 * local disk in a layout this product meets routinely: a submodule checked out
 * inside a linked worktree gets
 * `origin = <parent>/.git/modules/<name>` — the parent repository's gitdir —
 * while the real forge URL is left on a second remote. Taking `origin` there
 * identifies the repository by a directory that exists on one machine, so it
 * converges with no other clone, and the display name comes out as the
 * submodule's directory rather than the repository's. Preferring an address
 * costs nothing in the ordinary case, where `origin` is one.
 *
 * It is a PREFERENCE and not a filter: a repository whose only remote is a
 * local path still gets that remote, because a local path is a better identity
 * for it than no remote at all (which would fall back to the checkout path).
 */
function remoteUrl(ctx: GitContext): string | undefined {
  const config = safeRead(ctx.configPath);
  if (config === undefined) return undefined;
  const remotes = parseRemoteUrls(config);
  const ordered = remotes.origin === undefined ? [] : [remotes.origin];
  for (const [name, url] of Object.entries(remotes)) if (name !== 'origin') ordered.push(url);
  return ordered.find((url) => namesARemoteAddress(url)) ?? ordered[0];
}

// One repository, located from `cwd`: ONE ancestor walk (findGitRoot) and,
// when the `.git` entry resolves, ONE config read (remoteUrl). resolveRepo,
// resolveRepoIdentity and resolveRepoAttribution read the remote through here,
// so "the remote" names the same thing in all three: `origin`, else the first
// remote in config order. That rule lives in remoteUrl above, which
// resolveRepoNwo also uses, though it walks and reads on its own rather than
// through this locator. `remote` is the `url =` value verbatim, undefined with
// no remote; `headRoot` is the HEAD worktree root (a linked worktree's main
// checkout, else the checkout itself).
interface RepoLocation {
  headRoot: string;
  remote: string | undefined;
}

function locateRepo(cwd: string): RepoLocation | undefined {
  const root = findGitRoot(cwd);
  if (!root) return undefined;
  const ctx = resolveGitContext(root);
  return { headRoot: ctx?.headRoot ?? root, remote: ctx ? remoteUrl(ctx) : undefined };
}

// The repo's display slug: the last path segment of the remote without its
// credentials or query, else the HEAD worktree basename, never an arbitrary
// directory name (see the header).
function slugOf(location: RepoLocation): string {
  return (
    (location.remote ? slugFromUrl(remoteWithoutCredentials(location.remote)) : undefined) ??
    basename(location.headRoot)
  );
}

// Map remote name -> url from git config's `[remote "name"]` sections. Only the
// first `url` per remote is kept; a non-remote `[section]` header ends the scope.
function parseRemoteUrls(config: string): Record<string, string> {
  const remotes: Record<string, string> = {};
  let current: string | undefined;
  for (const raw of config.split('\n')) {
    const line = raw.trim();
    const header = /^\[remote "([^"]+)"\]$/.exec(line);
    if (header) {
      current = header[1];
      continue;
    }
    if (line.startsWith('[')) {
      current = undefined;
      continue;
    }
    if (current && !(current in remotes)) {
      const url = /^url\s*=\s*(.+)$/.exec(line)?.[1];
      if (url) remotes[current] = url.trim();
    }
  }
  return remotes;
}

// Last path segment of a remote URL, minus a trailing `.git`. Handles both
// scp-like (`git@host:org/repo.git`) and URL (`https://host/org/repo`) forms by
// splitting on `/` and `:`.
function slugFromUrl(url: string): string | undefined {
  const segment = url
    .replace(/\.git$/, '')
    .split(/[/:]/)
    .filter(Boolean)
    .pop();
  return segment && segment.length > 0 ? segment : undefined;
}

// "owner/repo" (name-with-owner) from a remote URL, minus a trailing `.git`.
// Reduce to the path AFTER the host — `scheme://host/<path>`, or the part after
// the first `:` for the scp-like `host:<path>` form — then keep the WHOLE path:
// an owner can be multi-segment (a GitLab `group/subgroup/repo` → `group/subgroup`
// is the real owner), so we never drop the top group the way `slice(-2)` would.
// A single-segment path has no owner (`https://host/repo` → undefined), so we
// don't mistake the host for the owner.
function nwoFromUrl(url: string): string | undefined {
  const noGit = url.replace(/\.git$/, '');
  let path: string;
  if (noGit.includes('://')) {
    path = /^[a-z][a-z0-9+.-]*:\/\/[^/]+\/(.+)$/i.exec(noGit)?.[1] ?? '';
  } else if (noGit.includes(':')) {
    path = noGit.slice(noGit.indexOf(':') + 1);
  } else {
    path = noGit;
  }
  const parts = path.split('/').filter(Boolean);
  return parts.length >= 2 ? parts.join('/') : undefined;
}
