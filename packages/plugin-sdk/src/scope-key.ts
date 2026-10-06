import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize } from 'node:path';

import { resolveRepoAttribution } from './repo.ts';

// The scope-key rules the session-start hook and the transcript reconcilers
// (Claude Code, Codex, Antigravity) share, so each one stamps a root and a leaf
// the same way. They are pure file I/O through resolveRepoAttribution and never
// throw.

/**
 * One scope key per working directory for a whole reconcile pass: the canonical
 * `host/owner/repo` of the repository the directory sits in (its origin remote,
 * else the first), or none. A directory in no repository, a repository with no
 * remote and a record that names no cwd all yield no key. A scoped attachment is
 * meant to keep a keyless row local; that check is not part of this memo or of
 * this change.
 *
 * Memoised for two reasons. Cost: a pass pays one `.git` walk per distinct
 * directory, not one per leaf. Consistency: an llm_call's WHOLE attribute bag is
 * replaced when a later pass sees more output tokens for it, so a pass must stamp
 * every leaf from one directory with one answer. The resolver's own memo cannot
 * promise that, because it is process-wide and starts over once it is full; this
 * one lives as long as the pass and is never evicted. A later pass gives the same
 * answer as long as that repository's remote is unchanged.
 *
 * Each string is remembered on its own. `toolCallScopeKey` asks about a named
 * file's directory, unless the path is itself a checkout's top level, so a pass
 * pays one walk per directory its files sit in, not one per file.
 *
 * Only an absolute directory is keyed, and that rule is the resolver's:
 * `resolveRepoAttribution` answers no key for a relative or empty one, which the
 * walk would otherwise read against the reconciler's own process directory and
 * borrow whatever repository it runs in.
 */
export function scopeKeyMemo(): (cwd: string | undefined) => string | undefined {
  const memo = new Map<string, string | undefined>();
  return (cwd) => {
    if (cwd === undefined) return undefined;
    if (memo.has(cwd)) return memo.get(cwd);
    const key = resolveRepoAttribution(cwd).scopeKey;
    memo.set(cwd, key);
    return key;
  };
}

/**
 * A session root's scope key: the canonical `host/owner/repo` of the repository
 * its own cwd sits in, or none. It is the key a hook stamps for a path-less
 * capture in the same directory, because both read it from
 * `resolveRepoAttribution`. A relative or empty cwd, a missing one, a directory
 * in no repository and a repository with no forge remote all yield no key.
 *
 * The cwd is read on its own and never through the inventory context's project:
 * that project is found by walking from the cwd by name, so a relative cwd would
 * be read against the hook's or reconciler's own process directory and borrow
 * whatever repository that process runs in. `resolveRepoAttribution` is the one
 * place the absolute-only rule lives, so every root builder asks it.
 */
export function sessionRootScopeKey(cwd: string | undefined): string | undefined {
  return cwd === undefined ? undefined : resolveRepoAttribution(cwd).scopeKey;
}

/**
 * A tool_call leaf's scope key: never a repository other than the ones the call
 * names. A call that names a location is keyed by it, not by the directory it ran
 * from, so a write into a personal checkout from a work session cannot leave
 * under the work key. What a call can name:
 * - files (`filePaths`: a file tool's one file, an MCP tool's absolute
 *   `file_path`, a patch's every changed file);
 * - a search root (`searchRoot`: a Grep, Glob or LS `path`, a directory or one
 *   file).
 *
 * Either is keyed by the repository the named path itself sits in, by one rule:
 * the walk starts at the path, not at its parent. The resolver climbs by name and
 * probes `<start>/.git` before it climbs, so a file (which has no `.git` of its
 * own) and a path not yet created reach the repository their directory sits in,
 * while a path that is a checkout's top level, or a nested clone, is found at the
 * first probe. Starting at the parent would key that clone by the repository
 * around it.
 *
 * A named FILE is asked about through the pass memo by its directory unless the
 * path has a `.git` of its own: that one probe is the walk's first step, and a
 * miss leaves the walk climbing from the directory, so the key is the same either
 * way. What it buys is that the memo then answers once per directory a pass's
 * files sit in, as it did before the path itself was walked, and not once per
 * file. A search root is asked about as it is: it is a directory, or one file.
 *
 * Every named location must give a key and every key must be the same, or the
 * leaf gets none; a location in no repository is never replaced by the cwd's.
 * `keyless` marks a call whose named location no single repository covers (a Glob
 * whose own pattern is absolute, or climbs out of its root through a `..`
 * segment): it gets no key.
 *
 * A relative path or root is read against the call's cwd and is keyless without
 * an absolute one. A call that names nothing (no `filePaths`, no `searchRoot`) is
 * keyed by its cwd: the directory it ran in, which is the command's own working
 * directory when its events name one. A call that names an EMPTY file list and
 * no root has nothing to key by and gets no key (it is not treated as naming
 * nothing). The Codex and Antigravity transcript parsers emit one for a patch
 * whose events name no file, because a patch always names files.
 *
 * `scopeKeyOf` is the pass's memo (scopeKeyMemo). Only `cwd` and `filePaths` are
 * required of a call: Codex and Antigravity name files and name no root.
 */
export function toolCallScopeKey(
  tc: {
    readonly cwd: string | undefined;
    readonly filePaths: readonly string[] | undefined;
    readonly searchRoot?: string | undefined;
    readonly keyless?: boolean | undefined;
  },
  scopeKeyOf: (cwd: string | undefined) => string | undefined,
): string | undefined {
  if (tc.keyless === true) return undefined;
  if (tc.filePaths === undefined && tc.searchRoot === undefined) return scopeKeyOf(tc.cwd);
  // Each named location as the path its key is read from. join() leaves a
  // relative path relative when there is no absolute cwd to read it against, and
  // scopeKeyOf keys no relative path. An absolute path is normalised first: the
  // walk climbs by name, so a `..` segment left in place would climb back into
  // the directory it left.
  const resolved = (path: string): string =>
    isAbsolute(path) ? normalize(path) : join(tc.cwd ?? '', path);
  // Where a named file's walk is asked about. The walk from the path probes
  // `<path>/.git` and, on a miss, climbs to its directory and goes on from there,
  // so asking about the directory after a miss reads the same repository. A
  // relative path is never keyed, whichever way it is asked about, so it takes
  // no probe.
  const walkStart = (path: string): string =>
    isAbsolute(path) && existsSync(join(path, '.git')) ? path : dirname(path);
  const locations = [
    ...(tc.filePaths ?? []).map((path) => walkStart(resolved(path))),
    ...(tc.searchRoot === undefined ? [] : [resolved(tc.searchRoot)]),
  ];
  let agreed: string | undefined;
  for (const location of locations) {
    const key = scopeKeyOf(location);
    if (key === undefined || (agreed !== undefined && key !== agreed)) return undefined;
    agreed = key;
  }
  return agreed;
}
