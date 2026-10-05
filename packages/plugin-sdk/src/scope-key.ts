import { dirname, isAbsolute, join, normalize } from 'node:path';

import { resolveRepoAttribution } from './repo.ts';

// The scope-key rules the transcript reconcilers (Claude Code, Codex,
// Antigravity) share, so each one stamps a leaf the same way. They are pure file
// I/O through resolveRepoAttribution and never throw.

/**
 * One scope key per working directory for a whole reconcile pass: the canonical
 * `host/owner/repo` of the repository the directory sits in (its origin remote,
 * else the first), or none. A directory in no repository, a repository with no
 * remote and a record that names no cwd all yield no key, and a scoped
 * attachment is to keep a keyless row local (that decision belongs to the
 * forward path, not to this memo).
 *
 * Memoised for two reasons. Cost: a pass pays one `.git` walk per distinct
 * directory, not one per leaf. Consistency: an llm_call's WHOLE attribute bag is
 * replaced when a later pass sees more output tokens for it, so a pass must stamp
 * every leaf from one directory with one answer. The resolver's own memo cannot
 * promise that, because it is process-wide and starts over once it is full; this
 * one lives as long as the pass and is never evicted. A later pass gives the same
 * answer as long as that repository's remote is unchanged.
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
 * A tool_call leaf's scope key: never a repository other than the ones the call
 * names. A call that names a location is keyed by it, not by the directory it ran
 * from, so a write into a personal checkout from a work session cannot leave
 * under the work key. What a call can name:
 * - files (`filePaths`: a file tool's one file, an MCP tool's absolute
 *   `file_path`, a patch's every changed file), keyed by the repository the
 *   file's directory sits in;
 * - a search root (`searchRoot`: a Grep, Glob or LS `path`, a directory or one
 *   file), keyed by the repository the root itself sits in. The walk starts at
 *   the root, not at its parent: a root may be a checkout's top level, and its
 *   parent would miss that checkout, or name the enclosing one when the root is
 *   a nested clone.
 *
 * Every named location must give a key and every key must be the same, or the
 * leaf gets none; a location in no repository is never replaced by the cwd's.
 * `keyless` marks a call whose named location no single repository covers (a Glob
 * whose own pattern is absolute): it gets no key.
 *
 * A relative path or root is read against the call's cwd and is keyless without
 * an absolute one. A call that names nothing (no `filePaths`, no `searchRoot`) is
 * keyed by its cwd: the directory it ran in, which is the command's own working
 * directory when its events name one. A call that names an EMPTY file list and
 * no root has nothing to key by and gets no key (it is not treated as naming
 * nothing); no producer emits one today.
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
  // Each named location as the directory its key is read from. join() leaves a
  // relative path relative when there is no absolute cwd to read it against, and
  // scopeKeyOf keys no relative directory. An absolute path is normalised first:
  // the walk climbs by name, so a `..` segment left in place would climb back
  // into the directory it left.
  const resolved = (path: string): string =>
    isAbsolute(path) ? normalize(path) : join(tc.cwd ?? '', path);
  const directories = [
    ...(tc.filePaths ?? []).map((path) => dirname(resolved(path))),
    ...(tc.searchRoot === undefined ? [] : [resolved(tc.searchRoot)]),
  ];
  let agreed: string | undefined;
  for (const directory of directories) {
    const key = scopeKeyOf(directory);
    if (key === undefined || (agreed !== undefined && key !== agreed)) return undefined;
    agreed = key;
  }
  return agreed;
}
