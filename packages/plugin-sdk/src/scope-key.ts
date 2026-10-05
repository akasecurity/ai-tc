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
 * A tool_call leaf's scope key. A call that names files (a file tool's one
 * file, a patch's every changed file) is keyed by those files' repository, not
 * by the directory it ran from: a write into a personal checkout from a work
 * session must not leave under the work key. Every file a call names must give
 * the same key, or the leaf gets none. A relative path is read against the
 * call's cwd and is keyless without an absolute one. A call that names no file
 * is keyed by its cwd: the directory it ran in, which is the command's own
 * working directory when its events name one.
 *
 * `scopeKeyOf` is the pass's memo (scopeKeyMemo). The call's members are the
 * ones every reconciler's tool-call record carries.
 */
export function toolCallScopeKey(
  tc: { readonly cwd: string | undefined; readonly filePaths: readonly string[] | undefined },
  scopeKeyOf: (cwd: string | undefined) => string | undefined,
): string | undefined {
  if (tc.filePaths === undefined) return scopeKeyOf(tc.cwd);
  let agreed: string | undefined;
  for (const path of tc.filePaths) {
    // join() leaves the path relative when there is no absolute cwd to read it
    // against, and scopeKeyOf keys no relative directory.
    const file = isAbsolute(path) ? normalize(path) : join(tc.cwd ?? '', path);
    const key = scopeKeyOf(dirname(file));
    if (key === undefined || (agreed !== undefined && key !== agreed)) return undefined;
    agreed = key;
  }
  return agreed;
}
