// The scope key a scanned file's capture carries: the canonical
// `host/owner/repo` of the NEAREST repository that holds the file, which is
// not always the scan root's repository.
//
// A scan root routinely contains other repositories. The walk skips a `.git`
// directory but not the directory holding it (SKIP_DIRS in ./walk.ts), and
// discovery stops at the first `.git` it meets (./discover.ts), so a submodule,
// or a personal clone kept inside a work checkout, is walked as part of the
// root around it. Keyed by the root, that clone's files would carry the root
// repository's key, which would claim them for a repository they are not in.
//
// A directory is a repository root when it holds a `.git` entry: a directory
// for a clone, a file for a submodule or a linked worktree. That is the test
// resolveRepoAttribution's own upward walk applies, so the two agree on where a
// repository starts. Every root is keyed by resolveRepoAttribution, so a nested
// repository with no forge remote gets no key, never the enclosing one's; a
// scoped attachment is meant to keep a keyless capture local, and that check is
// not part of this change. A file in no nested repository takes the scan root's
// answer, from the same resolver walking up from the root: a root inside a
// repository (a package directory of a monorepo, a session's working directory)
// keys by the repository around it.
//
// Lazy and scan-local. scanDir asks only for a file that reaches capture, so a
// re-run that skips every file at the ledger reads no repository. The answer
// for every directory a lookup climbs through is remembered, so no directory is
// probed for `.git` twice and no repository root is resolved twice in one scan.
// The memory belongs to the one scan that made it: it grows with the tree
// rather than up to a fixed count, and is dropped when the scan ends.
import { existsSync } from 'node:fs';
import { join, posix, resolve } from 'node:path';

import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';

export function scopeKeysUnder(rootDir: string): (relativePath: string) => string | undefined {
  // Absolute, because resolveRepoAttribution returns no key for a directory
  // that is not: it would read a relative one against the process's own working
  // directory, which need not be the one the scan was pointed at. A relative
  // root (a typed `--dir`) would therefore leave every file keyless.
  const base = resolve(rootDir);
  // Posix directory relative to the root ('.' is the root itself) to the key of
  // its nearest repository. `has` tells "no key" apart from "not looked up",
  // so a keyless directory is not probed again either.
  const keyByDir = new Map<string, string | undefined>();
  return (relativePath) => {
    const climbed: string[] = [];
    let dir = posix.dirname(relativePath);
    let key: string | undefined;
    for (;;) {
      if (keyByDir.has(dir)) {
        key = keyByDir.get(dir);
        break;
      }
      climbed.push(dir);
      const parent = posix.dirname(dir);
      // A walked file's relative path climbs to '.', the scan root, which is
      // its own parent. The root's `.git`, and any above it, are the
      // resolver's to find: it walks up from the root itself.
      if (parent === dir) {
        key = resolveRepoAttribution(base).scopeKey;
        break;
      }
      // A nested repository root. The climb starts at the file, so the first
      // one met is the deepest.
      if (existsSync(join(base, dir, '.git'))) {
        key = resolveRepoAttribution(join(base, dir)).scopeKey;
        break;
      }
      dir = parent;
    }
    for (const at of climbed) keyByDir.set(at, key);
    return key;
  };
}
