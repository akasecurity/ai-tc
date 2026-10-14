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
// scoped attachment keeps a keyless capture local, and the attached gateway's
// verdict does that, not this file. A file in no nested repository takes the
// scan root's answer, from the same resolver walking up from the root: a root
// inside a repository (a package directory of a monorepo, a session's working
// directory) keys by the repository around it.
//
// Lazy and scan-local. Without a register, scanDir asks only for a file that
// reaches capture, so a re-run that skips every file at the ledger reads no
// repository. With a register (Data Shares on) it also asks for every file it
// skips unread, because the ledger row of each is compared with the repository
// the file is in now: one probe per directory and one read per repository, however
// many files are skipped. A gateway that forwards by scope can ask later for the
// keys of the nested roots. The answer for every directory the climbing lookup
// climbs through is remembered, so it probes no directory for `.git` twice and
// reads each repository root once per scan. The memory belongs to the one scan
// that made it: it grows with the tree rather than up to a fixed count, and is
// dropped when the scan ends.
//
// The same lookup says which directory it answered from, beside the key
// (`repositoryOf`), because a ledger row records the repository's directory too.
// For a nested repository that is the directory holding its `.git`. For a file
// that climbs to the scan root it is the directory holding the nearest `.git` at
// or above the scan root, found once per scan with the same existence test, or
// none when there is no `.git` on the way up to the filesystem root. The key of
// either is read from that directory, and the answer is kept only if its `.git` is
// still there after the read: with it gone the resolver would have climbed, and
// the answer is neither a root nor a key (see `confirmed`).
//
// That per-scan memory is the only one this file trusts. Every call to
// resolveRepoAttribution here passes `{ cache: false }`, so nothing in this file
// reads or writes the resolver's own memory, which lasts for the life of the
// process and is keyed by the directory's path string. An answer in it for a
// nested directory, given while that directory was an ordinary one, is the
// enclosing repository's, and a clone made there since would be keyed by it.
//
// A second lookup, `ofRepositoryRoot`, keys a directory the caller already
// knows to be a repository root, and never climbs. The climbing lookup above is
// right for a FILE: a file under a `.git` that is not a repository (a link to
// nowhere) belongs to the repository around it, as git itself reads it. It is
// wrong for a directory a walk named as a root, because there climbing past an
// unusable `.git` answers with the enclosing repository's key, as if the
// nested directory were that repository. `ofRepositoryRoot` answers for the
// directory itself or not at all, with the one residual its own doc names.
import { existsSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';

import { resolveRepoAttribution } from '@akasecurity/plugin-sdk';

/**
 * The nearest repository holding a file: the absolute directory that holds its
 * `.git`, and its key. The root is `undefined` when the file is in no
 * repository, and the key when that repository has no forge remote.
 */
export interface FileRepository {
  readonly root: string | undefined;
  readonly key: string | undefined;
}

export interface ScopeKeyLookup {
  /** The key of the nearest repository holding the file at this posix path under the root. */
  (relativePath: string): string | undefined;
  /**
   * The nearest repository holding the file at this posix path under the root:
   * the directory it was answered from, beside the key `(relativePath)` gives. The
   * two are one answer, from the same per-scan memory.
   */
  readonly repositoryOf: (relativePath: string) => FileRepository;
  /**
   * The key of the repository rooted exactly at this posix directory under the
   * root, or `undefined` when that directory has no `.git` that exists now, or
   * has no forge remote. Never the key of a repository around it, with one
   * residual, and in that case it IS the enclosing repository's key: a `.git`
   * removed and then recreated during the call. The read in between climbs past
   * the missing `.git` and answers for the repository around it, and the
   * recreated `.git` then passes the second check (see `scopeKeysUnder`).
   */
  readonly ofRepositoryRoot: (relativeDir: string) => string | undefined;
}

export function scopeKeysUnder(rootDir: string): ScopeKeyLookup {
  // Absolute, because resolveRepoAttribution returns no key for a directory
  // that is not: it would read a relative one against the process's own working
  // directory, which need not be the one the scan was pointed at. A relative
  // root (a typed `--dir`) would therefore leave every file keyless.
  const base = resolve(rootDir);
  // The directory holding the nearest `.git` at or above the scan root, for the
  // files that climb all the way to it. Found on the first need and kept for the
  // scan: the same existence test the nested climb applies, walked up from the
  // root to the filesystem root. The wrapper tells "no repository" apart from
  // "not looked up".
  let aboveBase: { readonly root: string | undefined } | undefined;
  const rootAtOrAboveBase = (): string | undefined => {
    if (aboveBase === undefined) {
      let dir = base;
      let root: string | undefined;
      for (;;) {
        if (existsSync(join(dir, '.git'))) {
          root = dir;
          break;
        }
        const parent = dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
      aboveBase = { root };
    }
    return aboveBase.root;
  };

  // A key read from `root`, kept only if the `.git` it was read under is still
  // there. The check that a directory holds a `.git` and the resolver's read of
  // its key are two reads of the disk, and the resolver climbs when `root` has no
  // `.git`: one removed between them (the last rmdir of a removal) would pair the
  // key of the repository AROUND `root` with `root` itself, and a row recorded
  // that way would take the enclosing repository's key under the clone's own
  // directory. So the answer stands only if the `.git` is still there afterwards,
  // and is neither a root nor a key when it is not: a row that has a recorded
  // repository then keeps it, and one that has none records nothing, to be filled
  // by a later scan. What this cannot see is a `.git` removed AND recreated
  // between the two checks, where the read in between has climbed past the missing
  // `.git` and the recreated one passes the second check. The same residual
  // `ofRepositoryRoot` has.
  const confirmed = (root: string, key: string | undefined): FileRepository =>
    existsSync(join(root, '.git')) ? { root, key } : { root: undefined, key: undefined };

  // Posix directory relative to the root ('.' is the root itself) to the
  // repository of its nearest repository root. An entry exists once the
  // directory has been climbed through, so a keyless directory is not probed
  // again either.
  const repositoryByDir = new Map<string, FileRepository>();
  const repositoryOf = (relativePath: string): FileRepository => {
    const climbed: string[] = [];
    let dir = posix.dirname(relativePath);
    let found: FileRepository;
    for (;;) {
      const known = repositoryByDir.get(dir);
      if (known !== undefined) {
        found = known;
        break;
      }
      climbed.push(dir);
      const parent = posix.dirname(dir);
      // A walked file's relative path climbs to '.', the scan root, which is
      // its own parent. The root's `.git`, and any above it, are found by
      // climbing from the root itself (`rootAtOrAboveBase`).
      if (parent === dir) {
        const root = rootAtOrAboveBase();
        // The key is read from the root the climb found, which is the repository
        // the resolver's own climb from `base` reaches, so the two cannot name
        // different repositories. With no root there is none to read.
        found =
          root === undefined
            ? { root, key: resolveRepoAttribution(base, { cache: false }).scopeKey }
            : confirmed(root, resolveRepoAttribution(root, { cache: false }).scopeKey);
        break;
      }
      // A nested repository root. The climb starts at the file, so the first
      // one met is the deepest.
      if (existsSync(join(base, dir, '.git'))) {
        const root = join(base, dir);
        found = confirmed(root, resolveRepoAttribution(root, { cache: false }).scopeKey);
        break;
      }
      dir = parent;
    }
    for (const at of climbed) repositoryByDir.set(at, found);
    return found;
  };
  const keyOfFile = (relativePath: string): string | undefined => repositoryOf(relativePath).key;

  // Does not use `repositoryByDir`: an entry there can be an ANCESTOR's key. A climb
  // that starts below a directory whose `.git` is not usable stores the
  // enclosing repository's key for that directory too, which is the answer this
  // lookup must never give. It does not use the resolver's own per-directory
  // memory either (`cache: false`): that memory is keyed by the directory's path
  // string, so an answer given while the directory was an ordinary one inside the
  // checkout is the checkout's, and would be handed back as this directory's own
  // once a repository is made there. The price is one read of each reported root
  // when a gateway asks for the keys, which happens at most once per scan.
  const ofRepositoryRoot = (relativeDir: string): string | undefined => {
    const root = join(base, relativeDir);
    const dotGit = join(root, '.git');
    if (!existsSync(dotGit)) return undefined;
    const key = resolveRepoAttribution(root, { cache: false }).scopeKey;
    // Checked again AFTER the read. The resolver climbs when `root` has no
    // `.git`, so a `.git` removed between the check above and the read would
    // answer with the enclosing repository's key, and the resolver does not say
    // which root it answered for. The key stands only if the `.git` it was read
    // under is still there. What this cannot see is a `.git` removed and
    // recreated between the two checks.
    return existsSync(dotGit) ? key : undefined;
  };

  return Object.assign(keyOfFile, { repositoryOf, ofRepositoryRoot });
}
