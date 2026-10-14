// Working-tree file walker: yield source and secret-bearing files under a root
// directory for static security scanning. Pure I/O — no detection logic — so it
// unit-tests without a runtime.
//
// Two ignore mechanisms with deliberately different semantics:
//   .gitignore     → MARK: "git doesn't track this" is a fact about the repo,
//                    not an instruction to us — gitignored files are scanned
//                    (local scratch hides real secrets) and their findings
//                    carry gitignored provenance for policy to weigh.
//   .akaignore     → SKIP: explicit user intent aimed at this scanner. Same
//                    gitignore syntax, hard skip — no read, no ledger entry,
//                    no finding. A negation (`!vendor/`) also re-includes a
//                    directory from the default SKIP_DIRS floor.
//
// The SKIP_DIRS/.akaignore discovery walk is exported as walkTree so every
// caller that needs to find files under a root directory — walkSourceFiles
// here and collectManifests (./manifests.ts) — shares one interpretation of
// the on-disk ignore files instead of each re-implementing it.
import { type Dirent, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, sep } from 'node:path';

import {
  canonicalizeScanPath,
  childRel,
  defaultDataDir,
  evaluateIgnore,
  type IgnoreLayer,
  isProtectedScanPath,
  protectedScanRoots,
  readIgnoreLayer,
  scanFileKind,
  SOURCE_EXTENSIONS,
  withLayer,
} from '@akasecurity/plugin-sdk';
import ignore from 'ignore';

import { COMMON_SKIP_DIRS } from './constants.ts';

export { SOURCE_EXTENSIONS };

const AKAIGNORE_FILENAME = '.akaignore';

// Directories skipped by DEFAULT — huge, machine-generated trees that are
// almost never worth scanning. Not an absolute invariant: a repo whose
// first-party code genuinely lives in e.g. vendor/ can re-include it with a
// `!vendor/` negation in .akaignore.
//
// Consulted by walkTree below, which every file-discovery walk in this
// package — including the manifest walk (./manifests.ts) — goes through, so
// a dependency manifest under node_modules is skipped as another package's,
// not this project's, exactly like a source file would be.
export const SKIP_DIRS = new Set([
  ...COMMON_SKIP_DIRS,
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.turbo',
  'vendor',
  'target',
  'coverage',
]);

const DEFAULT_MAX_BYTES = 512 * 1024; // 512 KB

export interface WalkedFile {
  path: string; // absolute path
  relativePath: string; // relative to rootDir
  content: string;
  mtime: string; // ISO timestamp, used as occurredAt in stored events
  gitignored: boolean; // excluded by a .gitignore between rootDir and the file
}

// What a `shouldRead` predicate sees: everything stat() gives us for free,
// BEFORE the file contents are read.
export interface WalkedFileMeta {
  path: string; // absolute path
  relativePath: string; // relative to rootDir
  mtime: string; // ISO timestamp
  size: number; // bytes
  gitignored: boolean;
}

export interface WalkOptions {
  rootDir?: string;
  // The source extensions to read. Secret-bearing files (`.env`, `.env.*`) are
  // read whatever this holds.
  extensions?: ReadonlySet<string>;
  // The OS home and AKA's home, whose credential paths are never read
  // (`protectedScanRoots`). Default to `homedir()` and `defaultDataDir()`.
  home?: string | undefined;
  akaHome?: string | undefined;
  // The protected paths already resolved by `resolveProtectedRoots`; when
  // given, `home` and `akaHome` are not consulted.
  protectedRoots?: readonly string[] | undefined;
  maxFileSizeBytes?: number;
  // Programmatic excludes in gitignore syntax, anchored at rootDir — the host's
  // counterpart to on-disk .akaignore files (skip semantics, same layer stack).
  // On-disk .akaignore files are consulted later, so a repo's own negations can
  // override these host-supplied patterns.
  excludePatterns?: string[];
  // Pre-read gate: return false to skip a file WITHOUT reading its contents.
  // This is where scan-ledger mtime skips save the actual I/O — on an unchanged
  // tree the walk degrades to stat calls only.
  shouldRead?: (meta: WalkedFileMeta) => boolean;
  // Told every directory below rootDir that this walk lists and that holds a
  // `.git` entry, as walkTree's option of the same name does (posix path
  // relative to rootDir; rootDir itself is never reported). Additive: a caller
  // that does not pass it walks exactly as before.
  onRepositoryRoot?: ((relativeDir: string) => void) | undefined;
}

// The layer representation, the deepest-first lookup and the walk-relative path
// arithmetic all live in `@akasecurity/plugin-sdk`'s ./ignore-layers, shared
// with the SessionStart inventory walk and the dashboard's folder scan. This
// walk carries ONE posix path per directory (`dirRel`, relative to `rootDir`)
// and every layer holds an integer offset into it, in place of the
// `relative(layer.base, absPath)` path diff this used to run per layer per
// entry — which allocated, normalised separators, and could never stop early.
//
// TWO stacks descend here, not one: `.gitignore` MARKS (provenance) and
// `.akaignore` SKIPS, so each entry was paying that diff twice.

/** One file surfaced by walkTree, before any caller-specific filtering. */
export interface TreeFile {
  path: string; // absolute
  name: string; // basename
  // True when trackGitignore was requested and the file sits under a
  // .gitignore match. Always false when trackGitignore is off — no
  // .gitignore file is even read in that mode.
  gitignored: boolean;
}

export interface TreeWalkOptions {
  // Host-supplied programmatic excludes, gitignore syntax, anchored at
  // rootDir — the same outermost skip layer walkSourceFiles has always
  // accepted (see WalkOptions.excludePatterns). On-disk .akaignore files are
  // appended after it, so their negations win.
  excludePatterns?: string[] | undefined;
  // Also accumulate .gitignore layers per directory and report each file's
  // gitignored status. Off by default: only walkSourceFiles needs the mark,
  // so a caller that doesn't ask for it never pays for reading .gitignore.
  trackGitignore?: boolean;
  // Told every directory BELOW rootDir that this walk lists and that holds a
  // `.git` entry: a nested clone (a directory), a submodule or a linked
  // worktree (a file). It receives the directory's posix path relative to
  // rootDir, the form every layer is addressed through. Read off the listing
  // the walk has already made, so it costs no I/O, and only what the walk
  // enters is reported: a SKIP_DIRS or .akaignore'd directory is never listed.
  // rootDir itself is never reported, because its repository is the walk's own.
  onRepositoryRoot?: ((relativeDir: string) => void) | undefined;
  // Canonical paths (see `protectedScanRoots`) never listed or yielded, nor
  // anything below them.
  protectedRoots?: readonly string[] | undefined;
}

// Lazily discover every file under rootDir that survives the SKIP_DIRS floor
// and any .akaignore hard-skip (including `!` negations) — the one
// interpretation of those two things every walker in this package shares.
// Best-effort: any unreadable directory is silently skipped so a permission
// error never aborts the whole walk.
export function* walkTree(rootDir: string, opts: TreeWalkOptions = {}): Generator<TreeFile> {
  const trackGitignore = opts.trackGitignore ?? false;
  const onRepositoryRoot = opts.onRepositoryRoot;
  const protectedRoots = opts.protectedRoots ?? [];
  // Compared on disk identity; yielded paths keep the caller's spelling.
  const canonicalRoot = protectedRoots.length > 0 ? canonicalizeScanPath(rootDir) : rootDir;
  if (isProtectedScanPath(canonicalRoot, protectedRoots)) return;

  // Host-supplied excludePatterns form the OUTERMOST skip layer: on-disk
  // .akaignore files are appended after it, so their negations win. Anchored at
  // rootDir, which is offset 0 in the `dirRel` every layer is addressed through.
  const rootSkipLayers: readonly IgnoreLayer[] =
    opts.excludePatterns && opts.excludePatterns.length > 0
      ? [{ matcher: ignore().add(opts.excludePatterns), anchorLen: 0 }]
      : [];

  // One directory being walked: its listing, the next entry to visit, and the
  // ignore state its entries are judged against.
  //
  // inIgnoredDir: git semantics — once a directory is gitignored, nothing
  // beneath it can be re-included, so we stop evaluating and mark everything.
  // (The skip stack needs no equivalent: a skipped directory is never entered.)
  //
  // `dirRel` is `dir` as a posix path relative to `rootDir` ('' at the root),
  // built by appending one component per descent. It is what both layer stacks
  // are addressed through, so it is threaded rather than recomputed.
  interface WalkFrame {
    dir: string;
    dirCanonical: string;
    dirRel: string;
    dirents: Dirent[];
    next: number;
    markLayers: readonly IgnoreLayer[];
    skipLayers: readonly IgnoreLayer[];
    inIgnoredDir: boolean;
  }
  // Depth-first and in listing order, with an explicit stack rather than
  // recursion: a tree can nest as deep as the platform's path limit allows,
  // which on a long-path Windows host is thousands of levels.
  const stack: WalkFrame[] = [];

  const enter = (
    dir: string,
    dirCanonical: string,
    dirRel: string,
    markLayers: readonly IgnoreLayer[],
    skipLayers: readonly IgnoreLayer[],
    inIgnoredDir: boolean,
  ): void => {
    let dirents: Dirent[];
    try {
      dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      return;
    }

    // A repository nested below the root, told by the `.git` entry this listing
    // already holds. `dirRel` is '' only at the root.
    if (
      onRepositoryRoot !== undefined &&
      dirRel !== '' &&
      dirents.some((entry) => entry.name === '.git')
    ) {
      onRepositoryRoot(dirRel);
    }

    stack.push({
      dir,
      dirCanonical,
      dirRel,
      dirents,
      next: 0,
      markLayers: withLayer(
        markLayers,
        trackGitignore && !inIgnoredDir
          ? readIgnoreLayer(dir, '.gitignore', dirRel.length)
          : undefined,
      ),
      skipLayers: withLayer(skipLayers, readIgnoreLayer(dir, AKAIGNORE_FILENAME, dirRel.length)),
      inIgnoredDir,
    });
  };

  enter(rootDir, canonicalRoot, '', [], rootSkipLayers, false);
  for (let frame = stack.at(-1); frame !== undefined; frame = stack.at(-1)) {
    const entry = frame.dirents[frame.next];
    if (entry === undefined) {
      stack.pop();
      continue;
    }
    frame.next++;
    const { dir, dirCanonical, dirRel, inIgnoredDir } = frame;
    const dirMarkLayers = frame.markLayers;
    const dirSkipLayers = frame.skipLayers;
    const name = entry.name;
    const fullPath = join(dir, name);
    const canonical = dirCanonical === dir ? fullPath : join(dirCanonical, name);
    if (isProtectedScanPath(canonical, protectedRoots)) continue;

    if (entry.isDirectory()) {
      const skipState = evaluateIgnore(dirSkipLayers, dirRel, name, true);
      // Precedence: an explicit .akaignore re-include beats the SKIP_DIRS
      // default; otherwise SKIP_DIRS and .akaignore matches both hard-skip.
      if (skipState !== 'unignored' && (SKIP_DIRS.has(name) || skipState === 'ignored')) {
        continue;
      }
      const dirIgnored =
        trackGitignore &&
        (inIgnoredDir || evaluateIgnore(dirMarkLayers, dirRel, name, true) === 'ignored');
      enter(fullPath, canonical, childRel(dirRel, name), dirMarkLayers, dirSkipLayers, dirIgnored);
      continue;
    }

    if (!entry.isFile()) continue;

    // .akaignore skip — before stat/read, so an excluded file costs nothing.
    // Applies uniformly to every file this walk discovers; extension or
    // basename filtering is entirely the caller's job.
    if (evaluateIgnore(dirSkipLayers, dirRel, name, false) === 'ignored') continue;

    yield {
      path: fullPath,
      name,
      gitignored:
        trackGitignore &&
        (inIgnoredDir || evaluateIgnore(dirMarkLayers, dirRel, name, false) === 'ignored'),
    };
  }
}

/**
 * The paths a walk never reads, for the OS home and AKA's home (defaulting to
 * `homedir()` and `defaultDataDir()`). Throws when either home cannot be
 * resolved: the scan then fails visibly instead of reading AKA's own key files
 * or reporting an unread tree as clean.
 */
export function resolveProtectedRoots(home?: string, akaHome?: string): readonly string[] {
  try {
    return protectedScanRoots(home ?? homedir(), akaHome ?? defaultDataDir());
  } catch (cause) {
    throw new Error(
      'the home directory cannot be resolved, so the paths a scan must never read are unknown; nothing was scanned',
      { cause },
    );
  }
}

// Lazily walk all source and secret-bearing files under rootDir. Each file is
// read once and yielded; callers stream through it to bound peak memory.
// Gitignored files are read too: local, untracked config is where secrets live.
export function* walkSourceFiles(opts: WalkOptions = {}): Generator<WalkedFile> {
  const rootDir = opts.rootDir ?? process.cwd();
  const extensions = opts.extensions ?? SOURCE_EXTENSIONS;
  const maxBytes = opts.maxFileSizeBytes ?? DEFAULT_MAX_BYTES;

  const protectedRoots = opts.protectedRoots ?? resolveProtectedRoots(opts.home, opts.akaHome);

  for (const file of walkTree(rootDir, {
    excludePatterns: opts.excludePatterns,
    trackGitignore: true,
    onRepositoryRoot: opts.onRepositoryRoot,
    protectedRoots,
  })) {
    if (scanFileKind(file.name, extensions) === 'other') continue;

    let size: number;
    let mtime: Date;
    try {
      const st = statSync(file.path);
      size = st.size;
      mtime = st.mtime;
    } catch {
      continue;
    }

    if (size > maxBytes) continue;

    const meta: WalkedFileMeta = {
      path: file.path,
      // Posix-separated like every stored relative path (and the ignore
      // matching inside walkTree) — native separators must not leak into the
      // contract.
      relativePath: relative(rootDir, file.path).split(sep).join('/'),
      mtime: mtime.toISOString(),
      size,
      gitignored: file.gitignored,
    };
    if (opts.shouldRead && !opts.shouldRead(meta)) continue;

    let content: string;
    try {
      content = readFileSync(file.path, 'utf8');
    } catch {
      continue;
    }

    yield {
      path: meta.path,
      relativePath: meta.relativePath,
      content,
      mtime: meta.mtime,
      gitignored: meta.gitignored,
    };
  }
}
