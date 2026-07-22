// Working-tree file walker: yield source files under a root directory for
// static code security scanning. Pure I/O — no detection logic — so it
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
import { type Dirent, readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';

import ignore, { type Ignore } from 'ignore';

import { COMMON_SKIP_DIRS } from './constants.ts';

export const SOURCE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.rb',
  '.cs',
  '.php',
  '.go',
  '.rs',
]);

const AKAIGNORE_FILENAME = '.akaignore';

// Directories skipped by DEFAULT — huge, machine-generated trees that are
// almost never worth scanning. Not an absolute invariant: a repo whose
// first-party code genuinely lives in e.g. vendor/ can re-include it with a
// `!vendor/` negation in .akaignore.
//
// Exported so the manifest walk (./manifests.ts) skips the same trees as this
// one — a dependency manifest under node_modules is another package's, not
// this project's.
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
  extensions?: Set<string>;
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
}

// One ignore file's rules, anchored to the directory that contains it (git
// patterns are relative to their own ignore file, not the repo root).
interface IgnoreLayer {
  base: string; // absolute dir the ignore file lives in
  matcher: Ignore;
}

// Read a directory's ignore file into a matcher layer. Fail-open: an
// unreadable or malformed file yields no layer — we scan MORE on error,
// never less.
function readIgnoreLayer(dir: string, filename: string): IgnoreLayer | undefined {
  try {
    const content = readFileSync(join(dir, filename), 'utf8');
    return { base: dir, matcher: ignore().add(content) };
  } catch {
    return undefined;
  }
}

type IgnoreState = 'ignored' | 'unignored' | 'unmatched';

// Evaluate the layered ignore state for a path, mirroring git's semantics:
// deeper ignore files are consulted later, so their verdicts (ignore OR
// re-include via `!`) override shallower ones. 'unignored' is distinct from
// 'unmatched' because an explicit `!` re-include also overrides the SKIP_DIRS
// default floor. Directories are tested with a trailing slash so `dir/`-style
// patterns match.
function evaluate(layers: IgnoreLayer[], absPath: string, isDir: boolean): IgnoreState {
  let state: IgnoreState = 'unmatched';
  for (const layer of layers) {
    // The ignore package expects posix-style relative paths.
    const rel = relative(layer.base, absPath).split(sep).join('/') + (isDir ? '/' : '');
    const verdict = layer.matcher.test(rel);
    if (verdict.ignored) state = 'ignored';
    else if (verdict.unignored) state = 'unignored';
  }
  return state;
}

// Lazily walk all source files under rootDir. Each file is read once and
// yielded; callers stream through it to bound peak memory. Best-effort: any
// unreadable entry is silently skipped so a permission error on one file never
// aborts the whole scan.
//
// (If the walker ever scans non-source files like .env, the .gitignore
// mark-don't-skip stance becomes even more load-bearing — gitignored config is
// exactly where secrets live.)
export function* walkSourceFiles(opts: WalkOptions = {}): Generator<WalkedFile> {
  const rootDir = opts.rootDir ?? process.cwd();
  const extensions = opts.extensions ?? SOURCE_EXTENSIONS;
  const maxBytes = opts.maxFileSizeBytes ?? DEFAULT_MAX_BYTES;

  // Host-supplied excludePatterns form the OUTERMOST skip layer: on-disk
  // .akaignore files are appended after it, so their negations win.
  const rootSkipLayers: IgnoreLayer[] =
    opts.excludePatterns && opts.excludePatterns.length > 0
      ? [{ base: rootDir, matcher: ignore().add(opts.excludePatterns) }]
      : [];

  // inIgnoredDir: git semantics — once a directory is gitignored, nothing
  // beneath it can be re-included, so we stop evaluating and mark everything.
  // (The skip stack needs no equivalent: a skipped directory is never entered.)
  function* visit(
    dir: string,
    markLayers: IgnoreLayer[],
    skipLayers: IgnoreLayer[],
    inIgnoredDir: boolean,
  ): Generator<WalkedFile> {
    let dirents: Dirent[];
    try {
      dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      return;
    }

    const markLayer = inIgnoredDir ? undefined : readIgnoreLayer(dir, '.gitignore');
    const dirMarkLayers = markLayer ? [...markLayers, markLayer] : markLayers;
    const skipLayer = readIgnoreLayer(dir, AKAIGNORE_FILENAME);
    const dirSkipLayers = skipLayer ? [...skipLayers, skipLayer] : skipLayers;

    for (const entry of dirents) {
      const name = entry.name;
      const fullPath = join(dir, name);

      if (entry.isDirectory()) {
        const skipState = evaluate(dirSkipLayers, fullPath, true);
        // Precedence: an explicit .akaignore re-include beats the SKIP_DIRS
        // default; otherwise SKIP_DIRS and .akaignore matches both hard-skip.
        if (skipState !== 'unignored' && (SKIP_DIRS.has(name) || skipState === 'ignored')) {
          continue;
        }
        const dirIgnored = inIgnoredDir || evaluate(dirMarkLayers, fullPath, true) === 'ignored';
        yield* visit(fullPath, dirMarkLayers, dirSkipLayers, dirIgnored);
        continue;
      }

      if (!entry.isFile()) continue;

      // extname handles dotfiles (.eslintrc → '') and extension-less names
      // (Makefile → '') — both fall out at the allowlist check.
      const ext = extname(name);
      if (!extensions.has(ext)) continue;

      // .akaignore skip — before stat/read, so an excluded file costs nothing.
      if (evaluate(dirSkipLayers, fullPath, false) === 'ignored') continue;

      let size: number;
      let mtime: Date;
      try {
        const st = statSync(fullPath);
        size = st.size;
        mtime = st.mtime;
      } catch {
        continue;
      }

      if (size > maxBytes) continue;

      const meta: WalkedFileMeta = {
        path: fullPath,
        // Posix-separated like every stored relative path (and the ignore
        // matching above) — native separators must not leak into the contract.
        relativePath: relative(rootDir, fullPath).split(sep).join('/'),
        mtime: mtime.toISOString(),
        size,
        gitignored: inIgnoredDir || evaluate(dirMarkLayers, fullPath, false) === 'ignored',
      };
      if (opts.shouldRead && !opts.shouldRead(meta)) continue;

      let content: string;
      try {
        content = readFileSync(fullPath, 'utf8');
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

  yield* visit(rootDir, [], rootSkipLayers, false);
}
