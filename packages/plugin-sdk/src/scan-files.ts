// What a file-scanning walk may read: which files are source, which are the
// dotenv files secrets are kept in, and which paths are never read at all.
// Shared by `aka scan` (@akasecurity/local-ops fs-scan) and the worktree
// scanner (@akasecurity/scanner walk).
import { realpathSync } from 'node:fs';
import { basename, extname, resolve, sep } from 'node:path';

import { defaultDataDir } from '@akasecurity/persistence';

export const SOURCE_EXTENSIONS: ReadonlySet<string> = new Set([
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

export type ScanFileKind = 'source' | 'secret-bearing' | 'other';

/**
 * Classifies a file by its basename. `extname` gives a dotfile such as `.env`
 * an empty extension, so a dotenv file is recognised by name: `.env` itself
 * and every `.env.<variant>`. A name with a source extension is source first,
 * so `.env.ts` is source.
 */
export function scanFileKind(
  name: string,
  sourceExtensions: ReadonlySet<string> = SOURCE_EXTENSIONS,
): ScanFileKind {
  if (sourceExtensions.has(extname(name))) return 'source';
  if (name === '.env' || name.startsWith('.env.')) return 'secret-bearing';
  return 'other';
}

/**
 * Paths a scan never reads, whatever it is pointed at: live credentials AKA or
 * its host wrote for itself.
 *
 *   <home>/.claude/ide/              one lock file per attached IDE, carrying a live auth token
 *   <home>/.claude/.credentials.json the host's stored credential
 *   <home>/.codex/auth.json          the Codex CLI's stored credential
 *   <akaHome>, <home>/.aka, default  AKA's own homes: vault key, control-plane credential, store
 *
 * `home` is the OS home the hosts write under; `akaHome` is AKA's own home,
 * which `--home` relocates independently, so both are protected. Neither host
 * home honours a relocation variable such as `CODEX_HOME`.
 *
 * Returned canonical (see `canonicalizeScanPath`) and deduplicated. Computed per
 * call rather than at module scope because `homedir()` and `defaultDataDir()`
 * can throw on a host with no home configured.
 */
export function protectedScanRoots(home: string, akaHome: string): readonly string[] {
  const akaHomeDirname = basename(defaultDataDir());
  return [
    ...new Set(
      [
        resolve(home, '.claude', 'ide'),
        resolve(home, '.claude', '.credentials.json'),
        resolve(home, '.codex', 'auth.json'),
        resolve(akaHome),
        defaultDataDir(),
        resolve(home, akaHomeDirname),
      ].map(canonicalizeScanPath),
    ),
  ];
}

/**
 * A path's on-disk identity: symlinks followed and, on a case-insensitive
 * volume, the volume's own casing (`realpathSync.native` returns it;
 * `realpathSync` does not). A path that does not exist falls back to its
 * lexical form.
 */
export function canonicalizeScanPath(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    return resolve(path);
  }
}

/** Whether a canonical path is a protected root or lies under one. */
export function isProtectedScanPath(canonical: string, roots: readonly string[]): boolean {
  return roots.some((root) => canonical === root || canonical.startsWith(root + sep));
}
