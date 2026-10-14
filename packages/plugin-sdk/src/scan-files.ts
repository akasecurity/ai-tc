// What a file-scanning walk may read: which files are source, which are the
// dotenv files secrets are kept in, and which paths are never read at all.
//
// `aka scan` (@akasecurity/local-ops fs-scan) reads every file that is not
// protected. The worktree scanner (@akasecurity/scanner walk) reads source and
// secret-bearing files by `scanFileKind`, and also skips the protected paths.
import { realpathSync } from 'node:fs';
import { basename, extname, resolve, sep } from 'node:path';

import { defaultDataDir } from '@akasecurity/persistence/sqlite-free';

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

// Document, image and log extensions that end a name such as `README.env.md`,
// which is about a dotenv file rather than one.
const NON_ENV_EXTENSIONS: ReadonlySet<string> = new Set([
  '.md',
  '.markdown',
  '.txt',
  '.rst',
  '.adoc',
  '.html',
  '.htm',
  '.pdf',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.log',
]);

export type ScanFileKind = 'source' | 'secret-bearing' | 'other';

/**
 * Classifies a file by its basename; a full path is reduced to its basename
 * first. `extname` gives a dotfile such as `.env` an empty extension, so a
 * dotenv file is recognised by name, case-insensitively: `.env`, every
 * `.env.<variant>`, every `<name>.env` and `<name>.env.<variant>`, and direnv's
 * `.envrc`. A name with a source extension is source first, so `.env.ts` is
 * source. Template variants such as `.env.example` are included on purpose,
 * because real keys get committed under those names; the command-risk rule that
 * flags reading a credential file excludes them, since it judges the command.
 */
export function scanFileKind(
  name: string,
  sourceExtensions: ReadonlySet<string> = SOURCE_EXTENSIONS,
): ScanFileKind {
  const base = basename(name);
  if (sourceExtensions.has(extname(base))) return 'source';
  const lower = base.toLowerCase();
  if (NON_ENV_EXTENSIONS.has(extname(lower))) return 'other';
  if (lower === '.envrc' || lower.endsWith('.env') || lower.includes('.env.')) {
    return 'secret-bearing';
  }
  return 'other';
}

/**
 * Whether a capture is a whole-file snapshot of a secret-bearing file. Such a
 * capture is recorded locally and never forwarded to a control plane. Decided
 * from the two fields that persist with the stored row, so a row read back
 * later is judged the same way as the live capture.
 */
export function isSecretBearingFileSnapshot(
  metadata: { filePath?: string | undefined; wholeFile?: boolean | undefined } | undefined,
): boolean {
  const filePath = metadata?.filePath;
  if (metadata?.wholeFile !== true || filePath === undefined) return false;
  return scanFileKind(basename(filePath)) === 'secret-bearing';
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
 * Not listed, and read by a scan: `~/.gemini` (the conversation store, which is
 * scanned) and `~/.claude.json` (user-authored MCP server configuration).
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
 * lexical form. A root and a path compared with `isProtectedScanPath` both come
 * through here, so a lexical fallback is only ever reached for an absent path,
 * which has nothing under it to match.
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
  return roots.some((root) => {
    if (!canonical.startsWith(root)) return false;
    if (canonical.length === root.length || root.endsWith(sep)) return true;
    return canonical[root.length] === sep;
  });
}
