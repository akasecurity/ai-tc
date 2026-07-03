// Cross-repo discovery: walk the filesystem from EXPLICIT search roots and
// return the absolute path of every git repo root found. Pure node:fs I/O —
// never spawns child processes. Best-effort: unreadable directories are silently
// skipped so a permission error on one path never aborts the whole discovery.
import { type Dirent, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { COMMON_SKIP_DIRS } from './constants.ts';

// Directories to skip during discovery traversal, extending the shared cache
// list. Distinct from walk's SKIP_DIRS: we don't skip .git here (its presence
// is what we're detecting), but we do skip platform directories that never
// contain code repos.
const DISCOVER_SKIP = new Set([
  ...COMMON_SKIP_DIRS,
  'Library', // macOS user library — large, no repos
  'System', // macOS system — never a repo
  'Applications', // macOS app bundles
  '.Trash',
  '.npm',
  '.pnpm',
  '.yarn',
]);

export interface DiscoverOptions {
  // Directories to search. REQUIRED — the library never picks a scope this
  // powerful itself. The host decides the default (the plugin uses the current
  // working directory) and must get explicit user intent before anything as
  // broad as the home directory.
  searchRoots: string[];
  maxDepth?: number; // how many levels deep to recurse (default: 4)
  excludePaths?: Set<string>; // absolute paths to skip entirely
}

// Walk down from each search root and collect the path of every directory that
// contains a `.git` entry. Stops recursing into a directory once `.git` is
// found there — nested repos (submodules) are not separately enumerated.
// Returns deduplicated, absolute repo root paths.
export function discoverGitRepos(opts: DiscoverOptions): string[] {
  const searchRoots = opts.searchRoots;
  const maxDepth = opts.maxDepth ?? 4;
  const excludePaths = opts.excludePaths ?? new Set<string>();

  const repos: string[] = [];
  const seen = new Set<string>();

  function visit(dir: string, depth: number): void {
    if (depth > maxDepth || excludePaths.has(dir)) return;

    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      return;
    }

    const hasGit = entries.some((e) => e.name === '.git');
    if (hasGit) {
      if (!seen.has(dir)) {
        seen.add(dir);
        repos.push(dir);
      }
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (DISCOVER_SKIP.has(entry.name)) continue;
      if (entry.name.startsWith('.')) continue; // skip hidden dirs not in allow-list
      visit(join(dir, entry.name), depth + 1);
    }
  }

  for (const root of searchRoots) {
    visit(root, 0);
  }

  return repos;
}
