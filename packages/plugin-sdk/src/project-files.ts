import { type Dirent, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';

import type { ProjectFileInput, ProjectFilesScan } from '@akasecurity/schema';
import ignore, { type Ignore } from 'ignore';

import { resolveWorktreeRoot } from './repo.ts';

// The real project-file inventory walk: enumerate the session worktree so the
// Inventory page's file tree shows the actual repo instead of an empty pane.
// Unlike the security scanner's walk (which READS gitignored files because
// that's where secrets hide), this is an inventory of the project as shared —
// gitignored files are local scratch, not part of the repo, so they are
// SKIPPED along with .git and dependency/build trees. Stat-only (no file
// contents), pure fs, fail-open: any unreadable entry is silently dropped and
// a walk that can't even start returns undefined.

// Hard floor of never-inventoried directories — huge machine-generated trees.
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.pnpm-store',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.turbo',
  'dist',
  'build',
  'out',
  'coverage',
  'target',
  '.cache',
]);

// A partial tree is worse than a capped one everywhere except huge monorepos;
// 20k files covers those comfortably while bounding SessionStart cost.
const MAX_FILES = 20_000;

// One .gitignore's rules, anchored to the directory that contains it (git
// patterns are relative to their own ignore file, not the repo root).
interface IgnoreLayer {
  base: string;
  matcher: Ignore;
}

function readIgnoreLayer(dir: string): IgnoreLayer | undefined {
  try {
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    return { base: dir, matcher: ignore().add(content) };
  } catch {
    return undefined;
  }
}

// Layered gitignore verdict, deeper files consulted later so their verdicts
// (ignore OR `!` re-include) override shallower ones. Directories are tested
// with a trailing slash so `dir/`-style patterns match.
function isIgnored(layers: IgnoreLayer[], absPath: string, isDir: boolean): boolean {
  let ignored = false;
  for (const layer of layers) {
    const rel = relative(layer.base, absPath).split(sep).join('/') + (isDir ? '/' : '');
    const verdict = layer.matcher.test(rel);
    if (verdict.ignored) ignored = true;
    else if (verdict.unignored) ignored = false;
  }
  return ignored;
}

// ─── Origin classification ────────────────────────────────────────────────────
// Deterministic path/extension heuristics onto the schema Origin vocabulary.
// First match wins, most specific first; anything unclassified is first-party
// `source`. (`public-dep` never occurs here — dependency trees are skipped.)

const GENERATED_FILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'cargo.lock',
  'poetry.lock',
  'gemfile.lock',
  'composer.lock',
  'go.sum',
]);
const CONFIG_EXTENSIONS = new Set(['.yml', '.yaml', '.toml', '.ini', '.properties', '.conf']);
const DOCS_EXTENSIONS = new Set(['.md', '.mdx', '.rst', '.adoc', '.txt']);
const DATA_EXTENSIONS = new Set(['.csv', '.tsv', '.parquet', '.sql', '.jsonl', '.ndjson']);
const CONFIG_BASENAMES = new Set([
  'package.json',
  'dockerfile',
  'makefile',
  'justfile',
  '.gitignore',
  '.gitattributes',
  '.npmrc',
  '.nvmrc',
  '.editorconfig',
  '.akaignore',
]);

function classifyOrigin(relPath: string, name: string): ProjectFileInput['origin'] {
  const lowerName = name.toLowerCase();
  const dot = lowerName.lastIndexOf('.');
  const ext = dot > 0 ? lowerName.slice(dot) : '';
  const segments = relPath.split('/');

  if (
    GENERATED_FILES.has(lowerName) ||
    lowerName.includes('.generated.') ||
    segments.includes('__generated__') ||
    segments.includes('generated') ||
    ext === '.map' ||
    lowerName.endsWith('.min.js') ||
    lowerName.endsWith('.min.css')
  ) {
    return 'generated';
  }
  if (segments.includes('vendor') || segments.includes('third_party')) return 'vendored';
  if (DOCS_EXTENSIONS.has(ext) || lowerName.startsWith('license') || segments[0] === 'docs') {
    return 'docs';
  }
  if (
    DATA_EXTENSIONS.has(ext) ||
    segments.includes('fixtures') ||
    segments.includes('__fixtures__')
  ) {
    return 'data';
  }
  if (
    CONFIG_BASENAMES.has(lowerName) ||
    CONFIG_EXTENSIONS.has(ext) ||
    lowerName.startsWith('.') ||
    lowerName.includes('.config.') ||
    lowerName.startsWith('tsconfig')
  ) {
    return 'config';
  }
  return 'source';
}

/**
 * Walk the git worktree containing `cwd` into a {@link ProjectFilesScan}:
 * every non-gitignored file, repo-relative posix path, origin-classified, with
 * the private-repo default access (`approved` — the per-file override table is
 * where users adjust). Returns undefined outside a git repo or when the walk
 * yields nothing (a failed walk must drop the scan, never wipe a stored tree).
 */
export function resolveProjectFiles(cwd: string): ProjectFilesScan | undefined {
  try {
    const worktree = resolveWorktreeRoot(cwd);
    if (!worktree) return undefined;
    const root: string = worktree;

    const files: ProjectFileInput[] = [];

    // Returns true when the file cap was hit — propagated up so the whole walk
    // stops at the first over-cap file.
    function visit(dir: string, layers: IgnoreLayer[]): boolean {
      let dirents: Dirent[];
      try {
        dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
      } catch {
        return false;
      }
      const layer = readIgnoreLayer(dir);
      const dirLayers = layer ? [...layers, layer] : layers;

      for (const entry of dirents) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (SKIP_DIRS.has(entry.name) || isIgnored(dirLayers, fullPath, true)) continue;
          // A nested `.git` marks ANOTHER repo's checkout (a linked worktree
          // under .claude/worktrees/, a nested clone, a submodule) — its files
          // belong to THAT project's tree, never this one's.
          if (existsSync(join(fullPath, '.git'))) continue;
          if (visit(fullPath, dirLayers)) return true;
          continue;
        }
        if (!entry.isFile()) continue;
        if (entry.name === '.git') continue;
        if (isIgnored(dirLayers, fullPath, false)) continue;

        if (files.length >= MAX_FILES) return true;
        const relPath = relative(root, fullPath).split(sep).join('/');
        files.push({
          path: relPath,
          name: basename(entry.name),
          origin: classifyOrigin(relPath, entry.name),
          defaultAccess: 'approved',
        });
      }
      return false;
    }

    const truncated = visit(root, []);
    if (files.length === 0) return undefined;
    files.sort((a, b) => a.path.localeCompare(b.path));
    return { files, truncated, scannedAt: new Date().toISOString() };
  } catch {
    return undefined;
  }
}
