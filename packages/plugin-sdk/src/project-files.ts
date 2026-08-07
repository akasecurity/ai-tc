import { type Dirent, existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

import type { ProjectFileInput, ProjectFilesScan } from '@akasecurity/schema';
import ignore, { type Ignore } from 'ignore';

import { resolveHeadRoot, resolveWorktreeRoot } from './repo.ts';

// The real project-file inventory walk: enumerate the session worktree so the
// Inventory page's file tree shows the actual repo instead of an empty pane.
// Unlike the security scanner's walk (which READS gitignored files because
// that's where secrets hide), this is an inventory of the project as shared —
// gitignored files are local scratch, not part of the repo, so they are
// SKIPPED along with .git and dependency/build trees. Stat-only (no file
// contents), pure fs, fail-open: an unreadable directory marks the scan
// truncated (a partial walk must never shrink the stored tree) and a walk
// that can't even start returns undefined.
//
// Known fidelity gaps vs. "the project as shared", deliberate for now:
// symlinks are skipped (never followed — avoids cycle/escape risks; git
// tracks them as first-class entries, so recording them un-followed is a
// possible future upgrade), tracked-but-ignored files (`git add -f`, committed
// files under SKIP_DIRS) are invisible, `.git/info/exclude` and the global
// gitignore aren't consulted, and MAX_FILES bounds KEPT files, not traversal.
//
// Nothing bounds traversal, and the cost is not flat: an entry is tested against
// every .gitignore layer above it that has an opinion to give, so a tree whose
// directories each carry one costs O(entries x depth). A deep enough chain
// outruns the hosts' 10 s hook timeout, and a deep enough one over a wide leaf
// exhausts the heap. `bench/project-files.bench.ts` measures the curve.

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

// One .gitignore's rules, plus how much of the walk's current repo-relative
// directory path belongs to the directory that contains it (git patterns are
// relative to their own ignore file, not the repo root).
//
// The walk carries ONE `dirRel` string per directory and every layer keeps an
// offset into it, so testing a layer is a slice of that string. Holding a
// per-layer prefix instead would rebuild all of them on every descent — O(depth)
// strings of O(depth) characters per directory, for prefixes the deepest-first
// lookup below usually never reads.
interface IgnoreLayer {
  matcher: Ignore;
  /** Length of `dirRel` at the directory holding this .gitignore. */
  anchorLen: number;
}

function readIgnoreLayer(dir: string, anchorLen: number): IgnoreLayer | undefined {
  try {
    const content = readFileSync(join(dir, '.gitignore'), 'utf8');
    return { matcher: ignore().add(content), anchorLen };
  } catch {
    return undefined;
  }
}

/** `name` as the layer's own .gitignore addresses it: posix, anchor-relative. */
function relToAnchor(dirRel: string, anchorLen: number, name: string): string {
  if (anchorLen === dirRel.length) return name;
  // Skip the separator that follows the anchor, unless the anchor is the root
  // and contributes no leading segment at all.
  return `${dirRel.slice(anchorLen === 0 ? 0 : anchorLen + 1)}/${name}`;
}

// Layered gitignore verdict for the entry named `name` in the directory `dirRel`
// addresses. A deeper .gitignore's verdict (ignore OR `!` re-include) overrides
// a shallower one's, so the answer is the DEEPEST layer that has one: this walks
// from the deepest and returns at the first, which reaches that answer without
// consulting the ancestors behind it. A layer matching neither is silent and the
// search continues past it — an entry no layer names at all is kept.
// Directories are tested with a trailing slash so `dir/`-style patterns match.
function isIgnored(
  layers: readonly IgnoreLayer[],
  dirRel: string,
  name: string,
  isDir: boolean,
): boolean {
  const suffix = isDir ? '/' : '';
  for (let i = layers.length - 1; i >= 0; i--) {
    const layer = layers[i];
    if (layer === undefined) continue;
    const verdict = layer.matcher.test(relToAnchor(dirRel, layer.anchorLen, name) + suffix);
    if (verdict.ignored) return true;
    if (verdict.unignored) return false;
  }
  return false;
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
// `.txt` files that are manifests/config, not prose — checked BEFORE the docs
// branch, which would otherwise claim them via the blanket `.txt` extension.
const CONFIG_TXT_BASENAMES = new Set(['cmakelists.txt', 'constraints.txt', 'robots.txt']);
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
  // `requirements*.txt` covers requirements-dev.txt / requirements_test.txt….
  if (
    CONFIG_TXT_BASENAMES.has(lowerName) ||
    (ext === '.txt' && lowerName.startsWith('requirements'))
  ) {
    return 'config';
  }
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
    // A LINKED-worktree session walks its branch checkout, but the scan is
    // recorded under the HEAD repo's canonical project id — so it is a partial
    // view by construction (main-only files are absent from this checkout) and
    // must never prune the stored tree. Marked truncated, same as a capped walk.
    const isLinkedCheckout = resolveHeadRoot(cwd) !== worktree;

    const files: ProjectFileInput[] = [];
    // An unreadable subdirectory (chmod, antivirus lock, transient EMFILE)
    // means the walk lost a subtree it may have seen before — indistinguishable
    // from deletion unless the scan is marked truncated so the prune is skipped.
    // Held on an object, not a `let`: the flag is only ever set inside the
    // recursive `visit` closure, which control-flow analysis can't see — a
    // property read stays `boolean` where a narrowed `let` would read as `false`.
    const walk = { lostSubtree: false };

    // Returns true when the file cap was hit — propagated up so the whole walk
    // stops at the first over-cap file.
    // `dirRel` is `dir` as a repo-relative posix path ('' at the root). It is
    // built by appending one component per descent rather than diffed against
    // the root, which is also the path every kept file is recorded under.
    function visit(dir: string, dirRel: string, layers: IgnoreLayer[]): boolean {
      let dirents: Dirent[];
      try {
        dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
      } catch {
        walk.lostSubtree = true;
        return false;
      }
      const layer = readIgnoreLayer(dir, dirRel.length);
      // Copied only when this directory contributes a layer; otherwise the same
      // array descends unchanged, since a layer's anchor offset does not move.
      const dirLayers = layer ? [...layers, layer] : layers;

      for (const entry of dirents) {
        if (entry.isDirectory()) {
          if (SKIP_DIRS.has(entry.name) || isIgnored(dirLayers, dirRel, entry.name, true)) continue;
          const fullPath = join(dir, entry.name);
          // A nested `.git` marks ANOTHER repo's checkout (a linked worktree
          // under .claude/worktrees/, a nested clone, a submodule) — its files
          // belong to THAT project's tree, never this one's.
          if (existsSync(join(fullPath, '.git'))) continue;
          const childRel = dirRel === '' ? entry.name : `${dirRel}/${entry.name}`;
          if (visit(fullPath, childRel, dirLayers)) return true;
          continue;
        }
        // Dirent types are lstat-based, so a symlink is neither a file nor a
        // directory here and falls through — intentionally skipped, never
        // followed (see the fidelity-gaps note above).
        if (!entry.isFile()) continue;
        if (entry.name === '.git') continue;
        if (isIgnored(dirLayers, dirRel, entry.name, false)) continue;

        if (files.length >= MAX_FILES) return true;
        const relPath = dirRel === '' ? entry.name : `${dirRel}/${entry.name}`;
        files.push({
          path: relPath,
          name: basename(entry.name),
          origin: classifyOrigin(relPath, entry.name),
          defaultAccess: 'approved',
        });
      }
      return false;
    }

    const truncated = visit(root, '', []) || walk.lostSubtree || isLinkedCheckout;
    if (files.length === 0) return undefined;
    files.sort((a, b) => a.path.localeCompare(b.path));
    return { files, truncated, scannedAt: new Date().toISOString() };
  } catch {
    return undefined;
  }
}
