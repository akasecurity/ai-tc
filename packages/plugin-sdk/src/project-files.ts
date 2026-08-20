import { type Dirent, existsSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

import type { ProjectFileInput, ProjectFilesScan } from '@akasecurity/schema';

import {
  childRel,
  evaluateIgnore,
  type IgnoreLayer,
  readIgnoreLayer,
  withLayer,
} from './ignore-layers.ts';
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
// files under SKIP_DIRS) are invisible, and `.git/info/exclude` and the global
// gitignore aren't consulted.
//
// TRAVERSAL IS BOUNDED, AND MAX_FILES IS NOT THE BOUND. MAX_FILES caps what is
// KEPT; the cost of getting there is `entries x layers`, since an entry is
// tested against every .gitignore layer above it that has an opinion to give.
// Measured on an arm64 Mac against `test/fixtures/adversarial/hostile-repo/`:
// 400 nested directories each carrying a .gitignore, over 5,000 leaf files, took
// 13.0 s and 645 MB — past the hosts' 10 s hook timeout, on a tree of 5,400
// files. Claude Code and Codex read a killed hook as "no opinion" and lose the
// inventory; Antigravity reads it as a DENY and runs this pass from
// `PreInvocation`, so there the same tree blocks the user's every tool call.
// A synchronous walk never yields, so no watchdog can preempt it — the bound
// has to be inside the walk.
//
// WHY IT IS TWO NUMBERS RATHER THAN ONE. Neither half bounds the product on its
// own, and each is easy to mistake for sufficient:
//
//   - A DEPTH cap bounds the layer stack, so it bounds the cost of one entry.
//     It bounds nothing about how many entries there are — 500k files ignored by
//     a pattern at the SHALLOWEST layer are each tested against the whole stack
//     before that match is reached, and none of them is a KEPT file, so
//     MAX_FILES never fires. Measured at the cap: that shape still costs 5.6 s.
//   - A DEADLINE bounds the total whatever the shape, and is the only bound
//     stated in the unit the host actually enforces. It cannot replace the depth
//     cap: a deadline says nothing until it fires, so the deep chain would spend
//     the whole budget on one subtree and every ordinary repo would pay for the
//     clock instead of the depth cap answering in one comparison.
//
// A work budget was tried in between the two and is not what ships. Charging
// `1 + layers` per entry bounds the same quantity deterministically, but the
// number that makes it safe can only be calibrated on one machine: 3,000,000
// units measured 5.6 s here and would be three times that on a slow runner —
// which is the hook timeout, reached by the bound meant to prevent it.
//
// Both are stated as defaults on {@link PROJECT_WALK_BOUNDS} and overridable per
// call, and the clock is injectable, so a test drives either with a tree small
// enough to build and no wall-clock flake.
//
// AND A BOUND CHANGES WHAT THE STORED TREE CONTAINS, which is the part that
// cannot be quiet. A partial walk that is not marked `truncated` PRUNES whatever
// is already stored down to what this pass could see, so every omission here —
// a subtree past the depth cap, a walk stopped on the deadline — sets it, the
// same way an unreadable directory and the MAX_FILES cap already do.
// `bench/project-files.bench.ts` measures the curve under the bound.

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

/** How far the walk may descend, and how long it may spend. */
export interface ProjectWalkBounds {
  /**
   * Deepest directory below the worktree root the walk enters. Also bounds the
   * ignore-layer stack and the length of the walk-relative path every layer is
   * addressed through, since both grow with depth.
   */
  maxDepth: number;
  /** Wall-clock ceiling on the whole walk. Reaching it stops the walk. */
  budgetMs: number;
}

/**
 * The shipped bounds.
 *
 * `maxDepth: 64` is about nine times the deepest path this repository tracks
 * (7), and dependency and build trees are in SKIP_DIRS before depth is
 * consulted at all — so no project layout reaches it and an attacker-authored
 * chain stops there.
 *
 * `budgetMs: 4_000` sits inside the hosts' 10 s hook timeout with room for
 * everything else SessionStart does, and above the performance plan's worst
 * LEGITIMATE case: a monorepo of 500k gitignored files, traversed because the
 * pattern is what ignores them rather than the directory, measured 852 ms here
 * (arm64 Mac) and stays whole on a runner several times slower. A repository
 * that does cross it is truncated rather than lost, which is the trade — the
 * alternative is the host killing the hook, which on Antigravity denies the
 * user's tool call and stores nothing at all.
 */
export const PROJECT_WALK_BOUNDS: ProjectWalkBounds = { maxDepth: 64, budgetMs: 4_000 };

/**
 * How often the deadline is read, in entries. A `now()` per entry is a real cost
 * on the 500k-entry trees this is sized against, and the bound it enforces is
 * seconds — so reading it every few hundred entries is exact enough while
 * costing nothing measurable.
 */
const DEADLINE_CHECK_INTERVAL = 512;

/** Everything a caller may vary. The clock is injectable so a deadline test needs no wall clock. */
export interface ProjectWalkOptions {
  bounds?: ProjectWalkBounds;
  /** Monotonic milliseconds. Defaults to `performance.now`. */
  now?: () => number;
}

// The layer representation and the deepest-first lookup live in
// ./ignore-layers.ts, shared with the dashboard's folder scan and the standalone
// scanner — all three walk a tree under accumulated ignore files and asked the
// same question three different ways until they did not.
//
// This walk keeps only the mapping onto its own question: an entry is inventoried
// unless the deepest layer with an opinion says `ignored`. An explicit `!`
// re-include (`unignored`) and no opinion at all (`unmatched`) both keep the
// entry — the two are distinct only for callers carrying a default skip floor
// for a re-include to override, and this walk's SKIP_DIRS floor is absolute.
function isIgnored(
  layers: readonly IgnoreLayer[],
  dirRel: string,
  name: string,
  isDir: boolean,
): boolean {
  return evaluateIgnore(layers, dirRel, name, isDir) === 'ignored';
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
export function resolveProjectFiles(
  cwd: string,
  opts: ProjectWalkOptions = {},
): ProjectFilesScan | undefined {
  const bounds = opts.bounds ?? PROJECT_WALK_BOUNDS;
  const now = opts.now ?? (() => performance.now());
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
    //
    // `omitted` is the same signal reached by a BOUND rather than by a fault: a
    // subtree refused at the depth cap, or a walk stopped on the deadline, is a
    // subtree this pass cannot see, and it prunes exactly like a lost one unless
    // the scan says so. Kept separate from `lostSubtree` because the two are
    // different facts about the tree and only one of them is a filesystem
    // problem. `seen` drives how often the deadline is read.
    const walk = { lostSubtree: false, omitted: false, seen: 0 };
    const deadline = now() + bounds.budgetMs;

    // Returns true when the walk must STOP — the file cap or the traversal
    // budget — propagated up so nothing below it is visited.
    // `dirRel` is `dir` as a repo-relative posix path ('' at the root). It is
    // built by appending one component per descent rather than diffed against
    // the root, which is also the path every kept file is recorded under.
    // `depth` is how far below the root `dir` sits; the root itself is 0.
    function visit(
      dir: string,
      dirRel: string,
      layers: readonly IgnoreLayer[],
      depth: number,
    ): boolean {
      let dirents: Dirent[];
      try {
        dirents = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
      } catch {
        walk.lostSubtree = true;
        return false;
      }
      // The deadline is read on TWO schedules, and neither covers the other.
      //
      // Per DIRECTORY, here: the entry counter below is global, so a tree with
      // fewer entries than one interval never reaches a check at all — measured,
      // a 100-file tree walked against a 1 ms budget and a clock already
      // 10,000,000 ms past it read the clock exactly once, at the start, and
      // finished untruncated. That is not a rare shape: a deep chain of small
      // directories costs a readdir, a `.gitignore` read and an `existsSync` per
      // level, which is where a slow or networked filesystem spends seconds
      // without ever producing many entries.
      if (now() > deadline) {
        walk.omitted = true;
        return true;
      }
      // Copied only when this directory contributes a layer; otherwise the same
      // array descends unchanged, since a layer's anchor offset does not move.
      const dirLayers = withLayer(layers, readIgnoreLayer(dir, '.gitignore', dirRel.length));

      for (const entry of dirents) {
        // And per ENTRY, because the mirror-image shape is one directory holding
        // half a million of them — checked only on entry to a directory, the
        // deadline would not be read again until that whole readdir had been
        // walked. The interval keeps that read off the per-entry hot path.
        walk.seen++;
        if (walk.seen % DEADLINE_CHECK_INTERVAL === 0 && now() > deadline) {
          walk.omitted = true;
          return true;
        }

        if (entry.isDirectory()) {
          if (SKIP_DIRS.has(entry.name) || isIgnored(dirLayers, dirRel, entry.name, true)) continue;
          const fullPath = join(dir, entry.name);
          // A nested `.git` marks ANOTHER repo's checkout (a linked worktree
          // under .claude/worktrees/, a nested clone, a submodule) — its files
          // belong to THAT project's tree, never this one's.
          if (existsSync(join(fullPath, '.git'))) continue;
          // Refused for DEPTH, after the checks above: a directory the tree
          // was never going to enter is not an omission, and marking one would
          // truncate a scan of an ordinary repo whose node_modules happens to
          // sit deep.
          if (depth >= bounds.maxDepth) {
            walk.omitted = true;
            continue;
          }
          if (visit(fullPath, childRel(dirRel, entry.name), dirLayers, depth + 1)) return true;
          continue;
        }
        // Dirent types are lstat-based, so a symlink is neither a file nor a
        // directory here and falls through — intentionally skipped, never
        // followed (see the fidelity-gaps note above).
        if (!entry.isFile()) continue;
        if (entry.name === '.git') continue;
        if (isIgnored(dirLayers, dirRel, entry.name, false)) continue;

        if (files.length >= MAX_FILES) return true;
        const relPath = childRel(dirRel, entry.name);
        files.push({
          path: relPath,
          name: basename(entry.name),
          origin: classifyOrigin(relPath, entry.name),
          defaultAccess: 'approved',
        });
      }
      return false;
    }

    const truncated =
      visit(root, '', [], 0) || walk.lostSubtree || walk.omitted || isLinkedCheckout;
    if (files.length === 0) return undefined;
    files.sort((a, b) => a.path.localeCompare(b.path));
    return { files, truncated, scannedAt: new Date().toISOString() };
  } catch {
    return undefined;
  }
}
