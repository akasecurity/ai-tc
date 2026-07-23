import { readdirSync, realpathSync } from 'node:fs';
import { basename, dirname, sep } from 'node:path';

// Shared by every writer that stores or compares repo-relative paths (the
// CLI/web-ui scan pipeline and the plugin scan pipeline both key stored rows
// on paths built this way), so the two pipelines produce byte-identical path
// keys for the same file instead of drifting apart under two hand-written
// copies of the same one-liner.

/** Normalize a filesystem path to posix-style forward slashes. A no-op outside win32. */
export function toPosix(path: string): string {
  return path.split(sep).join('/');
}

/** A resolved project identity for a scan target that sits outside any git repo. */
export interface NonGitProject {
  /** The directory every stored path is relativized against. */
  root: string;
  /** The `path:`-prefixed reconcile key every stored row for this project shares. */
  projectKey: string;
  /** Display name: the resolved project root's own directory name. */
  project: string;
}

// How many directory levels the project-root search climbs before giving up.
// Bounds the readdir work per resolution and stops the walk from ever running
// to the filesystem root on a pathological path.
const MAX_PROJECT_ROOT_LEVELS = 40;

// The highest ancestor at or above `startDir` (within the bounded climb) that
// directly contains a file whose basename `recognizeMarker` accepts, or
// `startDir` itself when none does. Climbing to the HIGHEST marker is what makes
// a scan of `/proj` and a scan of `/proj/src` resolve to the same `/proj` when
// `/proj/package.json` exists.
function findProjectRoot(startDir: string, recognizeMarker: (basename: string) => unknown): string {
  let dir = startDir;
  let root: string | null = null;
  for (let level = 0; level < MAX_PROJECT_ROOT_LEVELS; level += 1) {
    if (directoryHasMarker(dir, recognizeMarker)) root = dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return root ?? startDir;
}

// True when `dir` directly contains a file whose basename `recognizeMarker`
// accepts. An unreadable directory carries no marker, so the climb continues.
function directoryHasMarker(dir: string, recognizeMarker: (basename: string) => unknown): boolean {
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && recognizeMarker(entry.name) != null) return true;
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * Resolve a stable project identity for a NON-git scan target, so a scan at any
 * depth inside the same project keys and relativizes on one anchor. `startDir`
 * is the walked directory (a file target passes its own dirname);
 * `recognizeMarker` classifies a basename as a project marker (pass
 * `manifestKindOf`, whose non-null result marks a dependency manifest such as
 * package.json, go.mod, or a .csproj).
 *
 * The anchor is the highest ancestor carrying a marker. With no marker anywhere
 * above the target it falls back to the target itself — a bare folder with no
 * manifest has no project boundary, so scans at different depths inside it
 * cannot reconcile, which is unavoidable when there is no boundary to find.
 *
 * `root` and the `path:` key both derive from that one resolved root, so a
 * stored path (taken relative to `root`) always matches its key. The key uses
 * the root's realpath so two symlinked routes to one directory share it, and two
 * directories with the same basename never collide; `realpathSync` throwing on a
 * vanished path propagates to the fail-open caller.
 */
export function resolveNonGitProject(
  startDir: string,
  recognizeMarker: (basename: string) => unknown,
): NonGitProject {
  const projectRoot = findProjectRoot(startDir, recognizeMarker);
  const realRoot = realpathSync(projectRoot);
  return { root: projectRoot, projectKey: `path:${realRoot}`, project: basename(realRoot) };
}
