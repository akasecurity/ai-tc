import { realpathSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';

// A path to an installed file that names no version.
//
// Every package-manager layout the binary ships through installs each version
// into its own directory and keeps one link pointed at the current one:
//
//   Homebrew   <prefix>/opt/<formula>        -> <prefix>/Cellar/<formula>/<version>
//   Scoop      <root>/apps/<app>/current     -> <root>/apps/<app>/<version>
//   installers <install-dir>/current         -> <install-dir>/<version>/aka-<triple>
//
// A path written down once and read on every later launch has to go through
// that link: the versioned directory is removed by the next upgrade, and the
// link is re-pointed at its replacement.

// Resolves a path through every link in it, or null when it names nothing.
export type Realpath = (path: string) => string | null;

export const realpathOrNull: Realpath = (path) => {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
};

// The link-based spellings of `realPath` the layouts above would provide, nearest
// version directory first. Unverified: most name nothing on any given machine.
export function stablePathCandidates(realPath: string): string[] {
  const candidates: string[] = [];
  let versionDir = dirname(realPath);
  for (;;) {
    const parent = dirname(versionDir);
    if (parent === versionDir) break;
    const rest = relative(versionDir, realPath);
    candidates.push(join(parent, 'current', rest));
    const grandparent = dirname(parent);
    if (grandparent !== parent) {
      candidates.push(join(grandparent, 'current', rest));
      if (basename(grandparent) === 'Cellar') {
        candidates.push(join(dirname(grandparent), 'opt', basename(parent), rest));
      }
    }
    versionDir = parent;
  }
  return candidates;
}

// `path` spelled through the link that follows upgrades, when one reaches the
// same file. Otherwise the resolved path itself, or `path` unchanged when it
// resolves to nothing.
export function stablePath(path: string, realpath: Realpath = realpathOrNull): string {
  const real = realpath(path);
  if (real === null) return path;
  for (const candidate of stablePathCandidates(real)) {
    if (candidate !== real && realpath(candidate) === real) return candidate;
  }
  return real;
}

// Whether `path` names a file directly, inside a version directory that one of
// the layouts above links to — the spelling the next upgrade removes.
export function isVersionPinned(path: string, realpath: Realpath = realpathOrNull): boolean {
  if (realpath(path) !== path) return false;
  return stablePath(path, realpath) !== path;
}
