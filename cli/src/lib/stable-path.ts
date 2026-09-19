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
//
// Each link is looked for only where its own layout puts it, keyed on the
// directory names that layout carries (`Cellar`, `apps`, `<version>/aka-<triple>`),
// never at an arbitrary ancestor. A `current` link is also looked for no more
// than CURRENT_LINK_REACH path segments above the file.

// Resolves a path through every link in it, or null when it names nothing.
export type Realpath = (path: string) => string | null;

export const realpathOrNull: Realpath = (path) => {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
};

// The deepest a file may sit below the directory a `current` link points at,
// in path segments. The installers and Scoop put the binary one segment below
// it and the native host two.
export const CURRENT_LINK_REACH = 3;

// The installers' binroot, `aka-<platform>-<arch>`, and the version directory it
// sits in. The release archive's own top-level directory,
// `aka-<version>-<platform>-<arch>`, matches neither.
const INSTALLER_BINROOT = /^aka-(?:darwin|linux|win32)-(?:arm64|x64)$/;
const INSTALLER_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

interface LayoutLink {
  // The link a layout re-points on upgrade.
  link: string;
  // The file, spelled through that link.
  path: string;
}

// The layout links that could name `realPath`, nearest version directory first.
// Unverified: most name nothing on any given machine.
function layoutLinks(realPath: string): LayoutLink[] {
  const links: LayoutLink[] = [];
  let versionDir = dirname(realPath);
  for (let reach = 1; ; reach++) {
    const parent = dirname(versionDir);
    if (parent === versionDir) break;
    const grandparent = dirname(parent);
    const rest = relative(versionDir, realPath);
    const add = (link: string): void => {
      links.push({ link, path: join(link, rest) });
    };
    if (reach <= CURRENT_LINK_REACH) {
      if (
        INSTALLER_BINROOT.test(basename(versionDir)) &&
        INSTALLER_VERSION.test(basename(parent)) &&
        grandparent !== parent
      ) {
        add(join(grandparent, 'current'));
      }
      if (basename(grandparent) === 'apps') add(join(parent, 'current'));
    }
    if (basename(grandparent) === 'Cellar') {
      add(join(dirname(grandparent), 'opt', basename(parent)));
    }
    versionDir = parent;
  }
  return links;
}

// `path` spelled through the link that follows upgrades, when one reaches the
// same file. Otherwise the resolved path itself, or `path` unchanged when it
// resolves to nothing.
export function stablePath(path: string, realpath: Realpath = realpathOrNull): string {
  const real = realpath(path);
  if (real === null) return path;
  for (const { path: candidate } of layoutLinks(real)) {
    if (candidate !== real && realpath(candidate) === real) return candidate;
  }
  return real;
}

export interface VersionPin {
  // The layout's link, e.g. <install-dir>/current.
  link: string;
  // Which version directory that link names: the one this file is in, or
  // another. `another-version` is decided on the link alone, and says nothing
  // about whether that version ships a file at this path.
  names: 'this-version' | 'another-version';
}

// How `path` stands against its layout's link, when it names a file directly
// inside a version directory that link belongs to: `this-version` is the
// spelling the next upgrade removes, `another-version` a version the link has
// already moved on from. Null for a path reached through a link, a path that
// names nothing, and a file no layout links to.
export function versionPin(path: string, realpath: Realpath = realpathOrNull): VersionPin | null {
  if (realpath(path) !== path) return null;
  const links = layoutLinks(path);
  for (const { link, path: candidate } of links) {
    if (candidate !== path && realpath(candidate) === path) {
      return { link, names: 'this-version' };
    }
  }
  // A link that exists and did not reach this file above names some other
  // version directory: spelled through it, this file's own path would lead
  // straight back here.
  for (const { link } of links) {
    const target = realpath(link);
    if (target !== null && target !== link) return { link, names: 'another-version' };
  }
  return null;
}
