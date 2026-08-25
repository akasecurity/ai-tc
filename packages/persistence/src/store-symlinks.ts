// Which store paths are symlinks, and what the store inherits by following them.
//
// A chmod is never applied through a symlink (see chmodBestEffort in paths.ts),
// and mkdir does not follow the final link either, so a symlinked store path is
// used AS-IS: the store — including the prompt corpus in aka.db — is written
// inside the link's target, under whatever permissions that target already had.
// Neither fact is visible from the outside, so every surface that can tell the
// user has to be able to ask what the links are. Detection lives here, at the
// layer that owns the ~/.aka layout, because two callers need it and they render
// it very differently: `aka init` prints a multi-line report, and the hooks emit
// one line on stderr. Only the wording is theirs; the facts are one function.
import { existsSync, lstatSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { dataDir, dbPath, keysDir, settingsDir } from './local-layout.ts';

// Every path the store spans and holds to an owner-only mode, mapped to what
// actually lands there. Not all of them are created by `aka init` — keys/ is
// minted lazily by the vault key provider, on first use — so an absent path is
// the normal case and each caller filters it out rather than treating it as a
// finding.
//
// The description is load-bearing, not decoration: the symlink warning is
// emitted once per path, and one generic sentence is wrong for most of them.
// `aka.db` only ever lands under data/, so telling a reader their prompt corpus
// went to ~/.aka/keys sends them to the wrong directory to check.
const STORE_DB = 'the store database (including the prompt corpus)';
const STORE_SETTINGS = 'your settings file';

function storeContents(home: string): Map<string, string> {
  return new Map([
    [home, 'the store (including the prompt corpus in aka.db)'],
    [settingsDir(home), STORE_SETTINGS],
    [dataDir(home), STORE_DB],
    [keysDir(home), 'the vault key'],
    [join(settingsDir(home), 'settings.json'), STORE_SETTINGS],
    [dbPath(home), STORE_DB],
  ]);
}

/**
 * The same layout as a plain list, for the callers that only need the paths.
 * Derived from the map rather than kept beside it, so a path can never appear in
 * one and not the other — and the descriptions stay private, since nothing
 * outside this module consumes them.
 */
export function storeTargets(home: string): string[] {
  return [...storeContents(home).keys()];
}

/**
 * One symlinked store path: where it points, what lands there, whether the
 * target resolves, and the mode the store inherits from it.
 */
export interface SymlinkedStorePath {
  path: string;
  target: string;
  holds: string;
  missing: boolean;
  mode?: number | undefined;
}

/**
 * The store paths that are symlinks, with what they resolve to and the mode that
 * target carries right now.
 *
 * NOT POSIX-gated, unlike the CLI's loose-path report. Windows applies no mode at
 * all, so there the redirection is the ONLY at-rest fact left to report — and a
 * junction, which lstat reports as a symlink, needs no elevation to create, so
 * this is reachable there. What drops away on Windows is the mode half, not the
 * finding. `platform` is a parameter so both branches are testable from any host.
 */
export function symlinkedStorePaths(
  home: string,
  platform: NodeJS.Platform = process.platform,
): SymlinkedStorePath[] {
  return [...storeContents(home)].flatMap(([path, holds]) => {
    try {
      if (!lstatSync(path).isSymbolicLink()) return [];
      return [
        {
          path,
          target: linkTarget(path),
          holds,
          // existsSync follows the link, so a target that is gone reads as
          // absent here while lstat above still sees the link itself.
          missing: !existsSync(path),
          mode: targetMode(path, platform),
        },
      ];
    } catch {
      return []; // absent → not a symlinked target
    }
  });
}

/**
 * Where a link points, preferring the fully resolved absolute path — that is the
 * directory the store actually lands in, which is what the warning is about. A
 * link resolving nowhere has no real path, so fall back to its literal contents,
 * resolved against the link's own directory: readlink returns whatever was
 * stored, and a relative target on its own names nothing a reader can act on.
 */
export function linkTarget(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(dirname(path), readlinkSync(path));
  }
}

// The mode the link's target carries. This is the permission the store actually
// inherits, and it is the fact a loose-path report can no longer carry — it skips
// a symlinked path, because the chmod there was declined rather than rejected,
// and without this the one actionable half of the warning ("that target is
// readable by everyone") would go unsaid. Undefined when there is nothing to
// stat, so a link resolving nowhere reads as unknown rather than as owner-only —
// and on Windows, where no mode is ever applied and there is none to inherit.
function targetMode(path: string, platform: NodeJS.Platform): number | undefined {
  if (platform === 'win32') return undefined;
  try {
    return statSync(path).mode & 0o777; // statSync follows the link, which is the point
  } catch {
    return undefined;
  }
}
