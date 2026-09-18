import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';

import type { CliUpdateTarget, ReleaseChannel } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';

import { quoteForDisplay } from './exec.ts';
import { isSea } from './self-exec.ts';
import { isExactSemver } from './semver.ts';
import { CLI_PACKAGE, isRecord } from './updates.ts';

// How THIS `aka` got onto the machine, and therefore how it must be updated.
//
// `npm install -g` is only correct for one of the installations we ship. A
// standalone-installer binary embeds its own runtime and has no npm package
// behind it; a pnpm/bun/yarn global lives in that manager's own store; and an
// npm global installed under one nvm version is invisible to the `npm` that is
// first on PATH under another. Running the wrong one is not a no-op — it
// installs a SECOND copy that may or may not win the PATH lookup, so `aka
// --version` reports the old one and the update looks broken.
//
// So the channel is derived from where the running code actually lives, never
// from what happens to be on PATH, and the update is pinned back to that same
// location.
//
// This module does NOT read `import.meta.url` to find that location, and must
// not start. Every caller states its own origin (`InstallOrigin`), because the
// two apps that call this are bundled by different tools and only one of them
// leaves that value intact: esbuild/tsup keeps it, so the CLI's own dist path
// is what it resolves to at runtime, while a Next build REPLACES it with the
// build machine's absolute source path, baked in as a string literal. A default
// here would therefore be correct in the CLI, correct on the machine that ran
// the web build, and wrong on every user's dashboard — the failure that is
// invisible to every local check. `install-channel.test.ts` pins the absence.

export type InstallManager = 'npm' | 'pnpm' | 'yarn' | 'bun';

/**
 * What replaces the standalone binary. The same bytes ship through three
 * routes, and each is updated by a different command: a package manager that
 * owns the files it laid down, or the standalone installer, which owns nothing
 * and simply unpacks over its own root.
 */
export const SEA_OWNER = {
  Homebrew: 'homebrew',
  Scoop: 'scoop',
  Standalone: 'standalone',
} as const;

export type SeaOwner = (typeof SEA_OWNER)[keyof typeof SEA_OWNER];

export type InstallChannel =
  /**
   * The self-contained binary. `managedBy` names what replaces it; `installRoot`
   * is the standalone installer's own root, and is null for every other owner —
   * whose layout the installer rule would otherwise match and misreport.
   */
  | { kind: 'sea'; execPath: string; managedBy: SeaOwner; installRoot: string | null }
  /** A global install owned by a JS package manager, pinned to `root`. */
  | { kind: 'global'; manager: InstallManager; root: string; packageDir: string }
  /** A Homebrew-managed tree — brew owns the files, so brew must do the upgrade. */
  | { kind: 'homebrew'; packageDir: string }
  /** Running out of a source checkout (`pnpm dev`, a linked workspace). */
  | { kind: 'dev'; packageDir: string }
  /**
   * Installed as a DEPENDENCY of a project rather than as a tool on PATH —
   * `<project>/node_modules/@akasecurity/cli`, which is what `npx aka` runs.
   * Nothing global owns this copy: it is updated by bumping the dependency in
   * the project that declares it.
   */
  | { kind: 'project'; packageDir: string; projectRoot: string; manager: InstallManager }
  /** Located, but under no layout we recognise. */
  | { kind: 'unknown'; detail: string };

// Filesystem seams, so classification is testable against synthetic trees
// without installing anything.
export interface ChannelProbe {
  sea: boolean;
  /** `process.execPath`, already realpath'd where possible. */
  execPath: string;
  /** Directory the running module was loaded from (non-SEA only). */
  moduleDir: string | undefined;
  exists: (path: string) => boolean;
  /** Package name declared by `<dir>/package.json`, or null. */
  packageName: (dir: string) => string | null;
}

// Walk up from `dir` looking for the CLI's own package.json. Same walk
// `cliVersion` does, but it returns the DIRECTORY — the install root is what
// the channel is derived from.
function findPackageDir(probe: ChannelProbe, dir: string): string | null {
  let current = dir;
  for (let i = 0; i < 8; i++) {
    if (probe.packageName(current) === CLI_PACKAGE) return current;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

// The nearest ancestor carrying a pnpm workspace manifest — the marker of a
// source checkout rather than an installed tree.
function findWorkspaceRoot(probe: ChannelProbe, dir: string): string | null {
  let current = dir;
  for (let i = 0; i < 8; i++) {
    if (probe.exists(join(current, 'pnpm-workspace.yaml'))) return current;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

// Split a path into its segments, so a layout match is on whole directory
// names — a substring test matches `~/my-pnpm-notes/…` and misdirects the
// update to a manager the user does not use.
function segments(path: string): string[] {
  return path.split(sep).filter(Boolean);
}

// Index of the LAST occurrence of a consecutive run of segments, or -1.
function lastRunIndex(parts: string[], run: string[]): number {
  for (let i = parts.length - run.length; i >= 0; i--) {
    if (run.every((name, k) => parts[i + k] === name)) return i;
  }
  return -1;
}

// How many separators a path opens with, carried through as a string rather
// than as a boolean. A path does not always start with one or zero of them: a
// Windows UNC path opens with TWO (`\\server\share\…`), and `segments` drops
// both when it filters the empty parts out. Rebuilding with one produces a
// rooted but drive-LESS path, which Windows resolves against whichever drive is
// current — so `npm install -g --prefix \server\share\…` writes to
// `C:\server\share\…` and leaves the install it was pinned to untouched. That
// is the second-copy failure this module exists to prevent, reached from inside
// it, and it is reachable wherever a profile is redirected to a file server,
// since npm's default global prefix is `%APPDATA%\npm`.
function leadingSeparators(path: string): string {
  let end = 0;
  while (path[end] === sep) end++;
  return path.slice(0, end);
}

function toPath(parts: string[], leading: string): string {
  return leading + parts.join(sep);
}

// pnpm keeps the real files in a content-addressed store and LINKS them into
// place, and this classifier realpaths — so the location it is handed can be
// `<root>/node_modules/.pnpm/<pkg>@<ver>/node_modules/<scope>/<name>` rather
// than the linked path anyone would recognise. That matters because the store
// path is not an install location any package manager accepts: matched as an
// ordinary `node_modules` layout it yields a prefix inside pnpm's cache, and
// `npm install -g --prefix <that>` writes there instead of over the install.
// Collapsing it back to the linked location is what makes the rules below —
// which are written against linked layouts — see the same path a user would.
// Both destinations then classify correctly: a pnpm GLOBAL collapses to
// `<pnpmHome>/global/<n>/node_modules/…`, and a project dependency to
// `<project>/node_modules/…`, which is a dev tree rather than an install.
// The two destinations put the store at different depths — a project's is
// under its `node_modules`, a global's directly under `<pnpmHome>/global/<n>` —
// so the linked path is rebuilt rather than sliced: everything above the store,
// then a `node_modules` (unless one is already the segment above it), then the
// package's own scope/name from below the store's inner `node_modules`.
function collapseVirtualStore(parts: string[]): string[] {
  const store = parts.lastIndexOf('.pnpm');
  if (store < 1) return parts;
  const inner = parts.indexOf('node_modules', store + 1);
  if (inner < 0) return parts;
  const above = parts.slice(0, store);
  const nodeModules = above[above.length - 1] === 'node_modules' ? [] : ['node_modules'];
  return [...above, ...nodeModules, ...parts.slice(inner + 1)];
}

// Homebrew's Cellar is always the segment directly below a brew PREFIX, and
// those are a closed set: /opt/homebrew (Apple silicon), /usr/local (Intel),
// and Linuxbrew's /home/linuxbrew/.linuxbrew or a per-user .linuxbrew. The
// anchor matters because `Cellar` is an ordinary word — matching the segment
// wherever it appears sends anyone with a directory of that name to
// `brew upgrade aka`, which upgrades a keg that does not hold their install,
// instead of to the package manager that really owns it.
const BREW_PREFIX_SEGMENTS = new Set(['homebrew', 'local', 'linuxbrew', '.linuxbrew']);

// The keg a path sits in — the segment directly below an anchored `Cellar` — or
// null when no anchored Cellar is above it. The keg NAME is what separates a
// binary brew laid down from one that merely lives inside some other keg's
// tree, so the answer is the name rather than a boolean.
function brewKeg(parts: string[]): string | null {
  for (let i = parts.length - 2; i >= 1; i--) {
    if (parts[i] === 'Cellar' && BREW_PREFIX_SEGMENTS.has(parts[i - 1] ?? '')) {
      return parts[i + 1] ?? null;
    }
  }
  return null;
}

// Scoop lays an app down at `<root>/apps/<app>/<version>/`, points a `current`
// junction at the version in use, and writes the launcher a user runs into
// `<root>/shims`. That launcher targets the junction, so `current` is the
// location a shim-started process reports — the primary shape here, not a
// fallback.
//
// The `apps`/`aka` run on its own is not evidence of Scoop: the standalone
// installer produces a byte-identical layout when pointed at that directory,
// and telling that user to run a package manager they do not have names a
// command that cannot run. The sibling `shims` directory is what separates the
// two — every Scoop root carries one, and an installer root has no reason to.
function isScoopApp(probe: ChannelProbe, parts: string[], leading: string): boolean {
  const at = lastRunIndex(parts, ['apps', 'aka']);
  // `apps`, `aka`, a version or `current`, then at least the executable.
  if (at < 1 || parts.length < at + 4) return false;
  return probe.exists(join(toPath(parts.slice(0, at), leading), 'shims'));
}

// Which manager owns a project's node_modules, read off the lockfile it
// committed. Only used to phrase advice — nothing here runs it — so an
// unrecognised project falls back to npm rather than refusing to answer.
const PROJECT_LOCKFILES: readonly (readonly [string, InstallManager])[] = [
  ['pnpm-lock.yaml', 'pnpm'],
  ['yarn.lock', 'yarn'],
  ['bun.lock', 'bun'],
  ['bun.lockb', 'bun'],
  ['package-lock.json', 'npm'],
];

function projectManager(probe: ChannelProbe, root: string): InstallManager {
  for (const [file, manager] of PROJECT_LOCKFILES) {
    if (probe.exists(join(root, file))) return manager;
  }
  return 'npm';
}

// `yarn`, `Yarn` and `.yarn` are the same vendor directory: yarn v1 capitalises
// it on Windows and hides it on POSIX.
function isYarnSegment(segment: string): boolean {
  return segment.toLowerCase().replace(/^\./, '') === 'yarn';
}

// The standalone installer lays a binary down at
// `<installRoot>/<version>/aka-<triple>/aka`; anything else is a copy someone
// placed by hand, which we can describe but not locate an install root for.
// Only asked of a binary no package manager owns: a brew keg and a Scoop app
// both end in that same `aka-<triple>/aka` shape, so asking this of one of them
// yields a root the installer does not own — and then prints it.
function seaInstallRoot(execPath: string): string | null {
  const parts = segments(execPath);
  const triple = parts[parts.length - 2];
  if (parts.length < 4 || !triple?.startsWith('aka-')) return null;
  return toPath(parts.slice(0, parts.length - 3), leadingSeparators(execPath));
}

/**
 * Classify an install from its own location. Pure: every filesystem read goes
 * through `probe`.
 */
export function classifyInstall(probe: ChannelProbe): InstallChannel {
  if (probe.sea) {
    const parts = segments(probe.execPath);
    const leading = leadingSeparators(probe.execPath);
    const managedBy =
      brewKeg(parts) === 'aka'
        ? SEA_OWNER.Homebrew
        : isScoopApp(probe, parts, leading)
          ? SEA_OWNER.Scoop
          : SEA_OWNER.Standalone;
    return {
      kind: 'sea',
      execPath: probe.execPath,
      managedBy,
      installRoot: managedBy === SEA_OWNER.Standalone ? seaInstallRoot(probe.execPath) : null,
    };
  }
  if (probe.moduleDir === undefined) {
    return { kind: 'unknown', detail: 'the running module has no resolvable path' };
  }
  const packageDir = findPackageDir(probe, probe.moduleDir);
  if (packageDir === null) {
    // No CLI package.json above us. In the published bundle that cannot
    // happen (every @akasecurity/* package is inlined INTO the CLI), so the
    // reachable case is a workspace checkout running a package's own source —
    // which is a dev tree, not an install to be replaced.
    const workspace = findWorkspaceRoot(probe, probe.moduleDir);
    if (workspace !== null) return { kind: 'dev', packageDir: workspace };
    return { kind: 'unknown', detail: `no ${CLI_PACKAGE} package.json above ${probe.moduleDir}` };
  }

  const parts = collapseVirtualStore(segments(packageDir));
  const leading = leadingSeparators(packageDir);

  // Homebrew owns its Cellar outright — an npm/pnpm write into it is fought
  // by the next `brew upgrade`, so brew is named even though the tree below
  // Cellar is an ordinary node_modules layout.
  if (brewKeg(parts) !== null) {
    return { kind: 'homebrew', packageDir };
  }

  // bun: <BUN_INSTALL>/install/global/node_modules/@akasecurity/cli
  const bun = lastRunIndex(parts, ['install', 'global', 'node_modules']);
  if (bun >= 0) {
    return {
      kind: 'global',
      manager: 'bun',
      root: toPath(parts.slice(0, bun + 2), leading),
      packageDir,
    };
  }

  // pnpm: <pnpmHome>/global/<n>/node_modules/@akasecurity/cli. `--global-dir`
  // takes the directory ABOVE the numbered store version.
  const pnpm = lastRunIndex(parts, ['global']);
  if (pnpm >= 0 && parts[pnpm + 2] === 'node_modules' && /^\d+$/.test(parts[pnpm + 1] ?? '')) {
    return {
      kind: 'global',
      manager: 'pnpm',
      root: toPath(parts.slice(0, pnpm + 1), leading),
      packageDir,
    };
  }

  // yarn (v1): `~/.config/yarn/global/node_modules/@akasecurity/cli` on POSIX,
  // but `%LOCALAPPDATA%\Yarn\Data\global\node_modules\…` on Windows — the
  // vendor segment is capitalised there AND separated from `global` by a `Data`
  // segment, so neither the case nor the adjacency holds across platforms. The
  // `global`/`node_modules` pair is what is stable; the vendor is looked for in
  // the two segments above it. Missing this does not degrade to vague advice:
  // yarn writes its own package.json into that directory, so the layout falls
  // through to the npm rule below and reads as a source checkout.
  const yarn = lastRunIndex(parts, ['global', 'node_modules']);
  if (yarn >= 1 && parts.slice(Math.max(0, yarn - 2), yarn).some(isYarnSegment)) {
    return {
      kind: 'global',
      manager: 'yarn',
      root: toPath(parts.slice(0, yarn + 1), leading),
      packageDir,
    };
  }

  // npm: <prefix>/lib/node_modules/@akasecurity/cli (POSIX) or
  // <prefix>/node_modules/@akasecurity/cli (Windows). The prefix is what
  // pins the update to THIS node/nvm version rather than whichever npm the
  // shell resolves.
  const npmPosix = lastRunIndex(parts, ['lib', 'node_modules']);
  if (npmPosix >= 0) {
    return {
      kind: 'global',
      manager: 'npm',
      root: toPath(parts.slice(0, npmPosix), leading),
      packageDir,
    };
  }
  const npmWin = lastRunIndex(parts, ['node_modules']);
  if (npmWin >= 0) {
    // A checkout's own node_modules is a dev link, not a global install.
    // This branch is also where a global layout NONE of the rules above match
    // would land, and it would read as a checkout rather than as unknown —
    // pnpm, yarn and bun each write a package.json into their global dir, so
    // the marker below cannot separate the two. Every manager this module
    // knows is matched above in both its POSIX and its Windows form, which is
    // what keeps the case hypothetical; a new manager needs its own rule
    // there rather than a wider net here.
    const prefix = toPath(parts.slice(0, npmWin), leading);
    // A package.json beside the node_modules means a PROJECT owns this copy,
    // and the two things that can be are told apart by the workspace manifest:
    // a checkout linking its own source is a dev tree, anything else is an
    // ordinary dependency — which is what `npx aka` runs. Calling that a
    // source checkout was the one layout whose advice was confidently wrong
    // rather than merely vague: it printed `git pull`, which updates nothing.
    if (probe.exists(join(prefix, 'package.json'))) {
      if (probe.exists(join(prefix, 'pnpm-workspace.yaml'))) return { kind: 'dev', packageDir };
      return {
        kind: 'project',
        packageDir,
        projectRoot: prefix,
        manager: projectManager(probe, prefix),
      };
    }
    if (probe.exists(join(prefix, 'src'))) return { kind: 'dev', packageDir };
    return { kind: 'global', manager: 'npm', root: prefix, packageDir };
  }

  // No node_modules above us at all: a source checkout being run directly.
  if (probe.exists(join(packageDir, 'src'))) return { kind: 'dev', packageDir };
  return { kind: 'unknown', detail: `unrecognised layout at ${packageDir}` };
}

/**
 * Where a caller says its own copy of the CLI lives. Each app states this for
 * itself; see the note at the top of this file for why it cannot be defaulted.
 */
export interface InstallOrigin {
  /**
   * A directory INSIDE the install to classify — the walk starts here and looks
   * upward for the CLI's package.json. `undefined` is a legitimate answer ("this
   * runtime cannot say"), and classifies as `unknown` rather than guessing.
   */
  moduleDir: string | undefined;
}

/**
 * Classify the install the given origin points into. The origin is required:
 * a wrong-but-plausible default is the one failure mode this module exists to
 * avoid, and it cannot be detected from inside here.
 */
export function detectInstallChannel(origin: InstallOrigin): InstallChannel {
  return classifyInstall(liveProbe(origin));
}

function realpathOr(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

function liveProbe(origin: InstallOrigin): ChannelProbe {
  return {
    sea: isSea(),
    execPath: realpathOr(process.execPath),
    moduleDir: origin.moduleDir === undefined ? undefined : realpathOr(origin.moduleDir),
    exists: existsSync,
    packageName: readPackageName,
  };
}

function readPackageName(dir: string): string | null {
  const p = join(dir, 'package.json');
  if (!existsSync(p)) return null;
  try {
    const raw: unknown = JSON.parse(readFileSync(p, 'utf8'));
    return isRecord(raw) && typeof raw.name === 'string' ? raw.name : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Turning a channel into an update action.
// ---------------------------------------------------------------------------

export interface UpdatePlan {
  /** A command this process may run itself, or null when only advice applies. */
  command: { bin: string; args: string[] } | null;
  /** What the user would type — printed whether or not we run it. */
  display: string;
  /** Why we will not run it, when `command` is null. */
  reason?: string;
}

const INSTALLER_SH =
  'curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.sh | sh';
const INSTALLER_PS1 =
  'irm https://raw.githubusercontent.com/akasecurity/ai-tc/bin-latest/tools/installer/install.ps1 | iex';

// The line each owner of the standalone binary is updated with, as a table over
// the vocabulary rather than a nested switch: annotated `Record<SeaOwner, …>`,
// so a member added to `SEA_OWNER` fails to compile here instead of falling
// through to the installer one-liner — which would tell a user whose package
// manager owns the files to unpack a second copy beside them.
//
// The reason carries no channel note. That sentence is about the REQUEST rather
// than the owner, so the caller appends it and every owner keeps one shape.
const SEA_UPDATE: Record<
  SeaOwner,
  (platform: NodeJS.Platform) => { display: string; reason: string }
> = {
  [SEA_OWNER.Homebrew]: () => ({
    display: 'brew upgrade aka',
    reason:
      'this standalone binary is managed by Homebrew — brew owns the files under ' +
      'Cellar, and re-running the installer would leave a second copy beside them',
  }),
  [SEA_OWNER.Scoop]: () => ({
    display: 'scoop update aka',
    reason:
      'this standalone binary is managed by Scoop — scoop owns the files under its ' +
      'apps directory, and re-running the installer would leave a second copy beside them',
  }),
  [SEA_OWNER.Standalone]: (platform) => ({
    display: platform === 'win32' ? INSTALLER_PS1 : INSTALLER_SH,
    reason:
      'this is the standalone binary — it embeds its own runtime and has no npm ' +
      'package behind it, so re-run the installer to replace it',
  }),
};

// Each manager's own global-install form, pinned to the store the running copy
// was found in wherever the manager accepts a location flag. yarn and bun take
// none, so those two rely on the manager resolving the same global dir it
// installed into — which it does unless the user moved it since.
//
// `command` and `display` are the same argv with different audiences, and the
// difference is quoting: argv reaches the manager as a vector, so a space in
// the root is nothing to it, while `display` is one line for a human to paste
// into a shell that splits on exactly that. Unquoted, an npm prefix of
// `C:\Program Files\nodejs` reads `--prefix C:\Program` and turns the rest of
// the path into a package spec.
function planGlobalUpdate(
  manager: InstallManager,
  root: string,
  spec: string,
  platform: NodeJS.Platform,
): UpdatePlan {
  const argsFor: Record<InstallManager, string[]> = {
    npm: ['install', '-g', '--prefix', root, spec],
    pnpm: ['add', '-g', '--global-dir', root, spec],
    yarn: ['global', 'add', spec],
    bun: ['add', '-g', spec],
  };
  const args = argsFor[manager];
  const display = [manager, ...args.map((arg) => quoteForDisplay(arg, platform))].join(' ');
  return { command: { bin: manager, args }, display };
}

// The sentence a plan appends when a non-stable release channel was asked for
// and this install kind has no way to follow one. Printing the stable command
// with no note would answer a request to switch channels by silently doing
// something else.
function cannotFollowChannel(releaseChannel: ReleaseChannel): string {
  return `; it cannot follow the ${releaseChannel} channel, so there is nothing here to switch`;
}

/** What a plan installs when no report has resolved a version for it. */
const STABLE_TARGET: CliUpdateTarget = { channel: RELEASE_CHANNEL.Stable, version: null };

/**
 * The npm spec an update installs.
 *
 * The RESOLVED VERSION wherever a report resolved one, so the version a surface
 * PRINTS is the version npm FETCHES. A dist-tag spec cannot carry that promise:
 * `beta` goes on serving 0.11.0-beta.3 after 0.11.0 ships, so a beta machine
 * offered the stable re-installed the prerelease, reported success, and was
 * offered the same update on every run afterwards.
 *
 * SECURITY: a resolved version is REGISTRY-SUPPLIED TEXT, and this string
 * becomes a child process's argv — which `exec.ts` hands to cmd.exe on Windows,
 * where Node concatenates argv without escaping it. So it crosses only through
 * `isExactSemver`: anchored, untrimmed, over an alphabet carrying no shell
 * metacharacter, no whitespace and no leading dash. Anything else is treated as
 * UNRESOLVED and falls back to the tag, which comes from the DIST_TAG table
 * keyed on a member of a closed union — so on every path the spec is built from
 * this repo's own text plus a value that has passed that check.
 *
 * The tag is also why the fallback cannot be spelled with the channel token: a
 * user types `stable` and the registry serves `latest`, so a spec built from
 * the typed token asks npm for a tag nothing publishes.
 */
function cliInstallSpec(target: CliUpdateTarget): string {
  const { channel, version } = target;
  const resolved = version !== null && isExactSemver(version) ? version : DIST_TAG[channel];
  return `${CLI_PACKAGE}@${resolved}`;
}

/**
 * The update action for a channel. Every runnable plan is pinned to the
 * location the running CLI was found in, so it can only ever replace THIS
 * install — never create a second one somewhere else on PATH.
 *
 * `target` carries both the published line to follow and the version a report
 * already resolved on it, as one value rather than two parameters: the row a
 * surface shows, the line it prints and the spec it runs all read the same
 * field, and a plan given only the channel installed whatever that channel's
 * tag happened to serve. See `cliInstallSpec` for what reaches the spec.
 */
export function planCliUpdate(
  channel: InstallChannel,
  platform: NodeJS.Platform = process.platform,
  target: CliUpdateTarget = STABLE_TARGET,
): UpdatePlan {
  const spec = cliInstallSpec(target);
  const releaseChannel = target.channel;
  const channelNote =
    releaseChannel === RELEASE_CHANNEL.Stable ? '' : cannotFollowChannel(releaseChannel);
  switch (channel.kind) {
    case 'global':
      return planGlobalUpdate(channel.manager, channel.root, spec, platform);
    case 'homebrew':
      return {
        command: null,
        display: 'brew upgrade aka',
        reason: `this copy is managed by Homebrew — brew owns the files under Cellar${channelNote}`,
      };
    case 'sea': {
      const advice = SEA_UPDATE[channel.managedBy](platform);
      return { command: null, display: advice.display, reason: `${advice.reason}${channelNote}` };
    }
    case 'dev':
      return {
        command: null,
        display: 'git pull',
        reason: `running from a source checkout at ${channel.packageDir} — nothing to install`,
      };
    case 'project': {
      // Advice rather than a runnable plan, deliberately. Bumping a dependency
      // rewrites the project's own manifest and lockfile, which is the user's
      // repository — a different thing from replacing a tool they installed,
      // and not something to do behind a confirmation about updating `aka`.
      const add = channel.manager === 'npm' ? 'install' : 'add';
      return {
        command: null,
        display: `${channel.manager} ${add} ${spec}`,
        reason:
          `this copy is a dependency of the project at ${channel.projectRoot}, not a global ` +
          `install — update it there, in that project`,
      };
    }
    case 'unknown':
      return {
        command: null,
        display: `npm install -g ${spec}`,
        reason: `could not tell how this copy of aka was installed (${channel.detail})`,
      };
  }
}

// The standalone binary's own line, which names the owner because the update
// command differs by owner and this preamble is what precedes it. A switch
// rather than a table, since only one arm has an install root to report; its
// own function with a `string` return so the exhaustiveness is the compiler's —
// with no `default`, a member added to `SEA_OWNER` leaves a path returning
// nothing and fails to build here.
function describeSea(channel: Extract<InstallChannel, { kind: 'sea' }>): string {
  switch (channel.managedBy) {
    case SEA_OWNER.Homebrew:
      return `Homebrew-managed standalone binary at ${channel.execPath}`;
    case SEA_OWNER.Scoop:
      return `Scoop-managed standalone binary at ${channel.execPath}`;
    case SEA_OWNER.Standalone:
      return channel.installRoot === null
        ? `standalone binary at ${channel.execPath}`
        : `standalone binary at ${channel.execPath} (installer root ${channel.installRoot})`;
  }
}

/** One-line description of the channel, for `aka update`'s preamble. */
export function describeChannel(channel: InstallChannel): string {
  switch (channel.kind) {
    case 'global':
      return `${channel.manager} global install at ${channel.root}`;
    case 'homebrew':
      return `Homebrew install at ${channel.packageDir}`;
    case 'sea':
      return describeSea(channel);
    case 'dev':
      return `source checkout at ${channel.packageDir}`;
    case 'project':
      return `${channel.manager} project dependency of ${channel.projectRoot}`;
    case 'unknown':
      return `unrecognised install (${channel.detail})`;
  }
}
