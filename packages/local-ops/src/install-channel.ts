import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';

import { quoteForDisplay } from './exec.ts';
import { isSea } from './self-exec.ts';
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

export type InstallChannel =
  /** The self-contained binary from tools/installer (or a hand-placed copy). */
  | { kind: 'sea'; execPath: string; installRoot: string | null }
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
// `brew upgrade aka`, a formula that does not exist, instead of to the
// package manager that really owns their install.
const BREW_PREFIX_SEGMENTS = new Set(['homebrew', 'local', 'linuxbrew', '.linuxbrew']);

function isHomebrewCellar(parts: string[]): boolean {
  return parts.some(
    (segment, i) => segment === 'Cellar' && i >= 1 && BREW_PREFIX_SEGMENTS.has(parts[i - 1] ?? ''),
  );
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

// The installer lays a binary down at
// `<installRoot>/<version>/aka-<triple>/aka`; anything else is a copy someone
// placed by hand, which we can describe but not locate an install root for.
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
    return { kind: 'sea', execPath: probe.execPath, installRoot: seaInstallRoot(probe.execPath) };
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
  if (isHomebrewCellar(parts)) {
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

/**
 * The update action for a channel. Every runnable plan is pinned to the
 * location the running CLI was found in, so it can only ever replace THIS
 * install — never create a second one somewhere else on PATH.
 */
export function planCliUpdate(
  channel: InstallChannel,
  platform: NodeJS.Platform = process.platform,
): UpdatePlan {
  const spec = `${CLI_PACKAGE}@latest`;
  switch (channel.kind) {
    case 'global':
      return planGlobalUpdate(channel.manager, channel.root, spec, platform);
    case 'homebrew':
      return {
        command: null,
        display: 'brew upgrade aka',
        reason: 'this copy is managed by Homebrew — brew owns the files under Cellar',
      };
    case 'sea':
      return {
        command: null,
        display: platform === 'win32' ? INSTALLER_PS1 : INSTALLER_SH,
        reason:
          'this is the standalone binary — it embeds its own runtime and has no npm ' +
          'package behind it, so re-run the installer to replace it',
      };
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

/** One-line description of the channel, for `aka update`'s preamble. */
export function describeChannel(channel: InstallChannel): string {
  switch (channel.kind) {
    case 'global':
      return `${channel.manager} global install at ${channel.root}`;
    case 'homebrew':
      return `Homebrew install at ${channel.packageDir}`;
    case 'sea':
      return channel.installRoot === null
        ? `standalone binary at ${channel.execPath}`
        : `standalone binary at ${channel.execPath} (installer root ${channel.installRoot})`;
    case 'dev':
      return `source checkout at ${channel.packageDir}`;
    case 'project':
      return `${channel.manager} project dependency of ${channel.projectRoot}`;
    case 'unknown':
      return `unrecognised install (${channel.detail})`;
  }
}
