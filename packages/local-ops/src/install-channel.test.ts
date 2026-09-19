import { readFileSync } from 'node:fs';
import { sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { CliUpdateTarget, ReleaseChannel } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { ChannelProbe, InstallChannel, SeaOwner } from './install-channel.ts';
import {
  classifyInstall,
  describeChannel,
  detectInstallChannel,
  planCliUpdate,
  SEA_OWNER,
} from './install-channel.ts';
import { CLI_PACKAGE } from './updates.ts';

// Every fixture path is written POSIX-style and translated to the host
// separator, so the same cases run on Windows CI rather than being skipped
// there — the layouts they describe are what npm/pnpm/bun really lay down.
function p(posix: string): string {
  return posix.split('/').join(sep);
}

// Every owner in the vocabulary, read off the registry rather than retyped, so
// a case that must hold for all of them grows a row when a member is added
// instead of going on covering the old set under a name that reads complete.
const SEA_OWNERS: SeaOwner[] = Object.values(SEA_OWNER);

// A label for a case driven over several channels. The kind alone stops
// separating them once three rows share `sea`, and a failure that cannot say
// which owner produced it is a failure someone has to re-derive by hand.
function channelLabel(channel: InstallChannel): string {
  return channel.kind === 'sea' ? `sea/${channel.managedBy}` : channel.kind;
}

interface ProbeOptions {
  sea?: boolean;
  execPath?: string;
  moduleDir?: string | undefined;
  /** Directories that exist, beyond the package dir itself. */
  dirs?: string[];
  /** Directory → package.json `name`. */
  packages?: Record<string, string>;
}

function probe(options: ProbeOptions): ChannelProbe {
  const dirs = new Set((options.dirs ?? []).map(p));
  const packages = new Map(
    Object.entries(options.packages ?? {}).map(([dir, name]) => [p(dir), name]),
  );
  return {
    sea: options.sea ?? false,
    execPath: p(options.execPath ?? '/usr/local/bin/node'),
    moduleDir: options.moduleDir === undefined ? undefined : p(options.moduleDir),
    // A declared package implies its own package.json exists — the classifier
    // probes for that file to tell a project checkout from a global prefix.
    exists: (path) =>
      dirs.has(path) ||
      packages.has(path) ||
      [...packages.keys()].some((dir) => path === `${dir}${sep}package.json`),
    packageName: (dir) => packages.get(dir) ?? null,
  };
}

// A global install of the CLI whose package.json sits at `packageDir`, with the
// running module one level down in its bundled dist/.
function globalProbe(packageDir: string, extra?: ProbeOptions): ChannelProbe {
  return probe({
    moduleDir: `${packageDir}/dist`,
    packages: { [packageDir]: CLI_PACKAGE },
    ...extra,
  });
}

describe('classifyInstall', () => {
  it('pins an npm global to its own prefix, not to whatever npm is on PATH', () => {
    const channel = classifyInstall(
      globalProbe('/Users/x/.nvm/versions/node/v24.4.0/lib/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({
      kind: 'global',
      manager: 'npm',
      root: p('/Users/x/.nvm/versions/node/v24.4.0'),
    });
  });

  it('distinguishes two nvm versions by the prefix they resolve to', () => {
    const a = classifyInstall(
      globalProbe('/Users/x/.nvm/versions/node/v22.1.0/lib/node_modules/@akasecurity/cli'),
    );
    const b = classifyInstall(
      globalProbe('/Users/x/.nvm/versions/node/v24.4.0/lib/node_modules/@akasecurity/cli'),
    );
    expect(a).not.toStrictEqual(b);
    expect(planCliUpdate(a).display).not.toBe(planCliUpdate(b).display);
  });

  it('recognises a pnpm global store and its --global-dir root', () => {
    const channel = classifyInstall(
      globalProbe('/Users/x/Library/pnpm/global/5/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({
      kind: 'global',
      manager: 'pnpm',
      root: p('/Users/x/Library/pnpm/global'),
    });
  });

  it('recognises a bun global install', () => {
    const channel = classifyInstall(
      globalProbe('/Users/x/.bun/install/global/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({ kind: 'global', manager: 'bun' });
  });

  it('recognises a yarn v1 global install', () => {
    const channel = classifyInstall(
      globalProbe('/Users/x/.config/yarn/global/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({
      kind: 'global',
      manager: 'yarn',
      root: p('/Users/x/.config/yarn/global'),
    });
  });

  it('recognises the WINDOWS yarn global folder, which is spelled differently', () => {
    // `%LOCALAPPDATA%\Yarn\Data\global` — the vendor segment is capitalised
    // and a `Data` segment sits between it and `global`, so a rule written
    // against the POSIX form (`yarn/global/node_modules`, consecutive and
    // lower-case) misses it entirely. What made that worth a test rather than a
    // shrug is where the miss LANDS: `yarn global` keeps its own package.json
    // in that directory, so the fallthrough reads it as a project checkout and
    // `aka update` tells a yarn user to run `git pull`.
    const channel = classifyInstall(
      globalProbe('/Users/u/AppData/Local/Yarn/Data/global/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({
      kind: 'global',
      manager: 'yarn',
      root: p('/Users/u/AppData/Local/Yarn/Data/global'),
    });
  });

  it('does not read a bare `global/node_modules` as yarn', () => {
    // The vendor segment is the whole of the evidence — without it this is an
    // ordinary npm prefix that happens to have a `global` directory in it.
    const channel = classifyInstall(
      globalProbe('/Users/x/tools/global/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({ kind: 'global', manager: 'npm' });
  });

  it('names Homebrew rather than writing into a tree brew owns', () => {
    const channel = classifyInstall(
      globalProbe('/opt/homebrew/Cellar/node/24.4.0/lib/node_modules/@akasecurity/cli'),
    );
    expect(channel.kind).toBe('homebrew');
    expect(planCliUpdate(channel).command).toBeNull();
  });

  it('recognises the other prefixes brew installs under', () => {
    for (const prefix of ['/usr/local', '/home/linuxbrew/.linuxbrew']) {
      const channel = classifyInstall(
        globalProbe(`${prefix}/Cellar/node/24.4.0/lib/node_modules/@akasecurity/cli`),
      );
      expect(channel.kind, prefix).toBe('homebrew');
    }
  });

  it('carries a UNC path\u2019s leading separators through the round trip', () => {
    // `segments` drops every empty part and the rebuild used to re-prepend a
    // single separator, so a Windows UNC install (`\\\\server\\share\\\u2026`, which a
    // redirected profile really produces \u2014 npm's default prefix is
    // `%APPDATA%\\npm`) came back one separator short. That path is rooted but
    // drive-LESS, so Windows resolves it against the current drive: the update
    // lands on C: and the install it was pinned to is untouched, which is the
    // second-copy failure this module exists to prevent.
    //
    // Written with the host separator like every other fixture here, so on the
    // Windows leg this IS a UNC path and on POSIX it is the same round-trip
    // property over a doubled separator.
    const channel = classifyInstall(
      globalProbe('//fileserver/profiles/u/AppData/Roaming/npm/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({
      kind: 'global',
      manager: 'npm',
      root: p('//fileserver/profiles/u/AppData/Roaming/npm'),
    });
    expect(planCliUpdate(channel).command?.args).toContain(
      p('//fileserver/profiles/u/AppData/Roaming/npm'),
    );
  });

  it('leaves an ordinary rooted path with exactly the separators it had', () => {
    // The control for the case above: preserving a RUN of separators must not
    // start adding one to a path that opens with a single separator, nor to a
    // Windows drive-letter path, which opens with none.
    expect(
      classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli')),
    ).toMatchObject({ root: p('/opt/node') });
    expect(
      classifyInstall(
        probe({ sea: true, execPath: '//fileserver/opt/aka/0.9.3/aka-win32-x64/aka' }),
      ),
    ).toMatchObject({ installRoot: p('//fileserver/opt/aka') });
  });

  it('does not read a directory merely NAMED Cellar as a Homebrew tree', () => {
    // `Cellar` is an ordinary word, and this was the one rule here matching a
    // bare segment anywhere in the path rather than a layout. A user with a
    // directory of that name was told to run `brew upgrade aka` — which
    // upgrades a keg that does not hold their install — instead of being
    // pointed at the manager that really owns it.
    const channel = classifyInstall(
      globalProbe('/Users/x/Cellar/tools/lib/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({ kind: 'global', manager: 'npm' });
  });

  it('reports the standalone binary, with the installer root it was laid down in', () => {
    const channel = classifyInstall(
      probe({
        sea: true,
        execPath: '/Users/x/.local/share/aka/0.9.3/aka-darwin-arm64/aka',
      }),
    );
    expect(channel).toStrictEqual<InstallChannel>({
      kind: 'sea',
      execPath: p('/Users/x/.local/share/aka/0.9.3/aka-darwin-arm64/aka'),
      managedBy: SEA_OWNER.Standalone,
      installRoot: p('/Users/x/.local/share/aka'),
    });
  });

  it('still reports sea for a hand-placed binary, with no install root', () => {
    const channel = classifyInstall(probe({ sea: true, execPath: '/usr/local/bin/aka' }));
    // `managedBy` is asserted here and not only on the case above: an owner rule
    // that answered unconditionally would set `installRoot` to null on this
    // path anyway, so the two keys it used to name were both unmoved by it.
    expect(channel).toMatchObject({
      kind: 'sea',
      managedBy: SEA_OWNER.Standalone,
      installRoot: null,
    });
  });

  it('a SEA never falls through to a package-manager plan', () => {
    // The defect this replaced: a binary install ran `npm install -g`, which
    // succeeded and changed nothing the user runs.
    const plan = planCliUpdate(
      classifyInstall(probe({ sea: true, execPath: '/usr/local/bin/aka' })),
    );
    expect(plan.command).toBeNull();
    expect(plan.display).not.toContain('npm');
  });

  // The binary ships through three routes and the bytes are the same on all of
  // them, so nothing in the file itself says who replaces it. Location is the
  // only evidence, and getting it wrong is not a vague answer: it names a
  // command that either cannot run or unpacks a second copy beside the one a
  // package manager owns.
  describe('who owns the standalone binary', () => {
    // Every prefix brew installs under, so the anchor is exercised as the set it
    // is rather than through whichever one the developer happens to have.
    const BREW_PREFIXES = [
      '/opt/homebrew',
      '/usr/local',
      '/home/linuxbrew/.linuxbrew',
      '/home/u/.linuxbrew',
    ];

    // The formula unpacks the archive into `libexec` and symlinks the launcher,
    // so the binary keeps its sidecars and the path ends in the same
    // `aka-<triple>/aka` shape the standalone installer produces.
    function brewExec(prefix: string): string {
      return `${prefix}/Cellar/aka/0.9.13/libexec/aka-darwin-arm64/aka`;
    }

    it('names Homebrew for a binary inside an aka keg, under every brew prefix', () => {
      for (const prefix of BREW_PREFIXES) {
        const channel = classifyInstall(probe({ sea: true, execPath: brewExec(prefix) }));
        expect(channel, prefix).toMatchObject({
          kind: 'sea',
          managedBy: SEA_OWNER.Homebrew,
        });
        expect(planCliUpdate(channel, 'darwin').display, prefix).toBe('brew upgrade aka');
      }
    });

    it('leaves a binary in someone ELSE\u2019s keg to the installer', () => {
      // A keg is only evidence when it is the `aka` keg. Anything else is a tree
      // brew owns for another formula, and a binary sitting inside one got there
      // some other way — `brew upgrade aka` would name a keg that is not it.
      // Two of the kegs carry `aka` inside their own name, so a prefix, suffix
      // or substring match on the keg is refused as well as a match on any keg.
      for (const keg of ['node', 'akamai', 'kaka']) {
        const channel = classifyInstall(
          probe({ sea: true, execPath: `/opt/homebrew/Cellar/${keg}/24.4.0/libexec/aka` }),
        );
        expect(channel, keg).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
        expect(planCliUpdate(channel, 'darwin').display, keg).toContain('install.sh');
      }
    });

    // The three places a Scoop install can be read from. `current` leads because
    // it is the normal route: the shim a user's PATH resolves targets that
    // junction, so it is what a shim-started process reports.
    const SCOOP_TAILS = ['current/aka.exe', '0.9.13/aka.exe', '0.9.13/aka-win32-x64/aka.exe'];
    const SCOOP_ROOT = 'C:/Users/u/scoop';
    // A drive-letter root opens with no separator, so on its own it never
    // exercises the leading separator the shims path is rebuilt with. The rooted
    // form does, on both hosts.
    const SCOOP_ROOTS = [SCOOP_ROOT, '/Users/u/scoop'];

    it('names Scoop for an apps/aka layout with a shims sibling', () => {
      for (const root of SCOOP_ROOTS) {
        for (const tail of SCOOP_TAILS) {
          const channel = classifyInstall(
            probe({
              sea: true,
              execPath: `${root}/apps/aka/${tail}`,
              dirs: [`${root}/shims`],
            }),
          );
          const label = `${root} ${tail}`;
          expect(channel, label).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Scoop });
          expect(planCliUpdate(channel, 'win32').display, label).toBe('scoop update aka');
        }
      }
    });

    it('leaves the same layout to the installer when no shims sibling is there', () => {
      // `install.ps1 --dir <…>\apps\aka` produces a byte-identical path on a
      // machine that has no Scoop at all, so the run alone cannot decide this.
      // Sending that user to `scoop update aka` names a command they cannot run.
      for (const root of SCOOP_ROOTS) {
        for (const tail of SCOOP_TAILS) {
          const channel = classifyInstall(
            probe({ sea: true, execPath: `${root}/apps/aka/${tail}` }),
          );
          const label = `${root} ${tail}`;
          expect(channel, label).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
          expect(planCliUpdate(channel, 'win32').display, label).toContain('install.ps1');
        }
      }
    });

    it('needs a version or `current` directory between apps/aka and the executable', () => {
      // Scoop always interposes one, so an executable sitting directly in
      // `apps/aka` is not a layout it produces, shims sibling or not.
      const channel = classifyInstall(
        probe({
          sea: true,
          execPath: `${SCOOP_ROOT}/apps/aka/aka.exe`,
          dirs: [`${SCOOP_ROOT}/shims`],
        }),
      );
      expect(channel).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
    });

    it('needs that segment to actually BE a version or `current`, not merely present', () => {
      // The length check above passes any word here — this is the layout no
      // version and no `current` can produce, with a `shims` sibling that
      // would otherwise be read as evidence on its own.
      const channel = classifyInstall(
        probe({
          sea: true,
          execPath: `${SCOOP_ROOT}/apps/aka/not-a-version/aka.exe`,
          dirs: [`${SCOOP_ROOT}/shims`],
        }),
      );
      expect(channel).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
    });

    it('reads no Scoop root off a path that carries no apps/aka run at all', () => {
      // With the run absent there is no root to look for `shims` under. A
      // `shims` directory beside the executable itself is ordinary, and must
      // not be mistaken for the one a Scoop root carries.
      const channel = classifyInstall(
        probe({ sea: true, execPath: '/Users/x/tools/aka', dirs: ['/Users/x/tools/shims'] }),
      );
      expect(channel).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
    });

    it('does not read a directory merely NAMED scoop as a Scoop app', () => {
      // The sibling of the Cellar case above: the shims directory is checked
      // against the root the `apps`/`aka` run names, so a shims directory
      // somewhere else is not evidence on its own.
      const channel = classifyInstall(
        probe({
          sea: true,
          execPath: `${SCOOP_ROOT}/0.9.13/aka-win32-x64/aka.exe`,
          dirs: [`${SCOOP_ROOT}/shims`],
        }),
      );
      expect(channel).toMatchObject({ kind: 'sea', managedBy: SEA_OWNER.Standalone });
    });

    it('reports no installer root for a binary a package manager owns', () => {
      // `installRoot` is the standalone installer's own root and means nothing
      // for the other two. Both of these end in `aka-<triple>/<exe>`, which is
      // exactly the shape the installer rule matches — so without the owner gate
      // each would report a root that no installer laid down, and print it.
      const brew = classifyInstall(probe({ sea: true, execPath: brewExec('/opt/homebrew') }));
      expect(brew).toMatchObject({ managedBy: SEA_OWNER.Homebrew, installRoot: null });

      const scoop = classifyInstall(
        probe({
          sea: true,
          execPath: `${SCOOP_ROOT}/apps/aka/0.9.13/aka-win32-x64/aka.exe`,
          dirs: [`${SCOOP_ROOT}/shims`],
        }),
      );
      expect(scoop).toMatchObject({ managedBy: SEA_OWNER.Scoop, installRoot: null });

      // The control, without which both assertions above hold whether or not the
      // gate is there: the SAME trailing shape, owned by nobody, does resolve a
      // root — so `null` is the gate's doing rather than the rule declining.
      const standalone = classifyInstall(
        probe({ sea: true, execPath: '/Users/x/.local/share/aka/0.9.13/aka-win32-x64/aka.exe' }),
      );
      expect(standalone).toMatchObject({
        managedBy: SEA_OWNER.Standalone,
        installRoot: p('/Users/x/.local/share/aka'),
      });
    });

    it('names the owner in the line that precedes the update command', () => {
      // `describeChannel` is the preamble the update command is printed under,
      // so an owner it does not distinguish reads as the installer's binary
      // above a `brew upgrade` the user never asked about.
      const brew = classifyInstall(probe({ sea: true, execPath: brewExec('/opt/homebrew') }));
      expect(describeChannel(brew)).toContain('Homebrew');

      const scoop = classifyInstall(
        probe({
          sea: true,
          execPath: `${SCOOP_ROOT}/apps/aka/current/aka.exe`,
          dirs: [`${SCOOP_ROOT}/shims`],
        }),
      );
      expect(describeChannel(scoop)).toContain('Scoop');

      const standalone = classifyInstall(
        probe({ sea: true, execPath: '/Users/x/.local/share/aka/0.9.3/aka-darwin-arm64/aka' }),
      );
      expect(describeChannel(standalone)).not.toContain('Homebrew');
      expect(describeChannel(standalone)).not.toContain('Scoop');

      // The installer root is reported AFTER the executable. Searched for in the
      // whole line it is satisfied by the executable path alone, which begins
      // with that very root — so only the remainder is evidence the root is shown.
      const standaloneExec = p('/Users/x/.local/share/aka/0.9.3/aka-darwin-arm64/aka');
      const standaloneLine = describeChannel(standalone);
      const execAt = standaloneLine.indexOf(standaloneExec);
      expect(execAt).toBeGreaterThanOrEqual(0);
      expect(standaloneLine.slice(execAt + standaloneExec.length)).toContain(
        p('/Users/x/.local/share/aka'),
      );

      // Three owners, three distinct lines: a switch arm that fell through to a
      // neighbour would leave two of them equal.
      const lines = [describeChannel(brew), describeChannel(scoop), describeChannel(standalone)];
      expect(new Set(lines).size).toBe(SEA_OWNERS.length);
    });

    it('enumerates the registry it drives every owner-wide case from', () => {
      // Each case below derives its rows from `SEA_OWNERS`, so an empty registry
      // would leave all of them looping over nothing and reporting green. The
      // count is asserted here, once, rather than re-derived at each of them.
      expect(SEA_OWNERS.length).toBeGreaterThan(1);
      expect(new Set(SEA_OWNERS).size).toBe(SEA_OWNERS.length);
      expect(SEA_OWNERS).toContain(SEA_OWNER.Homebrew);
      expect(SEA_OWNERS).toContain(SEA_OWNER.Scoop);
      expect(SEA_OWNERS).toContain(SEA_OWNER.Standalone);
    });

    it('gives each owner its own update command, and never a package spec', () => {
      const displays = SEA_OWNERS.map(
        (managedBy) =>
          planCliUpdate(
            { kind: 'sea', execPath: '/usr/local/bin/aka', managedBy, installRoot: null },
            'win32',
          ).display,
      );
      expect(displays.length).toBe(SEA_OWNERS.length);
      expect(new Set(displays).size).toBe(SEA_OWNERS.length);
      for (const display of displays) {
        // None of the three has an npm package behind it, so none of them may
        // ever print one — that is the defect the whole `sea` kind exists for.
        expect(display).not.toContain(CLI_PACKAGE);
      }
    });
  });

  it('recognises a source checkout rather than proposing an install', () => {
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/ai-tc/cli/src/commands',
        packages: { '/Users/x/code/ai-tc/cli': CLI_PACKAGE },
        dirs: ['/Users/x/code/ai-tc/cli/src'],
      }),
    );
    expect(channel.kind).toBe('dev');
    expect(planCliUpdate(channel).command).toBeNull();
  });

  it('reads a project-local dependency as the project\u2019s, not as a global install', () => {
    // What `npx aka` runs. Calling this a source checkout was the one layout
    // whose advice was confidently wrong rather than merely vague — it printed
    // `git pull`, which updates nothing, for a copy that is updated by bumping
    // a dependency in the project that declares it.
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/app/node_modules/@akasecurity/cli/dist',
        packages: {
          '/Users/x/code/app/node_modules/@akasecurity/cli': CLI_PACKAGE,
          '/Users/x/code/app': 'my-app',
        },
      }),
    );
    expect(channel).toMatchObject({ kind: 'project', projectRoot: p('/Users/x/code/app') });
    const plan = planCliUpdate(channel);
    expect(plan.command).toBeNull();
    expect(plan.display).not.toBe('git pull');
    expect(plan.reason).toContain(p('/Users/x/code/app'));
  });

  it('names the project\u2019s own manager, read off the lockfile it committed', () => {
    for (const [lockfile, manager] of [
      ['pnpm-lock.yaml', 'pnpm'],
      ['yarn.lock', 'yarn'],
      ['bun.lockb', 'bun'],
      ['package-lock.json', 'npm'],
    ] as const) {
      const channel = classifyInstall(
        probe({
          moduleDir: '/Users/x/code/app/node_modules/@akasecurity/cli/dist',
          packages: {
            '/Users/x/code/app/node_modules/@akasecurity/cli': CLI_PACKAGE,
            '/Users/x/code/app': 'my-app',
          },
          dirs: [`/Users/x/code/app/${lockfile}`],
        }),
      );
      expect(channel, lockfile).toMatchObject({ kind: 'project', manager });
      expect(planCliUpdate(channel).display, lockfile).toContain(manager);
    }
  });

  it('a project with no lockfile is still described, defaulting to npm', () => {
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/app/node_modules/@akasecurity/cli/dist',
        packages: {
          '/Users/x/code/app/node_modules/@akasecurity/cli': CLI_PACKAGE,
          '/Users/x/code/app': 'my-app',
        },
      }),
    );
    expect(channel).toMatchObject({ kind: 'project', manager: 'npm' });
    expect(describeChannel(channel)).toContain('npm');
  });

  it('a workspace checkout linking its own source stays a dev tree', () => {
    // The discriminator between the two things a package.json beside a
    // node_modules can mean. A monorepo's linked copy is its own source, so
    // `git pull` is the right advice there and a dependency bump is not.
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/ai-tc/node_modules/@akasecurity/cli/dist',
        packages: {
          '/Users/x/code/ai-tc/node_modules/@akasecurity/cli': CLI_PACKAGE,
          '/Users/x/code/ai-tc': 'ai-tc',
        },
        dirs: ['/Users/x/code/ai-tc/pnpm-workspace.yaml'],
      }),
    );
    expect(channel).toMatchObject({ kind: 'dev' });
  });

  it('reads a workspace checkout as dev even when the CLI package is not above it', () => {
    // `pnpm --filter cli dev` loads local-ops from its own source, so the walk
    // never meets a @akasecurity/cli package.json.
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/ai-tc/packages/local-ops/src',
        packages: { '/Users/x/code/ai-tc/packages/local-ops': '@akasecurity/local-ops' },
        dirs: ['/Users/x/code/ai-tc/pnpm-workspace.yaml'],
      }),
    );
    expect(channel).toMatchObject({ kind: 'dev', packageDir: p('/Users/x/code/ai-tc') });
  });

  it('fails closed when the layout is unrecognised', () => {
    const channel = classifyInstall(
      probe({ moduleDir: '/opt/weird/aka', packages: { '/opt/weird/aka': CLI_PACKAGE } }),
    );
    expect(channel.kind).toBe('unknown');
    expect(planCliUpdate(channel).command).toBeNull();
    expect(planCliUpdate(channel).reason).toContain('could not tell');
  });

  it('fails closed when the running module has no path at all', () => {
    expect(classifyInstall(probe({ moduleDir: undefined })).kind).toBe('unknown');
  });

  // pnpm links packages out of a content-addressed store and this classifier
  // realpaths, so the path it sees is the STORE path. Matched as an ordinary
  // node_modules layout it produces a "prefix" inside pnpm's cache — and
  // `npm install -g --prefix <cache>` writes there rather than over the install.
  describe('a pnpm virtual-store path collapses to the location it is linked from', () => {
    it('classifies a pnpm GLOBAL by its real global dir, not by the store', () => {
      const channel = classifyInstall(
        globalProbe(
          '/Users/x/Library/pnpm/global/5/.pnpm/@akasecurity+cli@0.9.3/node_modules/@akasecurity/cli',
        ),
      );
      expect(channel).toMatchObject({
        kind: 'global',
        manager: 'pnpm',
        root: p('/Users/x/Library/pnpm/global'),
      });
    });

    it('never aims a package manager at the store directory itself', () => {
      const channel = classifyInstall(
        globalProbe(
          '/Users/x/Library/pnpm/global/5/.pnpm/@akasecurity+cli@0.9.3/node_modules/@akasecurity/cli',
        ),
      );
      const plan = planCliUpdate(channel);
      expect(plan.command?.args.join(' ')).not.toContain('.pnpm');
      expect(plan.display).not.toContain('.pnpm');
    });

    it('reads a project dependency as the project\u2019s, not as a global install', () => {
      const channel = classifyInstall(
        probe({
          moduleDir:
            '/Users/x/proj/node_modules/.pnpm/@akasecurity+cli@0.9.3/node_modules/@akasecurity/cli/dist',
          packages: {
            '/Users/x/proj/node_modules/.pnpm/@akasecurity+cli@0.9.3/node_modules/@akasecurity/cli':
              CLI_PACKAGE,
            '/Users/x/proj': 'my-app',
          },
        }),
      );
      expect(channel).toMatchObject({ kind: 'project', projectRoot: p('/Users/x/proj') });
      expect(planCliUpdate(channel).command).toBeNull();
    });
  });

  it('does not read a directory merely NAMED like a manager store as that manager', () => {
    // A substring match on 'pnpm' or 'global' would misdirect the update here.
    const channel = classifyInstall(
      globalProbe('/Users/x/my-pnpm-globalthing/lib/node_modules/@akasecurity/cli'),
    );
    expect(channel).toMatchObject({ kind: 'global', manager: 'npm' });
  });
});

describe('the origin is the caller’s to state', () => {
  // The defect this guards is invisible to every other test in this file,
  // because they all inject a probe. A default read of `import.meta.url` here
  // is correct under tsup (the CLI) and silently wrong under a Next build,
  // which bakes the BUILD MACHINE's absolute source path into the server chunk
  // as a string literal — so the dashboard would classify the maintainer's disk
  // and report a failure quoting their home directory to every user. The only
  // way to make that unrepresentable is for this module never to reach for the
  // value at all.
  const source = readFileSync(
    fileURLToPath(new URL('./install-channel.ts', import.meta.url)),
    'utf8',
  );

  it('never reads import.meta.url — a bundler-poisoned default cannot exist', () => {
    const code = source
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*'))
      .join('\n');
    expect(code).not.toContain('import.meta');
  });

  it('classifies from the supplied origin, not from where this module sits', () => {
    // A path that exists nowhere: every real filesystem probe misses, so the
    // answer can only have come from the origin we passed.
    const channel = detectInstallChannel({ moduleDir: `${sep}nonexistent-${'x'.repeat(24)}` });
    expect(channel.kind).toBe('unknown');
    expect(planCliUpdate(channel).command).toBeNull();
  });

  it('treats an unstatable origin as unknown rather than guessing', () => {
    expect(detectInstallChannel({ moduleDir: undefined }).kind).toBe('unknown');
  });
});

describe('planCliUpdate', () => {
  it('passes the prefix to npm so a second copy cannot land elsewhere', () => {
    const plan = planCliUpdate(
      classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli')),
    );
    expect(plan.command).toStrictEqual({
      bin: 'npm',
      args: ['install', '-g', '--prefix', p('/opt/node'), `${CLI_PACKAGE}@latest`],
    });
  });

  it('leaves an ordinary root unquoted — only a path that needs it is touched', () => {
    // The control for the two cases below: quoting is by exception, so the
    // line every existing install prints is byte-identical to what it was.
    const plan = planCliUpdate(
      classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli')),
    );
    expect(plan.display).toBe(`npm install -g --prefix ${p('/opt/node')} ${CLI_PACKAGE}@latest`);
  });

  it('quotes a root with a space in the line it prints, but not in the argv it runs', () => {
    // `display` is documented as what the user would type, and both surfaces
    // present it that way — the CLI under `To update it, run:`, the dashboard
    // in a <pre>. Joined raw, an npm prefix of `C:\Program Files\nodejs` reads
    // as `--prefix C:\Program` with the rest of the path as a package spec.
    // argv is a vector and must stay unquoted: the manager receives it whole.
    const posix = planCliUpdate(
      {
        kind: 'global',
        manager: 'npm',
        root: '/opt/My Node/prefix',
        packageDir: '/opt/My Node/prefix/lib/node_modules/@akasecurity/cli',
      },
      'darwin',
    );
    expect(posix.display).toContain(String.raw`'/opt/My Node/prefix'`);
    expect(posix.command?.args).toContain('/opt/My Node/prefix');

    const win = planCliUpdate(
      {
        kind: 'global',
        manager: 'npm',
        root: String.raw`C:\Program Files\nodejs`,
        packageDir: String.raw`C:\Program Files\nodejs\node_modules\@akasecurity\cli`,
      },
      'win32',
    );
    expect(win.display).toContain(String.raw`"C:\Program Files\nodejs"`);
    expect(win.command?.args).toContain(String.raw`C:\Program Files\nodejs`);
  });

  it('offers the platform-appropriate installer for the standalone binary', () => {
    const sea = classifyInstall(probe({ sea: true, execPath: '/usr/local/bin/aka' }));
    expect(planCliUpdate(sea, 'darwin').display).toContain('install.sh');
    expect(planCliUpdate(sea, 'win32').display).toContain('install.ps1');
  });

  it('every non-runnable plan says why and what to run instead', () => {
    const channels: InstallChannel[] = [
      ...SEA_OWNERS.map((managedBy): InstallChannel => ({
        kind: 'sea',
        execPath: '/usr/local/bin/aka',
        managedBy,
        installRoot: null,
      })),
      { kind: 'homebrew', packageDir: '/opt/homebrew/x' },
      { kind: 'dev', packageDir: '/src/cli' },
      { kind: 'project', packageDir: '/p/node_modules/x', projectRoot: '/p', manager: 'pnpm' },
      { kind: 'unknown', detail: 'nowhere' },
    ];
    expect(channels.length).toBeGreaterThan(SEA_OWNERS.length);
    for (const channel of channels) {
      const label = channelLabel(channel);
      const plan = planCliUpdate(channel);
      expect(plan.command, label).toBeNull();
      expect(plan.reason, label).toBeTruthy();
      expect(plan.display.length, label).toBeGreaterThan(0);
      expect(describeChannel(channel).length, label).toBeGreaterThan(0);
    }
  });
});

/**
 * A target carrying a channel and NO resolved version — the offline row, and
 * what every plan built before a report has answered installs.
 *
 * `version: null` is spelled at each of these call sites rather than defaulted,
 * because that is the whole shape of the field: an omitted version is the defect
 * the pairing exists to prevent, so declining has to read as a decision.
 */
function onChannel(channel: ReleaseChannel): CliUpdateTarget {
  return { channel, version: null };
}

/**
 * The release channel a plan installs from, with no version resolved.
 *
 * The spec's tag then comes from the DIST_TAG table and from nowhere else: the
 * token a user types (`stable`) is not the tag the registry serves (`latest`),
 * so a spec built from the typed token asks npm for a tag nothing publishes and
 * the update fails with the registry's own 404.
 */
describe('planCliUpdate — the release channel', () => {
  const globalChannel = classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli'));

  it('defaults to the stable tag, byte-identical to what shipped', () => {
    // The control for every case below: the default must not move, because the
    // line every existing install prints is this one.
    expect(planCliUpdate(globalChannel, 'linux').command?.args).toContain(`${CLI_PACKAGE}@latest`);
    expect(planCliUpdate(globalChannel, 'linux')).toStrictEqual(
      planCliUpdate(globalChannel, 'linux', onChannel(RELEASE_CHANNEL.Stable)),
    );
  });

  it('asks for the tag the requested channel maps to, not the channel token', () => {
    const beta = planCliUpdate(globalChannel, 'linux', onChannel(RELEASE_CHANNEL.Beta));
    expect(beta.command?.args).toContain(`${CLI_PACKAGE}@beta`);
    expect(beta.display).toContain(`${CLI_PACKAGE}@beta`);

    const stable = planCliUpdate(globalChannel, 'linux', onChannel(RELEASE_CHANNEL.Stable));
    expect(stable.command?.args).toContain(`${CLI_PACKAGE}@latest`);
    // The spec never carries the typed token. Give `Stable` the value `latest`
    // and this is what still holds while `--channel stable` stops parsing, so
    // it is asserted as an absence rather than left to the positive above.
    expect(stable.command?.args).not.toContain(`${CLI_PACKAGE}@stable`);
    expect(stable.display).not.toContain('@stable');
  });

  it('carries the tag into the advisory lines a user would paste', () => {
    // These print a command instead of running one, so a tag left off here is a
    // line that silently installs the wrong channel.
    const project = planCliUpdate(
      { kind: 'project', packageDir: '/p/node_modules/x', projectRoot: '/p', manager: 'pnpm' },
      'linux',
      onChannel(RELEASE_CHANNEL.Beta),
    );
    expect(project.command).toBeNull();
    expect(project.display).toContain(`${CLI_PACKAGE}@beta`);

    const unknown = planCliUpdate(
      { kind: 'unknown', detail: 'nowhere' },
      'linux',
      onChannel(RELEASE_CHANNEL.Beta),
    );
    expect(unknown.command).toBeNull();
    expect(unknown.display).toContain(`${CLI_PACKAGE}@beta`);
  });

  it('says so on the two install kinds that cannot express a channel', () => {
    // The binary embeds its own runtime and Homebrew owns its tree — neither
    // has an npm spec to put a tag on. Printing the stable advice with no note
    // would answer a request to switch channels by quietly doing something else.
    const channels: InstallChannel[] = [
      ...SEA_OWNERS.map((managedBy): InstallChannel => ({
        kind: 'sea',
        execPath: '/usr/local/bin/aka',
        managedBy,
        installRoot: null,
      })),
      { kind: 'homebrew', packageDir: '/opt/homebrew/x' },
    ];
    // Every owner of the binary carries the note, not just the one the installer
    // owns: brew and scoop cannot follow a channel either, and an owner added
    // with the note left off would answer a switch request with a bare upgrade.
    expect(channels.length).toBe(SEA_OWNERS.length + 1);
    for (const channel of channels) {
      const label = channelLabel(channel);
      const asked = planCliUpdate(channel, 'linux', onChannel(RELEASE_CHANNEL.Beta));
      expect(asked.command, label).toBeNull();
      expect(asked.reason, label).toContain(RELEASE_CHANNEL.Beta);

      // And says nothing extra when nothing was asked for: the note is about
      // the request, so a default plan's reason is what it always was.
      const unasked = planCliUpdate(channel, 'linux');
      expect(unasked.reason, label).not.toContain(RELEASE_CHANNEL.Beta);
      expect(String(asked.reason).startsWith(String(unasked.reason)), label).toBe(true);
      expect(String(asked.reason).length, label).toBeGreaterThan(String(unasked.reason).length);
    }
  });

  it('quotes a root with a space whatever channel was asked for', () => {
    // The quoting is by exception and independent of the channel; a tag
    // appended into the joined display line must not disturb it.
    const win = planCliUpdate(
      {
        kind: 'global',
        manager: 'npm',
        root: String.raw`C:\Program Files\nodejs`,
        packageDir: String.raw`C:\Program Files\nodejs\node_modules\@akasecurity\cli`,
      },
      'win32',
      onChannel(RELEASE_CHANNEL.Beta),
    );
    expect(win.display).toContain(String.raw`"C:\Program Files\nodejs"`);
    expect(win.display).toContain(`${CLI_PACKAGE}@beta`);
    expect(win.command?.args).toContain(String.raw`C:\Program Files\nodejs`);
  });
});

/**
 * The spec a plan installs, once a report has RESOLVED a version.
 *
 * The property is that one value drives the row a surface shows and the spec it
 * runs. A dist-tag spec cannot carry it: `beta` goes on serving 0.11.0-beta.3
 * after 0.11.0 ships, so a machine offered the stable re-installed the
 * prerelease, printed success, and was offered the same update on every run
 * afterwards.
 */
describe('planCliUpdate — the version the spec names', () => {
  const globalChannel = classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli'));

  /** The last argv element of a runnable plan, which is the npm spec. */
  function specOf(target: CliUpdateTarget): string {
    const plan = planCliUpdate(globalChannel, 'linux', target);
    expect(plan.command, JSON.stringify(target)).not.toBeNull();
    const args = plan.command?.args ?? [];
    expect(args.length, JSON.stringify(target)).toBeGreaterThan(0);
    return String(args[args.length - 1]);
  }

  it('installs the resolved version rather than the channel’s tag', () => {
    // The graduation row. `beta` still points at the prerelease, so a tag spec
    // re-installs it while the report offers the release.
    expect(specOf({ channel: RELEASE_CHANNEL.Beta, version: '0.11.0' })).toBe(
      `${CLI_PACKAGE}@0.11.0`,
    );
    // Asserted as an absence too: the tag spec is the string this replaced, and
    // it is what a plan reverted to the old build would produce.
    expect(specOf({ channel: RELEASE_CHANNEL.Beta, version: '0.11.0' })).not.toBe(
      `${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`,
    );
  });

  it('names the resolved version on every channel, including stable', () => {
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(specOf({ channel, version: '0.12.3' }), channel).toBe(`${CLI_PACKAGE}@0.12.3`);
    }
  });

  it('keeps a prerelease version verbatim', () => {
    // A beta moving to a newer beta: the identifier must survive into the spec,
    // since `0.11.0-beta.4` and `0.11.0` are different releases.
    expect(specOf({ channel: RELEASE_CHANNEL.Beta, version: '0.11.0-beta.4' })).toBe(
      `${CLI_PACKAGE}@0.11.0-beta.4`,
    );
    expect(
      specOf({
        channel: RELEASE_CHANNEL.Nightly,
        version: '0.9.13-nightly.20260918.gabc1234',
      }),
    ).toBe(`${CLI_PACKAGE}@0.9.13-nightly.20260918.gabc1234`);
  });

  it('falls back to the channel’s tag when no version was resolved', () => {
    // The offline row, and the only case a dist-tag spec is still right: the
    // registry answered nothing, so there is no version to name.
    for (const channel of Object.values(RELEASE_CHANNEL)) {
      expect(specOf({ channel, version: null }), channel).toBe(
        `${CLI_PACKAGE}@${DIST_TAG[channel]}`,
      );
    }
  });

  it('carries the resolved version into the advisory lines a user would paste', () => {
    // These print a command instead of running one, so a version left off here
    // is a line that installs something other than what was offered.
    const project = planCliUpdate(
      { kind: 'project', packageDir: '/p/node_modules/x', projectRoot: '/p', manager: 'pnpm' },
      'linux',
      { channel: RELEASE_CHANNEL.Beta, version: '0.11.0' },
    );
    expect(project.command).toBeNull();
    expect(project.display).toContain(`${CLI_PACKAGE}@0.11.0`);
    expect(project.display).not.toContain(`${CLI_PACKAGE}@beta`);

    const unknown = planCliUpdate({ kind: 'unknown', detail: 'nowhere' }, 'linux', {
      channel: RELEASE_CHANNEL.Beta,
      version: '0.11.0',
    });
    expect(unknown.command).toBeNull();
    expect(unknown.display).toContain(`${CLI_PACKAGE}@0.11.0`);
  });

  it('still names the channel in the note, which is about the request', () => {
    // The two kinds with no npm spec at all. A resolved version does not give
    // them one, so the note has to go on naming the line that was asked for.
    const channels: InstallChannel[] = [
      ...SEA_OWNERS.map((managedBy): InstallChannel => ({
        kind: 'sea',
        execPath: '/usr/local/bin/aka',
        managedBy,
        installRoot: null,
      })),
      { kind: 'homebrew', packageDir: '/opt/homebrew/x' },
    ];
    expect(channels.length).toBe(SEA_OWNERS.length + 1);
    for (const channel of channels) {
      const label = channelLabel(channel);
      const plan = planCliUpdate(channel, 'linux', {
        channel: RELEASE_CHANNEL.Beta,
        version: '0.11.0',
      });
      expect(plan.command, label).toBeNull();
      expect(plan.reason, label).toContain(RELEASE_CHANNEL.Beta);
    }
  });
});

/**
 * A resolved version is REGISTRY-SUPPLIED TEXT on its way to a child process's
 * argv, and `exec.ts` hands that argv to cmd.exe on Windows, where Node
 * concatenates it without escaping. So the spawn seam is the assertion: a
 * version this grammar does not accept exactly must reach it never, and the
 * plan falls back to the closed dist-tag table instead.
 */
describe('planCliUpdate — what a hostile registry answer cannot reach', () => {
  const globalChannel = classifyInstall(globalProbe('/opt/node/lib/node_modules/@akasecurity/cli'));

  // Each is a token a shell would act on, or one npm would read as a flag, in a
  // position where a version is expected.
  //
  // The whitespace rows come in all three placements — leading, trailing and
  // both — because the check is an equality against the trimmed string and a
  // one-sided trim reads as a fix while leaving the other side open. With only
  // the two-sided and trailing forms here, `version === version.trimEnd()`
  // refuses every row and this whole describe stays green.
  const hostile = [
    '0.11.0; rm -rf /',
    '0.11.0 && curl http://example.test/x',
    '0.11.0 | tee /tmp/aka-pwn',
    '0.11.0`whoami`',
    '0.11.0$(whoami)',
    '0.11.0 --prefix=/tmp',
    '0.11.0\nlatest',
    '0.11.0%PATH%',
    ' 0.11.0 ',
    '0.11.0\t',
    ' 0.11.0',
    '\t0.11.0',
    '\n0.11.0',
    '-0.11.0',
    '--prefix=/tmp',
    '0.11.0"quoted"',
    "0.11.0'quoted'",
    '0.11.0&0.11.1',
    '0.11.0\r',
    '',
    'latest',
    '__proto__',
  ];

  it.each(hostile)('treats %j as unresolved and spawns the tag instead', (version) => {
    const plan = planCliUpdate(globalChannel, 'linux', {
      channel: RELEASE_CHANNEL.Beta,
      version,
    });

    // The positive control: this channel DOES have a runnable plan, so an
    // absence assertion below cannot pass on an empty argv.
    expect(plan.command).not.toBeNull();
    const args = plan.command?.args ?? [];
    expect(args.length).toBeGreaterThan(0);

    // The spec is the tag, built from this repo's own text.
    expect(args[args.length - 1]).toBe(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
    // And no argv element, nor the line printed beside it, carries the value.
    for (const arg of args) {
      expect(arg, arg).not.toContain(version === '' ? ' never' : version);
    }
    expect(plan.display).not.toContain(version === '' ? ' never' : version);
  });

  it('accepts the forms a registry really serves, so the refusal is not total', () => {
    // The non-vacuity control for the rows above: switch the check to `false`
    // and every one of them still passes while this goes red.
    for (const version of [
      '0.11.0',
      '1.0.0',
      '0.11.0-beta.4',
      '0.9.13-nightly.20260918.gabc1234',
    ]) {
      const plan = planCliUpdate(globalChannel, 'linux', {
        channel: RELEASE_CHANNEL.Beta,
        version,
      });
      const args = plan.command?.args ?? [];
      expect(args.length, version).toBeGreaterThan(0);
      expect(args[args.length - 1], version).toBe(`${CLI_PACKAGE}@${version}`);
    }
  });
});
