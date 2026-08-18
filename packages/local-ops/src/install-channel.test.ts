import { readFileSync } from 'node:fs';
import { sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { ChannelProbe, InstallChannel } from './install-channel.ts';
import {
  classifyInstall,
  describeChannel,
  detectInstallChannel,
  planCliUpdate,
} from './install-channel.ts';
import { CLI_PACKAGE } from './updates.ts';

// Every fixture path is written POSIX-style and translated to the host
// separator, so the same cases run on Windows CI rather than being skipped
// there — the layouts they describe are what npm/pnpm/bun really lay down.
function p(posix: string): string {
  return posix.split('/').join(sep);
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
    // directory of that name was told to run `brew upgrade aka` — a formula
    // that does not exist — instead of being pointed at the manager that
    // really owns the install.
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
      installRoot: p('/Users/x/.local/share/aka'),
    });
  });

  it('still reports sea for a hand-placed binary, with no install root', () => {
    const channel = classifyInstall(probe({ sea: true, execPath: '/usr/local/bin/aka' }));
    expect(channel).toMatchObject({ kind: 'sea', installRoot: null });
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

  it('does not mistake a project-local node_modules link for a global install', () => {
    const channel = classifyInstall(
      probe({
        moduleDir: '/Users/x/code/app/node_modules/@akasecurity/cli/dist',
        packages: {
          '/Users/x/code/app/node_modules/@akasecurity/cli': CLI_PACKAGE,
          '/Users/x/code/app': 'my-app',
        },
      }),
    );
    expect(channel.kind).toBe('dev');
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

    it('reads a project dependency as a dev tree, not as a global install', () => {
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
      expect(channel.kind).toBe('dev');
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
      { kind: 'sea', execPath: '/usr/local/bin/aka', installRoot: null },
      { kind: 'homebrew', packageDir: '/opt/homebrew/x' },
      { kind: 'dev', packageDir: '/src/cli' },
      { kind: 'unknown', detail: 'nowhere' },
    ];
    for (const channel of channels) {
      const plan = planCliUpdate(channel);
      expect(plan.command, channel.kind).toBeNull();
      expect(plan.reason, channel.kind).toBeTruthy();
      expect(plan.display.length, channel.kind).toBeGreaterThan(0);
      expect(describeChannel(channel).length, channel.kind).toBeGreaterThan(0);
    }
  });
});
