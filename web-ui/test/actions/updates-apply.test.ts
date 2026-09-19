import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { CLI_PACKAGE } from '@akasecurity/local-ops';
import type { CliUpdateTarget, ReleaseChannel, UpdateCache } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

// The dashboard's confirm dialog prints the command this action is about to
// run, and the two are built in different modules — ./page.tsx renders
// `planCliUpdate`'s display, this action calls `applyCliUpdate`. So the one
// thing that cannot be left to construction is that both derive the same
// TARGET: the channel AND the version. A channel-only target installs whatever
// that channel's dist-tag happens to serve, which on a graduating prerelease is
// a different release from the one the dialog named.
//
// Three reads are redirected. `applyCliUpdate` with no seam spawns a real `npm
// install -g` against the developer's own machine; `cliVersion` walks up from
// this file rather than from an installed CLI, so an unstubbed run would assert
// against whatever this checkout holds; and the update cache is read from
// `~/.aka`, so without a redirected home this suite would read the developer's
// own registry answers.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

const seams = vi.hoisted(
  (): {
    applied: (CliUpdateTarget | undefined)[];
    plugins: string[];
    cliVersion: string | null;
  } => ({ applied: [], plugins: [], cliVersion: null }),
);

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    cliVersion: (): string | null => seams.cliVersion,
    clearCache: (): void => undefined,
    detectInstallChannel: (): LocalOps.InstallChannel => ({
      kind: 'global',
      manager: 'npm',
      root: '/opt/node',
      packageDir: '/opt/node/lib/node_modules/@akasecurity/cli',
    }),
    applyCliUpdate: (
      _channel: LocalOps.InstallChannel,
      _mode?: 'inherit' | 'capture',
      _hasBin?: (bin: string) => boolean,
      target?: CliUpdateTarget,
    ): LocalOps.ApplyResult => {
      seams.applied.push(target);
      return { ok: true, output: '' };
    },
    applyPluginUpdate: (id: string): LocalOps.ApplyResult => {
      seams.plugins.push(id);
      return { ok: true, output: '' };
    },
  };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const { applyUpdate } = await import('../../app/(app)/updates/actions.ts');
const { planCliUpdate } = await import('@akasecurity/local-ops');

const newHome = tempHomes('aka-web-updates-apply-home-');

/**
 * The passive-notice cache the CLI's background refresh would have written,
 * carrying one CLI row at `latest`.
 *
 * Written through the same path `readCache` reads, so nothing here models the
 * cache layout — a suite that wrote the file somewhere else would exercise the
 * no-cache branch on every row and still read green.
 */
function seedCache(latest: string | null): void {
  const cache: UpdateCache = {
    checkedAt: Date.now(),
    report: {
      statuses: [
        {
          id: 'cli',
          name: 'aka CLI',
          kind: 'cli',
          installed: null,
          latest,
          updateAvailable: false,
        },
      ],
      availablePlugins: [],
    },
    notifiedPluginIds: [],
  };
  const dir = join(osHome.dir, '.aka', 'data');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'update-check.json'), `${JSON.stringify(cache)}\n`);
}

/** The npm spec the recorded target would really have spawned. */
function specOf(target: CliUpdateTarget | undefined): string {
  const plan = planCliUpdate(
    {
      kind: 'global',
      manager: 'npm',
      root: '/opt/node',
      packageDir: '/opt/node/lib/node_modules/@akasecurity/cli',
    },
    'linux',
    target ?? { channel: RELEASE_CHANNEL.Stable, version: null },
  );
  const args = plan.command?.args ?? [];
  expect(args.length).toBeGreaterThan(0);
  return String(args[args.length - 1]);
}

beforeEach(() => {
  seams.applied = [];
  seams.plugins = [];
  seams.cliVersion = null;
  osHome.dir = newHome();
});

describe('applyUpdate — the channel the dashboard installs', () => {
  it.each([
    ['0.9.11', RELEASE_CHANNEL.Stable],
    ['0.11.0-beta.2', RELEASE_CHANNEL.Beta],
    ['0.9.13-nightly.20260918.gabc1234', RELEASE_CHANNEL.Nightly],
    [null, RELEASE_CHANNEL.Stable],
  ] satisfies [string | null, ReleaseChannel][])(
    'derives %s as the channel to install',
    async (installed, expected) => {
      seams.cliVersion = installed;
      const result = await applyUpdate('cli');

      expect(result.ok).toBe(true);
      // The exact value, not merely "some member": a hardcoded stable satisfies
      // half these rows, which is why the prerelease ones are here.
      expect(seams.applied.map((t) => t?.channel)).toStrictEqual([expected]);
    },
  );
});

describe('applyUpdate — the version the dashboard installs', () => {
  it('installs the version the cache resolved, not the channel’s dist-tag', async () => {
    // The graduation row on this surface. The cached answer is the release, and
    // `beta` still points at the prerelease — so a target carrying only the
    // channel re-installs what is already here.
    seams.cliVersion = '0.11.0-beta.3';
    seedCache('0.11.0');
    await applyUpdate('cli');

    expect(seams.applied).toStrictEqual([{ channel: RELEASE_CHANNEL.Beta, version: '0.11.0' }]);
    expect(specOf(seams.applied[0])).toBe(`${CLI_PACKAGE}@0.11.0`);
    // Asserted as an absence too: the tag spec is the string this replaced.
    expect(specOf(seams.applied[0])).not.toBe(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
  });

  it('installs a prerelease version verbatim', async () => {
    seams.cliVersion = '0.11.0-beta.3';
    seedCache('0.11.0-beta.4');
    await applyUpdate('cli');

    expect(specOf(seams.applied[0])).toBe(`${CLI_PACKAGE}@0.11.0-beta.4`);
  });

  it('installs the stable version on a stable machine', async () => {
    seams.cliVersion = '0.9.11';
    seedCache('0.9.12');
    await applyUpdate('cli');

    expect(seams.applied).toStrictEqual([{ channel: RELEASE_CHANNEL.Stable, version: '0.9.12' }]);
    expect(specOf(seams.applied[0])).toBe(`${CLI_PACKAGE}@0.9.12`);
  });

  it('falls back to the dist-tag with no cache to resolve a version from', async () => {
    // The only case a tag spec is still right: nothing has answered, so there
    // is no version to name. This is also the control that keeps the rows above
    // honest — without it they pass on an action that ignores the cache.
    seams.cliVersion = '0.11.0-beta.3';
    await applyUpdate('cli');

    expect(seams.applied).toStrictEqual([{ channel: RELEASE_CHANNEL.Beta, version: null }]);
    expect(specOf(seams.applied[0])).toBe(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
  });

  it('never puts a cached answer this grammar refuses into the spec', async () => {
    // A cached `latest` is registry-supplied text, and `exec.ts` hands argv to
    // cmd.exe on Windows without escaping it. The spec falls back to the tag.
    for (const hostile of ['0.9.12; id', '0.9.12 && id', ' 0.9.12 ', '-0.9.12', '0.9.12`id`']) {
      seams.applied = [];
      osHome.dir = newHome();
      seams.cliVersion = '0.9.11';
      seedCache(hostile);
      await applyUpdate('cli');

      expect(seams.applied, hostile).toHaveLength(1);
      expect(specOf(seams.applied[0]), hostile).toBe(
        `${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Stable]}`,
      );
      expect(specOf(seams.applied[0]), hostile).not.toContain(hostile.trim());
    }
  });

  it('reports a restart only for the CLI, and touches no plugin on that path', async () => {
    // The control that keeps every row above pointed at the CLI branch: an
    // action that had stopped distinguishing the two would pass every channel
    // and version assertion by never reaching either call.
    const cli = await applyUpdate('cli');
    expect(cli.restartRequired).toBe(true);
    expect(seams.plugins).toStrictEqual([]);

    const plugin = await applyUpdate('claude-code');
    expect(plugin.restartRequired).toBe(false);
    expect(seams.plugins).toStrictEqual(['claude-code']);
    // And no second install was attempted for the plugin id.
    expect(seams.applied).toHaveLength(1);
  });
});
