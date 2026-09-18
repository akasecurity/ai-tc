import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import { AGENT_PLUGINS, CLI_PACKAGE, pluginRef } from '@akasecurity/local-ops';
import type { UpdateCache } from '@akasecurity/schema';
import { DIST_TAG, RELEASE_CHANNEL } from '@akasecurity/schema';
import type { ComponentProps, ReactElement, ReactNode } from 'react';
import { Children, isValidElement } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

// The dialog this route feeds introduces its line with "This runs the following
// command on this machine", and the thing that then runs it is `applyUpdate` in
// ./actions.ts — a different module, building a different plan. So the line and
// the install agree only because both derive the release channel from the same
// input, and nothing about the types says so.
//
// It cannot be asserted from the sibling route suite: the page reads the
// running CLI's own version, which under vitest walks up from this checkout and
// finds no `@akasecurity/cli` manifest at all. Every version it could see is
// therefore stable, and on stable the channel-aware spec and the old hardcoded
// one are the same string. Injecting that read is what makes the case live.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const origin = vi.hoisted(() => ({ moduleDir: undefined as string | undefined }));
vi.mock('../../app/lib/install-origin.ts', () => ({
  dashboardInstallOrigin: (): LocalOps.InstallOrigin => ({ moduleDir: origin.moduleDir }),
}));

const running = vi.hoisted(() => ({ version: null as string | null }));
// The installed-plugin ledger is redirected too, so a case can put a SECOND
// status row in the report. With the CLI row alone, reaching for "the row whose
// id is cli" and reaching for the last row are the same read, and a target
// taken off the wrong row would install the CLI at a plugin's version with
// every assertion here still green.
const installedPlugins = vi.hoisted(() => ({ map: new Map<string, string>() }));
vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    cliVersion: (): string | null => running.version,
    installedAgentPluginVersions: (): Map<string, string> => installedPlugins.map,
  };
});

const { default: UpdatesPage } = await import('../../app/(app)/updates/page.tsx');
const { UpdatesClient } = await import('../../app/(app)/updates/UpdatesClient.tsx');

type ClientProps = ComponentProps<typeof UpdatesClient>;

function findClient(node: ReactNode): ReactElement<ClientProps> | null {
  if (!isValidElement(node)) return null;
  if (node.type === UpdatesClient) return node as ReactElement<ClientProps>;
  const { children } = node.props as { children?: ReactNode };
  for (const child of Children.toArray(children)) {
    const found = findClient(child);
    if (found !== null) return found;
  }
  return null;
}

function renderPage(): ClientProps {
  const client = findClient(UpdatesPage());
  expect(client).not.toBeNull();
  if (client === null) throw new Error('unreachable');
  return client.props;
}

const newHome = tempHomes('aka-web-updates-channel-home-');
const newNpmPrefix = tempHomes('aka-web-updates-channel-npm-');

// The plugin the multi-row case installs, taken from the registry rather than
// spelled here — an id or a ref written by hand agrees with nothing.
//
// Bound through a second const so the narrowing survives into `seedCache`
// below: a function declaration is hoisted above these checks, so a value
// narrowed only by the guards is still optional inside one.
const foundAgent = AGENT_PLUGINS.find((a) => a.id === 'claude-code');
if (foundAgent === undefined) throw new Error('the registry no longer carries a claude-code agent');
const PLUGIN_AGENT = foundAgent;
const foundRef = pluginRef(PLUGIN_AGENT);
if (foundRef === undefined) throw new Error('the claude-code agent no longer has a plugin ref');
const PLUGIN_REF = foundRef;

/**
 * The passive-notice cache the CLI's background refresh would have written.
 *
 * Written through the path `readCache` reads, so nothing here models the cache
 * layout: a file written elsewhere leaves every row on the no-cache branch,
 * where the command line is the dist-tag spec and the version assertions below
 * would be asserting the very thing they exist to refuse.
 */
function seedCache(latest: string | null, pluginLatest?: string): void {
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
        // The cache is keyed by component id, so a plugin's cached answer is a
        // second row here — which is what puts a second row in the REPORT.
        ...(pluginLatest === undefined
          ? []
          : [
              {
                id: PLUGIN_AGENT.id,
                name: PLUGIN_AGENT.name,
                kind: 'plugin' as const,
                installed: null,
                latest: pluginLatest,
                updateAvailable: false,
              },
            ]),
      ],
      availablePlugins: [],
    },
    notifiedPluginIds: [],
  };
  const dir = join(osHome.dir, '.aka', 'data');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'update-check.json'), `${JSON.stringify(cache)}\n`);
}

/** A real npm-global layout, the one install kind with a runnable command. */
function npmGlobalCli(): string {
  const packageDir = join(newNpmPrefix(), 'lib', 'node_modules', '@akasecurity', 'cli');
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(
    join(packageDir, 'package.json'),
    JSON.stringify({ name: CLI_PACKAGE, version: '0.9.3' }),
  );
  return packageDir;
}

beforeEach(() => {
  osHome.dir = newHome();
  origin.moduleDir = npmGlobalCli();
  running.version = null;
  installedPlugins.map = new Map();
});

describe('the Updates route names the channel this copy follows', () => {
  it('asks for the stable tag with nothing resolved to install', () => {
    // The control. With no cache there is no version to name, so the line is
    // the dist-tag spec — and on stable that is the same string the hardcoded
    // build produced, so this case alone proves nothing. It is here so the rows
    // below cannot pass on an empty command.
    running.version = '0.9.3';
    const props = renderPage();

    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@latest`);
  });

  it.each([
    ['0.11.0-beta.2', 'beta'],
    ['0.9.13-nightly.20260918.gabc1234', 'nightly'],
  ])('asks for the %s machine’s own tag with nothing resolved', (installed, tag) => {
    running.version = installed;
    const props = renderPage();

    expect(props.commands.cli, installed).toContain(`${CLI_PACKAGE}@${tag}`);
    // And not the stable one beside it: the dialog names ONE command, so a
    // line carrying both tags is not a thing to tolerate.
    expect(props.commands.cli, installed).not.toContain(`${CLI_PACKAGE}@latest`);
  });

  it('never puts the typed channel token in the line, only the registry tag', () => {
    // `stable` is what a user types and `latest` is what npm serves. A spec
    // built from the token asks for a tag nothing publishes.
    running.version = '0.9.3';
    const props = renderPage();

    expect(props.commands.cli).not.toContain(`@${RELEASE_CHANNEL.Stable}`);
  });
});

/**
 * The VERSION in the line the dialog shows.
 *
 * The dialog introduces it with "This runs the following command on this
 * machine", and ./actions.ts is what then runs it — so the line has to name the
 * version the row beside it offered. A dist-tag spec cannot: `beta` goes on
 * serving the prerelease after the release ships, so the dialog promised 0.11.0
 * while the button re-installed 0.11.0-beta.3.
 */
describe('the Updates route names the version it will install', () => {
  it('shows the resolved version, not the channel’s tag', () => {
    // The graduation row on this surface.
    running.version = '0.11.0-beta.3';
    seedCache('0.11.0');
    const props = renderPage();

    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@0.11.0`);
    expect(props.commands.cli).not.toContain(`${CLI_PACKAGE}@${DIST_TAG[RELEASE_CHANNEL.Beta]}`);
  });

  it('shows the same version the row it renders offers', () => {
    // Read off the props rather than the literal, so the line and the table
    // cannot each be right against a different version.
    running.version = '0.11.0-beta.3';
    seedCache('0.11.0');
    const props = renderPage();

    const row = props.statuses.find((status) => status.id === 'cli');
    expect(row?.latest).toBe('0.11.0');
    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@${String(row?.latest)}`);
  });

  it('keeps a prerelease version verbatim', () => {
    running.version = '0.11.0-beta.3';
    seedCache('0.11.0-beta.4');
    const props = renderPage();

    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@0.11.0-beta.4`);
  });

  it('shows the stable version on a stable machine', () => {
    running.version = '0.9.3';
    seedCache('0.9.12');
    const props = renderPage();

    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@0.9.12`);
    expect(props.commands.cli).not.toContain(`${CLI_PACKAGE}@latest`);
  });

  it('reads the CLI’s own row when the report carries a plugin row too', () => {
    // Every other case here renders a report with one status, where "the row
    // whose id is cli" and "the last row" are the same read. With a plugin
    // installed they are different rows, and a target taken off the wrong one
    // puts a PLUGIN's version in the command that installs the CLI.
    running.version = '0.9.3';
    installedPlugins.map = new Map([[PLUGIN_REF, '0.9.98']]);
    seedCache('0.11.0', '0.9.99');
    const props = renderPage();

    // The positive control: the report really does carry both rows, in that
    // order, so the absence below is about the lookup rather than about a
    // plugin row that never arrived.
    expect(props.statuses.map((status) => status.id)).toStrictEqual(['cli', PLUGIN_AGENT.id]);
    expect(props.statuses.find((status) => status.id === PLUGIN_AGENT.id)?.latest).toBe('0.9.99');

    expect(props.commands.cli).toContain(`${CLI_PACKAGE}@0.11.0`);
    expect(props.commands.cli).not.toContain('0.9.99');
  });

  it('never shows a cached answer this grammar refuses', () => {
    // A cached `latest` is registry-supplied text on its way to argv.
    for (const hostile of ['0.9.12; id', ' 0.9.12 ', '-0.9.12', '0.9.12`id`']) {
      osHome.dir = newHome();
      origin.moduleDir = npmGlobalCli();
      running.version = '0.9.3';
      seedCache(hostile);
      const props = renderPage();

      expect(props.commands.cli, hostile).toContain(`${CLI_PACKAGE}@latest`);
      expect(props.commands.cli, hostile).not.toContain(hostile.trim());
    }
  });
});
