import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { InstallOrigin } from '@akasecurity/local-ops';
import type { ComponentProps, ReactElement, ReactNode } from 'react';
import { Children, isValidElement } from 'react';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

// The Updates route derives ONE line per component and hands it to a confirm
// dialog that introduces it with "This runs the following command on this
// machine". For the CLI that line depends on how this copy was installed, and
// three of the five channels cannot be applied from here at all — the
// standalone binary, a Homebrew tree, a source checkout. Their `display` is
// advice, and routing it through `commands` puts a curl-pipe-to-shell one-liner
// in front of the user as something the dashboard is about to execute, then
// runs nothing.
//
// Which side of that split each channel lands on is a property of the ROUTE,
// not of the classifier or of the dialog, so this is the only place it can be
// asserted. The page is a synchronous Server Component — a plain function
// returning an element — so calling it and reading the props it hands down
// needs no renderer and no DOM.
//
// `homedir()` is redirected because the page resolves ~/.aka from it and
// `n/no-process-env` rules out an env override; `next/cache` is stubbed because
// the client component pulls in the actions module, which imports
// revalidatePath at load. The install origin is stubbed so each channel can be
// driven from a synthetic tree — where the origin comes from is
// test/install-origin.test.ts's subject, not this file's.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const origin = vi.hoisted(() => ({ moduleDir: undefined as string | undefined }));
vi.mock('../../app/lib/install-origin.ts', () => ({
  dashboardInstallOrigin: (): InstallOrigin => ({ moduleDir: origin.moduleDir }),
}));

const { default: UpdatesPage } = await import('../../app/(app)/updates/page.tsx');
const { UpdatesClient } = await import('../../app/(app)/updates/UpdatesClient.tsx');

const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

beforeEach(() => {
  osHome.dir = tempDir('aka-web-updates-home-');
});

afterAll(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

type ClientProps = ComponentProps<typeof UpdatesClient>;

// The route returns a layout wrapper holding the page head and the client, so
// `element.type` on the root is a `div`. Reading props off the root would make
// every assertion below read `undefined` and report the wrong reason.
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
  // Asserted, never assumed: a miss means the tree moved, and every assertion
  // downstream would go red naming a value rather than the structure.
  expect(client).not.toBeNull();
  if (client === null) throw new Error('unreachable');
  return client.props;
}

/** A real npm-global layout: <prefix>/lib/node_modules/@akasecurity/cli. */
function npmGlobalCli(): string {
  const packageDir = join(
    tempDir('aka-web-updates-npm-'),
    'lib',
    'node_modules',
    '@akasecurity',
    'cli',
  );
  mkdirSync(packageDir, { recursive: true });
  writeFileSync(
    join(packageDir, 'package.json'),
    JSON.stringify({ name: '@akasecurity/cli', version: '0.9.3' }),
  );
  return packageDir;
}

/** A source checkout: a workspace manifest above the running module. */
function sourceCheckout(): string {
  const root = tempDir('aka-web-updates-checkout-');
  writeFileSync(join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n");
  const moduleDir = join(root, 'web-ui');
  mkdirSync(moduleDir, { recursive: true });
  return moduleDir;
}

describe('the Updates route splits a runnable command from advice', () => {
  it('offers a runnable command for an install it can actually replace', () => {
    origin.moduleDir = npmGlobalCli();
    const props = renderPage();
    // The positive control. Without it the two cases below are satisfied by a
    // route that offers nothing to anyone.
    expect(props.commands.cli).toContain('npm install -g');
    expect(props.advisories.cli).toBeUndefined();
  });

  it('routes a source checkout to advice rather than to the run button', () => {
    origin.moduleDir = sourceCheckout();
    const props = renderPage();
    // `git pull` reaching `commands` is the defect: the dialog would introduce
    // it as a command the dashboard is about to run, and nothing runs it.
    expect(props.commands.cli).toBeUndefined();
    expect(props.advisories.cli?.display).toBe('git pull');
    expect(props.advisories.cli?.reason).toContain('source checkout');
  });

  it('routes an unrecognised install to advice, with a reason', () => {
    origin.moduleDir = tempDir('aka-web-updates-orphan-');
    const props = renderPage();
    expect(props.commands.cli).toBeUndefined();
    expect(props.advisories.cli?.reason).toBeTruthy();
  });

  it('never carries the same id on both sides', () => {
    // The invariant the dialog rests on: an id in `commands` is one the button
    // will run, an id in `advisories` is one it will not, and a component in
    // both would be presented as whichever the client checked first.
    for (const moduleDir of [npmGlobalCli(), sourceCheckout(), undefined]) {
      origin.moduleDir = moduleDir;
      const props = renderPage();
      const both = Object.keys(props.commands).filter((id) => id in props.advisories);
      expect(both, String(moduleDir)).toStrictEqual([]);
    }
  });

  it('still hands down the plugin commands, which are not channel-dependent', () => {
    // `commands` used to be built with the CLI's line as its initialiser; the
    // plugins are appended to it and would be lost by a careless split.
    origin.moduleDir = sourceCheckout();
    const props = renderPage();
    for (const line of Object.values(props.commands)) {
      expect(line).toContain('claude plugin update ');
    }
    expect(Object.keys(props.installCommands).length).toBeGreaterThan(0);
  });
});
