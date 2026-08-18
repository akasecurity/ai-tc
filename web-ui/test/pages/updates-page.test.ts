import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  AGENT_PLUGINS,
  CLI_PACKAGE,
  createCliPluginManager,
  pluginRef,
} from '@akasecurity/local-ops';
import type { ComponentProps, ReactElement, ReactNode } from 'react';
import { Children, isValidElement } from 'react';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import UpdatesPage from '../../app/(app)/updates/page.tsx';
import { UpdatesClient } from '../../app/(app)/updates/UpdatesClient.tsx';

// The Updates route's own derivation is the CONFIRM DIALOG copy: for each
// agent, every command the button is about to spawn on this machine. Nothing
// else measures it. The strings themselves are asserted in local-ops (the verb
// table) and what they spawn is asserted there too (test/spawn.test.ts) — what
// only this route can answer is which of those renderings it picks, per agent,
// and it has three ways to get that wrong that all typecheck:
//
//   - the RECIPE instead of the SPAWN PLAN, which silently drops the snapshot
//     refresh from a dialog promising "this runs the following";
//   - one host's manager for every agent — the defect the verb table replaced,
//     reappearing at the surface a user reads before consenting;
//   - an EMPTY entry for an agent with no automated path, which renders a
//     dialog that promises nothing and then does something.
//
// The page is a synchronous Server Component — a plain function returning an
// element — so calling it and reading the props it hands down needs no
// renderer and no DOM. Only `homedir()` is redirected: the route resolves
// ~/.aka from it (for the passive update cache) and `n/no-process-env` rules
// out an env override. `next/cache` is stubbed because the client component
// pulls in the actions module, which imports revalidatePath at load.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

let home: string;

beforeAll(() => {
  // An empty home on purpose: no update cache, no plugin ledgers. The dialog
  // copy is derived from the static registry and the verb table, so it must not
  // depend on what happens to be installed here — and a route that only
  // rendered commands for installed plugins would pass a seeded fixture.
  home = mkdtempSync(join(tmpdir(), 'aka-web-updates-page-'));
  osHome.dir = home;
});

afterAll(() => {
  removeTree(home);
});

type ClientProps = ComponentProps<typeof UpdatesClient>;

/**
 * Find the UpdatesClient node in the tree the route returns.
 *
 * The route returns a layout wrapper holding the page head and the client, so
 * `element.type` on the root is a `div` and its props carry `className` and
 * `children`. Reading props off the root would make every assertion below read
 * `undefined` and report the wrong reason for going red.
 */
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
  // below would go red naming a value instead of the structure.
  expect(client).not.toBeNull();
  if (client === null) throw new Error('unreachable');
  return client.props;
}

describe('the Updates route’s confirm-dialog copy', () => {
  it('gives Claude Code its own verbs, prep included, newline-joined', () => {
    const { commands, installCommands } = renderPage();

    // Spelled out rather than derived from the manager, so this pins what a
    // user is asked to consent to. The refresh is the middle line — the one a
    // recipe deliberately omits and a spawn plan must not.
    expect(commands['claude-code']).toBe(
      [
        'claude plugin marketplace add akasecurity/marketplace',
        'claude plugin marketplace update akasecurity',
        'claude plugin update ai-tc@akasecurity',
      ].join('\n'),
    );
    expect(installCommands['claude-code']).toBe(
      [
        'claude plugin marketplace add akasecurity/marketplace',
        'claude plugin marketplace update akasecurity',
        'claude plugin install ai-tc@akasecurity',
      ].join('\n'),
    );
  });

  it('gives Codex its own — a different binary and different verbs', () => {
    const { commands, installCommands } = renderPage();

    expect(commands.codex).toBe(
      [
        'codex plugin marketplace add akasecurity/ai-tc',
        'codex plugin marketplace upgrade ai-tc',
        'codex plugin add aka-codex@ai-tc',
      ].join('\n'),
    );
    // Codex has no update verb, so install and update render identically. That
    // is the host's shape, not a copy-paste: assert it rather than leaving the
    // two cases to agree by accident.
    expect(installCommands.codex).toBe(commands.codex);
    expect(commands.codex).not.toContain('claude ');
    expect(commands.codex).not.toContain('plugin update');
  });

  it('never joins the plan with `&&` — one step in it is allowed to fail', () => {
    const { commands, installCommands } = renderPage();

    for (const entry of [...Object.values(commands), ...Object.values(installCommands)]) {
      expect(entry).not.toContain('&&');
    }
  });

  it('says so — rather than nothing — for an agent with no automated path', () => {
    const { commands, installCommands } = renderPage();

    // Antigravity carries no ref and no cliBin: `agy plugin install` takes a
    // local directory, not a `<plugin>@<marketplace>` ref. An empty string here
    // would render a dialog promising nothing under "this runs the following".
    for (const map of [commands, installCommands]) {
      expect(map.antigravity).toBe(
        'No automated path for Antigravity — see `aka plugins install antigravity`.',
      );
    }
  });

  it('covers the CLI and every registered agent, with nothing empty', () => {
    const { commands, installCommands } = renderPage();

    expect(commands.cli).toBe(`npm install -g ${CLI_PACKAGE}@latest`);
    // `cli` is an update-only row: there is no install button for the CLI you
    // are already running, so installCommands deliberately has no entry.
    expect(installCommands.cli).toBeUndefined();

    for (const agent of AGENT_PLUGINS) {
      expect(commands[agent.id], agent.id).toBeTruthy();
      expect(installCommands[agent.id], agent.id).toBeTruthy();
    }
  });

  it('renders the spawn plan the manager reports, for every automatable agent', () => {
    const { commands, installCommands } = renderPage();

    // The join the literals above cannot make: whatever the verb table says
    // today, the dialog shows THAT and not the recipe. A table edit moves both
    // sides, which is why the literal cases sit beside this one.
    const automatable = AGENT_PLUGINS.filter((a) => pluginRef(a) !== undefined && a.cliBin);
    expect(automatable.length).toBeGreaterThan(1);

    for (const agent of automatable) {
      const ref = pluginRef(agent);
      if (ref === undefined || !agent.cliBin) throw new Error('unreachable');
      const manager = createCliPluginManager(agent.cliBin);
      const { marketplaceSource: source, marketplace } = agent;
      expect(commands[agent.id], agent.id).toBe(
        manager.updateSpawnPlan(ref, source, marketplace).join('\n'),
      );
      expect(installCommands[agent.id], agent.id).toBe(
        manager.installSpawnPlan(ref, source, marketplace).join('\n'),
      );
      // …and not the `&&` recipe, which is the other rendering in scope here.
      expect(commands[agent.id]).not.toBe(manager.updateRecipe(ref, source).join(' && '));
    }
  });
});
