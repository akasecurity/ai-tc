import type * as LocalOps from '@akasecurity/local-ops';
import { AGENT_PLUGINS, createCliPluginManager, pluginRef } from '@akasecurity/local-ops';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// What `aka plugins install` PRINTS before it spawns, which nothing else
// measures. local-ops proves the spawn plan matches the argv that really
// reaches the host (test/spawn.test.ts) and the Updates route proves the
// dashboard renders that same plan; this is the terminal's half of the same
// promise, and it is the surface where a user watches the commands scroll past
// and can notice one they were never told about.
//
// The announce line used to render the RECIPE — register-then-op, joined with
// `&&` — while three commands spawned, so the snapshot refresh ran undisclosed.
// Both renderings typecheck, are non-empty, and name the right host, so only an
// assertion tying the printed lines to `installSpawnPlan` can tell them apart.
//
// `available()` is forced rather than probed: the real one shells out to
// `command -v claude`, so this case would assert one thing on a developer's
// machine and skip the branch entirely on a CI runner without the host CLI.
// `installAgentPlugin` is stubbed because the announce line is printed BEFORE
// the spawn, and this suite is about the copy, not the child process.
const spawned = vi.hoisted(() => ({ calls: [] as string[] }));

vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    createCliPluginManager: (bin: 'claude' | 'codex') => ({
      ...actual.createCliPluginManager(bin),
      available: () => true,
    }),
    installAgentPlugin: (agentId: string) => {
      spawned.calls.push(agentId);
      return { ok: true, output: '' };
    },
  };
});

const { runPlugins } = await import('../../src/commands/plugins.ts');

function capture(fn: () => void): string {
  let out = '';
  const spy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array): boolean => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  try {
    fn();
  } finally {
    spy.mockRestore();
  }
  return out;
}

beforeEach(() => {
  spawned.calls = [];
});

describe('aka plugins install discloses every command it is about to run', () => {
  // Both hosts, because their verbs differ and a single-host case passes while
  // the other renders a command its CLI rejects — the defect this table
  // replaced, reappearing in the copy a user reads.
  for (const agent of AGENT_PLUGINS) {
    const cliBin = agent.cliBin;
    const ref = pluginRef(agent);
    if (!cliBin || !ref) continue;
    const manager = createCliPluginManager(cliBin);

    it(`${agent.id}: names all of them, in order`, () => {
      const plan = manager.installSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
      expect(plan.length).toBeGreaterThan(1);

      const out = capture(() => {
        // Typed `void | Promise<void>`; the `install` subcommand is the
        // synchronous branch, so there is no promise here to await.
        void runPlugins(['install', agent.id]);
      });

      expect(spawned.calls).toEqual([agent.id]);
      for (const command of plan) expect(out).toContain(command);
      // In the plan's own order, so a render that lists the op before its prep
      // still fails — the order is the part a user checks against what scrolls
      // past next.
      const positions = plan.map((command) => out.indexOf(command));
      expect(positions).toEqual([...positions].sort((a, b) => a - b));
    });

    it(`${agent.id}: does not print the && recipe, which omits the refresh`, (ctx) => {
      const recipe = manager.installRecipe(ref, agent.marketplaceSource);
      const plan = manager.installSpawnPlan(ref, agent.marketplaceSource, agent.marketplace);
      // Only meaningful where the two actually differ; where a host has no
      // refresh they are the same list and there is nothing to get wrong. A
      // skip rather than a return: a body that ends before its first assertion
      // has checked nothing, and reporting that as a pass is how a case that
      // stopped covering anything goes unnoticed.
      if (recipe.length === plan.length) {
        ctx.skip(`${agent.id}: recipe and spawn plan are the same list`);
      }

      const out = capture(() => {
        // Typed `void | Promise<void>`; the `install` subcommand is the
        // synchronous branch, so there is no promise here to await.
        void runPlugins(['install', agent.id]);
      });

      expect(out).not.toContain(recipe.join(' && '));
    });
  }
});
