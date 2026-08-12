import { describe, expect, it } from 'vitest';

import { createCliPluginManager } from '../src/cli-plugin-manager.ts';

// The two host CLIs share the `<bin> plugin …` SHAPE and nothing else. Treating
// their verbs as interchangeable is what shipped `codex plugin install
// aka-codex@ai-tc` to users, which Codex rejects with "unrecognized subcommand"
// — every install and update through the Codex path failed. Pin each host's
// verbs against its real CLI, and pin that the hint copy and the spawned
// command are the same string: hint copy is the surface the user retypes, so a
// hint that drifts from the spawn fails in the user's terminal rather than here.

describe('claude verbs', () => {
  const claude = createCliPluginManager('claude');

  it('installs with `plugin install <ref>`', () => {
    expect(claude.installSteps('ai-tc@akasecurity')).toEqual([
      ['plugin', 'install', 'ai-tc@akasecurity'],
    ]);
  });

  it('updates with `plugin update <ref>`', () => {
    expect(claude.updateSteps('ai-tc@akasecurity')).toEqual([
      ['plugin', 'update', 'ai-tc@akasecurity'],
    ]);
  });

  it('prepares the marketplace with a bare `marketplace add` — it keeps no snapshot to refresh', () => {
    expect(claude.marketplaceSteps('akasecurity/marketplace', 'akasecurity')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/marketplace'],
    ]);
  });
});

describe('codex verbs', () => {
  const codex = createCliPluginManager('codex');

  it('installs with `plugin add <ref>` — codex has no `install` subcommand', () => {
    expect(codex.installSteps('aka-codex@ai-tc')).toEqual([['plugin', 'add', 'aka-codex@ai-tc']]);
  });

  it('updates by re-adding — codex has no `update` subcommand', () => {
    expect(codex.updateSteps('aka-codex@ai-tc')).toEqual([['plugin', 'add', 'aka-codex@ai-tc']]);
  });

  it('refreshes the snapshot as marketplace PREP, not as part of the op', () => {
    expect(codex.marketplaceSteps('akasecurity/ai-tc', 'ai-tc')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/ai-tc'],
      ['plugin', 'marketplace', 'upgrade', 'ai-tc'],
    ]);
  });

  it('skips the snapshot refresh when no marketplace name is known', () => {
    expect(codex.marketplaceSteps('akasecurity/ai-tc')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/ai-tc'],
    ]);
  });
});

// The refresh is best-effort, and the only thing that keeps it so is its ABSENCE
// from the fatal step list. apply.ts runs the plugin op through `runSteps`,
// which stops at the first failure — so a `marketplace upgrade` inside
// `updateSteps` turns a transient git-fetch failure into an aborted update that
// would have succeeded against the cached snapshot. Pin the separation
// directly: no marketplace command may appear in either op.
describe('a plugin op carries no marketplace command', () => {
  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      const ops = [...manager.installSteps('p@m'), ...manager.updateSteps('p@m')];
      expect(ops.length).toBeGreaterThan(0);
      for (const args of ops) expect(args).not.toContain('marketplace');
    });
  }
});

describe('no host emits a verb its CLI does not have', () => {
  // Verified against codex-cli 0.147.0 (`codex plugin --help`): add, list,
  // marketplace, remove — and `codex plugin marketplace`: add, list, upgrade,
  // remove. Claude Code's `claude plugin --help` carries install and update.
  const KNOWN_VERBS: Record<'claude' | 'codex', Set<string>> = {
    claude: new Set(['install', 'update', 'uninstall', 'marketplace', 'list', 'enable', 'disable']),
    codex: new Set(['add', 'remove', 'marketplace', 'list']),
  };
  const MARKETPLACE_VERBS: Record<'claude' | 'codex', Set<string>> = {
    claude: new Set(['add', 'remove', 'list']),
    codex: new Set(['add', 'list', 'upgrade', 'remove']),
  };

  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      const steps = [
        ...manager.installSteps('p@m'),
        ...manager.updateSteps('p@m'),
        ...manager.marketplaceSteps('owner/repo', 'm'),
      ];
      expect(steps.length).toBeGreaterThan(0);
      for (const args of steps) {
        expect(args[0]).toBe('plugin');
        expect(KNOWN_VERBS[bin]).toContain(args[1]);
        // `marketplace` is a command group, so its own sub-verb is a second
        // chance to name something the host does not have.
        if (args[1] === 'marketplace') expect(MARKETPLACE_VERBS[bin]).toContain(args[2]);
      }
    });
  }
});

describe('hint copy is the command that runs', () => {
  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      expect(manager.installCommands('p@m')).toEqual(
        manager.installSteps('p@m').map((args) => `${bin} ${args.join(' ')}`),
      );
      expect(manager.updateCommands('p@m')).toEqual(
        manager.updateSteps('p@m').map((args) => `${bin} ${args.join(' ')}`),
      );
    });
  }
});

// The recipes are the hints shown when the host CLI is NOT on PATH — a machine
// where the marketplace has almost certainly never been registered. A recipe
// that starts at the plugin op hands the user a line whose first command fails
// on an unregistered marketplace, and `&&` then swallows the rest.
describe('an off-PATH recipe registers the marketplace before using it', () => {
  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      const cases = [
        {
          recipe: manager.installRecipe('p@m', 'owner/repo', 'm'),
          op: manager.installCommands('p@m'),
        },
        {
          recipe: manager.updateRecipe('p@m', 'owner/repo', 'm'),
          op: manager.updateCommands('p@m'),
        },
      ];
      for (const { recipe, op } of cases) {
        expect(recipe[0]).toBe(`${bin} plugin marketplace add owner/repo`);
        // …and it still ENDS with the op, so a recipe is prep PLUS the thing the
        // user asked for, never prep instead of it.
        expect(recipe.slice(-op.length)).toEqual(op);
        expect(recipe.length).toBeGreaterThan(op.length);
      }
    });
  }

  it('omits the prep when there is no marketplace source to name', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.installRecipe('p@m')).toEqual(codex.installCommands('p@m'));
  });
});
