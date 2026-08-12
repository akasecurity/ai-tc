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

  it('renders a distinct install and update recipe — it has both verbs', () => {
    expect(claude.installRecipe('ai-tc@akasecurity', 'akasecurity/marketplace')).not.toEqual(
      claude.updateRecipe('ai-tc@akasecurity', 'akasecurity/marketplace'),
    );
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

// A recipe is the MANUAL EQUIVALENT — what a user runs by hand — and every
// caller joins it with `&&`. Two things follow, and the second is the one that
// bit: a recipe must reach the op (a line that only registers a marketplace
// achieves nothing), and it must carry ONLY steps whose failure should stop
// everything after them. `&&` cannot express "this one is survivable", so a
// best-effort step spliced into a recipe becomes fatal in exactly the copy the
// user retypes — a git-fetch error on `marketplace upgrade` short-circuiting
// the `plugin add` that is the entire point.
describe('a recipe is safe to join with &&', () => {
  for (const bin of ['claude', 'codex'] as const) {
    it(bin, () => {
      const manager = createCliPluginManager(bin);
      const cases = [
        { recipe: manager.installRecipe('p@m', 'owner/repo'), op: manager.installCommands('p@m') },
        { recipe: manager.updateRecipe('p@m', 'owner/repo'), op: manager.updateCommands('p@m') },
      ];
      for (const { recipe, op } of cases) {
        // Registers first — the op fails on an unknown marketplace without it.
        expect(recipe[0]).toBe(`${bin} plugin marketplace add owner/repo`);
        // …and still ENDS with the op, so a recipe is prep PLUS the thing the
        // user asked for, never prep instead of it.
        expect(recipe.slice(-op.length)).toEqual(op);
        expect(recipe.length).toBeGreaterThan(op.length);
        // No survivable step anywhere in it. `marketplace upgrade` is the one
        // this module treats as best-effort, so it is the one that must not be
        // here — its failure would take the op down with it.
        for (const line of recipe) expect(line).not.toContain('marketplace upgrade');
      }
    });
  }

  it('omits the prep when there is no marketplace source to name', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.installRecipe('p@m')).toEqual(codex.installCommands('p@m'));
  });
});

// The survivable step still has to RUN somewhere, or moving it out of the op
// silently deleted it. It belongs to the automated path alone, which captures
// and discards each result instead of chaining on success.
describe('the snapshot refresh survives as best-effort prep', () => {
  it('codex keeps it in marketplaceSteps, which ensureMarketplace runs', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.marketplaceSteps('akasecurity/ai-tc', 'ai-tc')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/ai-tc'],
      ['plugin', 'marketplace', 'upgrade', 'ai-tc'],
    ]);
  });
});
