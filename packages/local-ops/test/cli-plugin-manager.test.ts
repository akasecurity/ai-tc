import { describe, expect, it } from 'vitest';

import { createCliPluginManager } from '../src/cli-plugin-manager.ts';

// The manager exposes STEPS; rendering them is the caller's job (apply.ts runs
// them, the CLI and the dashboard print them). Rendering here rather than
// asserting against a shipped `installCommands`/`updateCommands` keeps the
// module's surface to what something actually calls — an exported helper whose
// only caller is the suite pinning it proves nothing about the product.
const rendered = (bin: string, steps: readonly (readonly string[])[]): string[] =>
  steps.map((args) => `${bin} ${args.join(' ')}`);

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

  it("refreshes the snapshot with `marketplace update` — its own spelling, not codex's", () => {
    // Claude Code caches the marketplace and reconciles it with its source
    // through `marketplace update` (verified against 2.1.220: the verb exists,
    // exits 0, and reports "Successfully updated marketplace"). Registering
    // alone does NOT reconcile — a re-add answers "already on disk" — so prep
    // that stopped at `add` left the op resolving against a stale manifest.
    expect(claude.marketplaceSteps('akasecurity/marketplace', 'akasecurity')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/marketplace'],
      ['plugin', 'marketplace', 'update', 'akasecurity'],
    ]);
  });

  it('skips the snapshot refresh when no marketplace name is known', () => {
    expect(claude.marketplaceSteps('akasecurity/marketplace')).toEqual([
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
  // remove. Against Claude Code 2.1.220: `claude plugin --help` carries install
  // and update, and `claude plugin marketplace --help` carries add, list,
  // remove and update. Each host read from that host — the sets below are a
  // model of two CLIs, so filling one in from the other is the same mistake as
  // sharing the verbs.
  const KNOWN_VERBS: Record<'claude' | 'codex', Set<string>> = {
    claude: new Set(['install', 'update', 'uninstall', 'marketplace', 'list', 'enable', 'disable']),
    codex: new Set(['add', 'remove', 'marketplace', 'list']),
  };
  const MARKETPLACE_VERBS: Record<'claude' | 'codex', Set<string>> = {
    claude: new Set(['add', 'remove', 'list', 'update']),
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
        {
          recipe: manager.installRecipe('p@m', 'owner/repo'),
          op: rendered(bin, manager.installSteps('p@m')),
        },
        {
          recipe: manager.updateRecipe('p@m', 'owner/repo'),
          op: rendered(bin, manager.updateSteps('p@m')),
        },
      ];
      for (const { recipe, op } of cases) {
        // Registers first — the op fails on an unknown marketplace without it.
        expect(recipe[0]).toBe(`${bin} plugin marketplace add owner/repo`);
        // …and still ENDS with the op, so a recipe is prep PLUS the thing the
        // user asked for, never prep instead of it.
        expect(recipe.slice(-op.length)).toEqual(op);
        expect(recipe.length).toBeGreaterThan(op.length);
        // No survivable step anywhere in it. The refresh is the one this
        // module treats as best-effort, so it is the one that must not be here
        // — its failure would take the op down with it. Derived from
        // `marketplaceSteps` (prep is register-then-refresh) rather than
        // spelled: the hosts disagree about the verb — `marketplace update` on
        // Claude Code, `marketplace upgrade` on Codex — and a literal check
        // silently covers only whichever one it names.
        const refresh = manager
          .marketplaceSteps('owner/repo', 'm')
          .slice(1)
          .map((args) => `${bin} ${args.join(' ')}`);
        expect(refresh.length).toBeGreaterThan(0);
        for (const line of refresh) expect(recipe).not.toContain(line);
      }
    });
  }

  it('omits the prep when there is no marketplace source to name', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.installRecipe('p@m')).toEqual(rendered('codex', codex.installSteps('p@m')));
  });
});

// The survivable step still has to RUN somewhere, or moving it out of the op
// silently deleted it. It belongs to the automated path alone, which captures
// and discards each result instead of chaining on success.
describe('the snapshot refresh survives as best-effort prep', () => {
  // Both hosts, because both cache a snapshot. Asserted per host rather than in
  // a loop over a shared expectation: the verbs differ, and a loop that derived
  // the expected step from the module would pass whatever the module said.
  it('codex keeps it in marketplaceSteps, which apply.ts runs as prep', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.marketplaceSteps('akasecurity/ai-tc', 'ai-tc')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/ai-tc'],
      ['plugin', 'marketplace', 'upgrade', 'ai-tc'],
    ]);
  });

  it('claude keeps it too — registering alone does not reconcile the snapshot', () => {
    const claude = createCliPluginManager('claude');
    expect(claude.marketplaceSteps('akasecurity/marketplace', 'akasecurity')).toEqual([
      ['plugin', 'marketplace', 'add', 'akasecurity/marketplace'],
      ['plugin', 'marketplace', 'update', 'akasecurity'],
    ]);
  });
});

// The spawn plan is the DISCLOSURE render — what the dashboard's confirm dialog
// promises will run. Its whole job is to omit nothing, which makes it the exact
// opposite of a recipe: it must carry the survivable refresh that a recipe must
// not. Getting these two backwards is silent in both directions — a dialog that
// under-reports, or a copy-paste line that dies on a git fetch — so pin the
// difference rather than either one alone.
describe('the spawn plan discloses every command the automated path runs', () => {
  it('codex: prep (both steps) then the op', () => {
    const codex = createCliPluginManager('codex');
    expect(codex.updateSpawnPlan('aka-codex@ai-tc', 'akasecurity/ai-tc', 'ai-tc')).toEqual([
      'codex plugin marketplace add akasecurity/ai-tc',
      'codex plugin marketplace upgrade ai-tc',
      'codex plugin add aka-codex@ai-tc',
    ]);
  });

  it('matches what apply.ts actually spawns: marketplaceSteps then the op', () => {
    for (const bin of ['claude', 'codex'] as const) {
      const m = createCliPluginManager(bin);
      expect(m.updateSpawnPlan('p@m', 'owner/repo', 'm')).toEqual([
        ...rendered(bin, m.marketplaceSteps('owner/repo', 'm')),
        ...rendered(bin, m.updateSteps('p@m')),
      ]);
      expect(m.installSpawnPlan('p@m', 'owner/repo', 'm')).toEqual([
        ...rendered(bin, m.marketplaceSteps('owner/repo', 'm')),
        ...rendered(bin, m.installSteps('p@m')),
      ]);
    }
  });

  it('is strictly wider than the recipe wherever a refresh exists', () => {
    const codex = createCliPluginManager('codex');
    const plan = codex.updateSpawnPlan('p@m', 'owner/repo', 'm');
    const recipe = codex.updateRecipe('p@m', 'owner/repo');
    // The refresh is the difference, and it belongs to exactly one of them.
    expect(plan.some((l) => l.includes('marketplace upgrade'))).toBe(true);
    expect(recipe.some((l) => l.includes('marketplace upgrade'))).toBe(false);
    expect(plan.length).toBeGreaterThan(recipe.length);
  });
});
