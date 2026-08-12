import { binExists, runCapture, runInherit } from './exec.ts';

// Generic delegator onto a host CLI's own plugin manager — the supported way
// to install and update its plugins. The AKA CLI is a hub over these, never a
// reimplementation: each host CLI owns its own plugin cache, enable/disable
// state, and restart lifecycle.
//
// The hosts share the SHAPE (`<bin> plugin …`) but NOT the verbs, and assuming
// they did is the defect this replaced — every Codex install and update emitted
// `codex plugin install|update`, which Codex rejects outright with
// "unrecognized subcommand". Claude Code takes `install` and `update`; Codex
// takes `add` for both, having no update verb at all (`add` re-resolves the
// plugin, so a refresh IS a re-add).
//
// Two kinds of command come out of this table and they are NOT interchangeable:
//
//   - the PLUGIN OP (`installSteps`/`updateSteps`) — what the user asked for.
//     A failure here is the operation failing, so apply.ts runs it fatally.
//   - MARKETPLACE PREP (`marketplaceSteps`) — registering the source, and for a
//     host whose `add` reads a local snapshot, refreshing that snapshot. This is
//     best-effort: it is a precondition that is usually already met, and a
//     transient failure (offline, a git fetch error, a marketplace registered
//     from a source that cannot be upgraded) must not abort an operation that
//     would have succeeded against the cached snapshot.
export type CliPluginBin = 'claude' | 'codex';

// One command's argv, minus the binary. A step list rather than a single argv
// because Codex's marketplace prep is two commands.
type Step = readonly string[];

interface HostVerbs {
  install: (ref: string) => Step[];
  update: (ref: string) => Step[];
  // Registering the marketplace. REQUIRED before the op — without it the op
  // fails on an unknown marketplace — so a failure here genuinely should stop
  // whatever follows.
  register: (source: string) => Step[];
  // Refreshing an already-registered snapshot. Optional, and empty on a host
  // that keeps no snapshot. A failure here is survivable: the cached snapshot
  // stays in place and the op can still run against it.
  refresh: (marketplace: string) => Step[];
}

const HOST_VERBS: Record<CliPluginBin, HostVerbs> = {
  claude: {
    install: (ref) => [['plugin', 'install', ref]],
    update: (ref) => [['plugin', 'update', ref]],
    register: (source) => [['plugin', 'marketplace', 'add', source]],
    refresh: () => [],
  },
  codex: {
    install: (ref) => [['plugin', 'add', ref]],
    // No `update` verb — `add` is the whole operation. It resolves the plugin
    // from the marketplace manifest, which for this repo's entries names an npm
    // package with no version pin, so `add` picks up a published bump on its
    // own. Refreshing the git snapshot is about the MANIFEST (a renamed package,
    // a newly listed plugin), which is why it is a separate, optional step.
    update: (ref) => [['plugin', 'add', ref]],
    register: (source) => [['plugin', 'marketplace', 'add', source]],
    refresh: (marketplace) => [['plugin', 'marketplace', 'upgrade', marketplace]],
  },
};

export interface CliPluginManager {
  available: () => boolean;
  // Bring the marketplace up to date, best-effort: register the source if it
  // isn't already, then refresh the snapshot on a host that keeps one. Every
  // step's result is captured and discarded — a re-add of an existing
  // marketplace is a no-op that reports success, and a refresh that fails
  // leaves the cached snapshot in place, which the plugin op can still use.
  ensureMarketplace: (source: string, marketplace?: string) => void;
  // The commands an install/update runs, in order. Exposed so a caller that
  // needs its own output mode (apply.ts streams or captures) and the hint copy
  // that tells a user what to type both come from ONE table — hint copy naming
  // a verb the host rejects is exactly how this bug reached a user's terminal.
  marketplaceSteps: (source: string, marketplace?: string) => Step[];
  installSteps: (ref: string) => Step[];
  updateSteps: (ref: string) => Step[];
  // The same steps rendered as copy-pasteable command lines.
  installCommands: (ref: string) => string[];
  updateCommands: (ref: string) => string[];
  // The MANUAL EQUIVALENT: what a user runs by hand to reach the same state —
  // register the marketplace, then the op. Shown where the automated path can't
  // run or may be interrupted, so every caller joins it with `&&`.
  //
  // Which means it must carry ONLY steps whose failure should stop the chain.
  // The snapshot refresh is deliberately absent: it is the one step this module
  // treats as survivable, and `&&` cannot express that — a git-fetch error on
  // `marketplace upgrade` would short-circuit the `plugin add` that is the whole
  // point. It is also redundant here, because `marketplace add` clones the
  // snapshot fresh on the machine this copy is written for. Leaving it in was a
  // real defect: it made best-effort prep fatal in exactly the line a user
  // retypes, while the code path went on treating the same failure as harmless.
  installRecipe: (ref: string, source?: string) => string[];
  updateRecipe: (ref: string, source?: string) => string[];
  // Everything the AUTOMATED path spawns, in order: prep (both steps) then the
  // op. This is the disclosure render — a confirm dialog saying "this runs the
  // following on your machine" is a promise, and naming one of three spawns
  // breaks it in a product whose whole pitch is that you can see what runs.
  //
  // NOT interchangeable with a recipe, and never to be joined with `&&`: it
  // deliberately includes the survivable refresh, whose failure the automated
  // path ignores and `&&` would not. Join with a newline and show it as a list.
  installSpawnPlan: (ref: string, source?: string, marketplace?: string) => string[];
  updateSpawnPlan: (ref: string, source?: string, marketplace?: string) => string[];
  install: (ref: string) => boolean;
  update: (ref: string) => boolean;
}

export function createCliPluginManager(bin: CliPluginBin): CliPluginManager {
  const verbs = HOST_VERBS[bin];
  const runAll = (steps: Step[]): boolean => steps.every((args) => runInherit(bin, [...args]));
  const render = (steps: Step[]): string[] => steps.map((args) => `${bin} ${args.join(' ')}`);
  const marketplaceSteps = (source: string, marketplace?: string): Step[] => [
    ...verbs.register(source),
    ...(marketplace ? verbs.refresh(marketplace) : []),
  ];
  // Register-then-op only. See `installRecipe` on why the refresh stays out.
  const recipe = (steps: Step[], source: string | undefined): string[] =>
    render([...(source ? verbs.register(source) : []), ...steps]);
  // Prep-then-op, refresh included — what `apply.ts` really spawns.
  const spawnPlan = (
    steps: Step[],
    source: string | undefined,
    marketplace: string | undefined,
  ): string[] => render([...(source ? marketplaceSteps(source, marketplace) : []), ...steps]);

  return {
    available: () => binExists(bin),
    ensureMarketplace: (source, marketplace) => {
      for (const args of marketplaceSteps(source, marketplace)) {
        runCapture(bin, [...args], 60_000);
      }
    },
    marketplaceSteps,
    installSteps: (ref) => verbs.install(ref),
    updateSteps: (ref) => verbs.update(ref),
    installCommands: (ref) => render(verbs.install(ref)),
    updateCommands: (ref) => render(verbs.update(ref)),
    installRecipe: (ref, source) => recipe(verbs.install(ref), source),
    updateRecipe: (ref, source) => recipe(verbs.update(ref), source),
    installSpawnPlan: (ref, source, marketplace) =>
      spawnPlan(verbs.install(ref), source, marketplace),
    updateSpawnPlan: (ref, source, marketplace) =>
      spawnPlan(verbs.update(ref), source, marketplace),
    install: (ref) => runAll(verbs.install(ref)),
    update: (ref) => runAll(verbs.update(ref)),
  };
}
