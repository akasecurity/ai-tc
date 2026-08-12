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
  marketplace: (source: string, marketplace: string | undefined) => Step[];
}

const HOST_VERBS: Record<CliPluginBin, HostVerbs> = {
  claude: {
    install: (ref) => [['plugin', 'install', ref]],
    update: (ref) => [['plugin', 'update', ref]],
    marketplace: (source) => [['plugin', 'marketplace', 'add', source]],
  },
  codex: {
    install: (ref) => [['plugin', 'add', ref]],
    // No `update` verb — `add` is the whole operation. It resolves the plugin
    // from the marketplace manifest, which for this repo's entries names an npm
    // package with no version pin, so `add` picks up a published bump on its
    // own. Refreshing the git snapshot is about the MANIFEST (a renamed package,
    // a newly listed plugin), which is why it sits in the prep below rather than
    // gating the op.
    update: (ref) => [['plugin', 'add', ref]],
    marketplace: (source, marketplace) => [
      ['plugin', 'marketplace', 'add', source],
      // Only names a configured marketplace, so it is skipped when the caller
      // has no name to pass.
      ...(marketplace ? [['plugin', 'marketplace', 'upgrade', marketplace] as Step] : []),
    ],
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
  // The whole recipe — marketplace prep followed by the plugin op — for the
  // hints shown when the host CLI is NOT on PATH. That branch is reached on a
  // machine where the marketplace has almost certainly never been registered,
  // so a hint carrying only the op hands the user a line that cannot work.
  installRecipe: (ref: string, source?: string, marketplace?: string) => string[];
  updateRecipe: (ref: string, source?: string, marketplace?: string) => string[];
  install: (ref: string) => boolean;
  update: (ref: string) => boolean;
}

export function createCliPluginManager(bin: CliPluginBin): CliPluginManager {
  const verbs = HOST_VERBS[bin];
  const runAll = (steps: Step[]): boolean => steps.every((args) => runInherit(bin, [...args]));
  const render = (steps: Step[]): string[] => steps.map((args) => `${bin} ${args.join(' ')}`);
  const marketplaceSteps = (source: string, marketplace?: string): Step[] =>
    verbs.marketplace(source, marketplace);
  const recipe = (
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
    installRecipe: (ref, source, marketplace) => recipe(verbs.install(ref), source, marketplace),
    updateRecipe: (ref, source, marketplace) => recipe(verbs.update(ref), source, marketplace),
    install: (ref) => runAll(verbs.install(ref)),
    update: (ref) => runAll(verbs.update(ref)),
  };
}
