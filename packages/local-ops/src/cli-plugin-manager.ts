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
// takes `add` and has no update verb at all, so a refresh there is a
// `marketplace upgrade` of the snapshot followed by a re-`add` (idempotent, and
// it reinstalls whatever the refreshed snapshot carries). Only
// `plugin marketplace add <source>` is genuinely common to both.
export type CliPluginBin = 'claude' | 'codex';

// One command's argv, minus the binary. A step list rather than a single argv
// because a Codex update is two commands.
type Step = readonly string[];

interface HostVerbs {
  install: (ref: string) => Step[];
  update: (ref: string, marketplace: string | undefined) => Step[];
}

const HOST_VERBS: Record<CliPluginBin, HostVerbs> = {
  claude: {
    install: (ref) => [['plugin', 'install', ref]],
    update: (ref) => [['plugin', 'update', ref]],
  },
  codex: {
    install: (ref) => [['plugin', 'add', ref]],
    update: (ref, marketplace) => [
      // Refresh the Git snapshot first — `add` installs from the snapshot, so
      // without this an update reinstalls the version already on disk. Skipped
      // when the caller has no marketplace name to name.
      ...(marketplace ? [['plugin', 'marketplace', 'upgrade', marketplace] as Step] : []),
      ['plugin', 'add', ref],
    ],
  },
};

export interface CliPluginManager {
  available: () => boolean;
  // Register the marketplace if it isn't already. `<bin> plugin marketplace add`
  // is idempotent enough for our purposes — a re-add of an existing marketplace
  // just errors, which we capture and ignore; the subsequent install/update is
  // what matters.
  ensureMarketplace: (source: string) => void;
  // The commands an install/update runs, in order. Exposed so a caller that
  // needs its own output mode (apply.ts streams or captures) and the hint copy
  // that tells a user what to type both come from ONE table — hint copy naming
  // a verb the host rejects is exactly how this bug reached a user's terminal.
  installSteps: (ref: string) => Step[];
  updateSteps: (ref: string, marketplace?: string) => Step[];
  // The same steps rendered as copy-pasteable command lines.
  installCommands: (ref: string) => string[];
  updateCommands: (ref: string, marketplace?: string) => string[];
  install: (ref: string) => boolean;
  update: (ref: string, marketplace?: string) => boolean;
}

export function createCliPluginManager(bin: CliPluginBin): CliPluginManager {
  const verbs = HOST_VERBS[bin];
  const runAll = (steps: Step[]): boolean => steps.every((args) => runInherit(bin, [...args]));

  return {
    available: () => binExists(bin),
    ensureMarketplace: (source: string) => {
      runCapture(bin, ['plugin', 'marketplace', 'add', source], 60_000);
    },
    installSteps: (ref) => verbs.install(ref),
    updateSteps: (ref, marketplace) => verbs.update(ref, marketplace),
    installCommands: (ref) => verbs.install(ref).map((args) => `${bin} ${args.join(' ')}`),
    updateCommands: (ref, marketplace) =>
      verbs.update(ref, marketplace).map((args) => `${bin} ${args.join(' ')}`),
    install: (ref) => runAll(verbs.install(ref)),
    update: (ref, marketplace) => runAll(verbs.update(ref, marketplace)),
  };
}
