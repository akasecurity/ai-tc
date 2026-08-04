import { binExists, runCapture, runInherit } from './exec.ts';

// Generic delegator onto a host CLI's own plugin manager — the supported way
// to install and update its plugins. The AKA CLI is a hub over these, never a
// reimplementation: each host CLI owns its own plugin cache, enable/disable
// state, and restart lifecycle.
//
// Parameterized by binary name because Claude Code (`claude`) and Codex CLI
// (`codex`) expose the SAME `<bin> plugin marketplace add|install|update`
// subcommand shape — confirmed for Codex against developers.openai.com/codex/
// plugins and the `codex-marketplace.com` docs. One factory avoids
// duplicating this thin wrapper per host; see claude-plugin.ts / codex-plugin.ts
// for the two bound instances the rest of local-ops imports.
export interface CliPluginManager {
  available: () => boolean;
  // Register the marketplace if it isn't already. `<bin> plugin marketplace add`
  // is idempotent enough for our purposes — a re-add of an existing marketplace
  // just errors, which we capture and ignore; the subsequent install/update is
  // what matters.
  ensureMarketplace: (source: string) => void;
  install: (ref: string) => boolean;
  update: (ref: string) => boolean;
}

export function createCliPluginManager(bin: string): CliPluginManager {
  return {
    available: () => binExists(bin),
    ensureMarketplace: (source: string) => {
      runCapture(bin, ['plugin', 'marketplace', 'add', source], 60_000);
    },
    install: (ref: string) => runInherit(bin, ['plugin', 'install', ref]),
    update: (ref: string) => runInherit(bin, ['plugin', 'update', ref]),
  };
}
