import { createCliPluginManager } from './cli-plugin-manager.ts';

// Bound `claude` instance of the generic cli-plugin-manager. Kept as its own
// module (rather than inlining `createCliPluginManager('claude')` at call
// sites) so `apply.ts` and the CLI commands keep their existing named imports
// — see codex-plugin.ts for the sibling `codex` instance.
const manager = createCliPluginManager('claude');

export const claudeAvailable = manager.available;
export const ensureMarketplace = manager.ensureMarketplace;
export const installClaudePlugin = manager.install;
export const updateClaudePlugin = manager.update;
