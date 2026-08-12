import { createCliPluginManager } from './cli-plugin-manager.ts';

// Bound `codex` instance of the generic cli-plugin-manager — the Codex CLI
// counterpart of claude-plugin.ts. Codex's verbs differ from Claude Code's
// (`plugin add`, no `plugin update`); the factory holds the per-host table, so
// this stays a thin binding rather than a reimplementation.
const manager = createCliPluginManager('codex');

export const codexAvailable = manager.available;
export const ensureCodexMarketplace = manager.ensureMarketplace;
export const installCodexPlugin = manager.install;
export const updateCodexPlugin = manager.update;
