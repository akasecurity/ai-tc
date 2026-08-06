import { createCliPluginManager } from './cli-plugin-manager.ts';

// Bound `codex` instance of the generic cli-plugin-manager — the Codex CLI
// counterpart of claude-plugin.ts. Codex's `codex plugin marketplace add|
// install|update` subcommands are the same shape as Claude Code's `claude
// plugin …` ones, so this is a thin binding, not a reimplementation.
const manager = createCliPluginManager('codex');

export const codexAvailable = manager.available;
export const ensureCodexMarketplace = manager.ensureMarketplace;
export const installCodexPlugin = manager.install;
export const updateCodexPlugin = manager.update;
