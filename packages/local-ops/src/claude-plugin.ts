import { binExists, runCapture, runInherit } from './exec.ts';

// Delegators onto the `claude` CLI's plugin manager — the supported way to install
// and update Claude Code plugins. The AKA CLI is a hub over it, never a
// reimplementation: Claude Code owns the plugin cache, enable/disable state, and the
// restart lifecycle.

export function claudeAvailable(): boolean {
  return binExists('claude');
}

// Register the marketplace if it isn't already. `claude plugin marketplace add` is
// idempotent enough for our purposes — a re-add of an existing marketplace just
// errors, which we capture and ignore; the subsequent install/update is what matters.
export function ensureMarketplace(source: string): void {
  runCapture('claude', ['plugin', 'marketplace', 'add', source], 60_000);
}

export function installClaudePlugin(ref: string): boolean {
  return runInherit('claude', ['plugin', 'install', ref]);
}

export function updateClaudePlugin(ref: string): boolean {
  return runInherit('claude', ['plugin', 'update', ref]);
}
