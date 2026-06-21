import {
  applyOnboarding,
  defaultDataDir,
  migrateLegacyLayout,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import type { WorkspaceSettings } from '@akasecurity/schema';

import { dataDir, dbPath, settingsDir } from './data-dir.ts';
import type { ResolvedProvider } from './provider.ts';
import { resolveProvider } from './provider.ts';

// The settings file readers and writer live in @akasecurity/persistence
// (shared with the CLI and the web-ui); re-exported so the SDK's public
// surface is unchanged. What stays here is the env-dependent composition:
// provider resolution via ./provider.ts, which reads process.env.
export { applyOnboarding };

export interface PluginConfig {
  // Onboarding answers + prefs, default-filled when settings.json is absent.
  settings: WorkspaceSettings;
  // Resolved on-disk paths, so adapters never recompute the layout.
  dataDir: string;
  dbPath: string;
  settingsDir: string;
  // True once /aka:setup has recorded onboardedAt — drives the first-run nudge.
  onboarded: boolean;
  // The provider backend this session talks to (anthropic | bedrock | vertex |
  // gateway), resolved from the contemporaneous env via ./provider.ts. Resolved
  // here so SessionStart can snapshot it onto the
  // session-root as an immutable per-session fact (it can't reach the reconciler,
  // which runs detached without the session's env).
  provider: ResolvedProvider;
}

/**
 * Load the plugin config from ~/.aka. Env vars can't reach hooks (Claude Code
 * spawns them as bare processes), so a file is the only channel; read fresh on
 * every call because hook processes are short-lived. Fully fail-open: a missing
 * or corrupt settings.json yields unonboarded defaults rather than throwing.
 */
export function loadConfig(base: string = defaultDataDir()): PluginConfig {
  // First touch migrates any pre-layout flat files into settings/ (best-effort).
  migrateLegacyLayout(base);
  const settings = readWorkspaceSettings(base);
  return {
    settings,
    dataDir: dataDir(base),
    dbPath: dbPath(base),
    settingsDir: settingsDir(base),
    onboarded: settings.onboardedAt != null,
    provider: resolveProviderSafe(),
  };
}

/**
 * Resolve the provider from env, fail-safe. `resolveProvider` is already lenient
 * (it parses {} on a bad env), but we wrap it once more so a config load — on the
 * fail-open hook path — can never throw on an unexpected error; default to
 * Anthropic-direct, matching the module's fail-open style.
 */
function resolveProviderSafe(): ResolvedProvider {
  try {
    return resolveProvider();
  } catch {
    return { provider: 'anthropic' };
  }
}
