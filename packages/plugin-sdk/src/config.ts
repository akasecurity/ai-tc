import { existsSync } from 'node:fs';
import { join } from 'node:path';

import {
  applyOnboarding,
  defaultDataDir,
  migrateLegacyLayout,
  readWorkspaceSettings,
  tightenFile,
} from '@akasecurity/persistence';
import type { WorkspaceSettings } from '@akasecurity/schema';

import { dataDir, dbPath, ensureDataDirSync, settingsDir } from './data-dir.ts';
import type { ResolvedProvider } from './provider.ts';
import { resolveProvider } from './provider.ts';
import type { ResolvedAntigravityProvider } from './provider-antigravity.ts';
import type { ResolvedCodexProvider } from './provider-codex.ts';

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
  // The provider backend this session talks to, resolved from the
  // contemporaneous env via ./provider.ts (Claude Code: anthropic | bedrock |
  // vertex | gateway) or ./provider-codex.ts (Codex CLI: openai | gateway) —
  // whichever resolver `loadConfig`'s caller passed. Resolved here so
  // SessionStart can snapshot it onto the session-root as an immutable
  // per-session fact (it can't reach the reconciler, which runs detached
  // without the session's env).
  provider: ResolvedProvider | ResolvedCodexProvider | ResolvedAntigravityProvider;
}

/**
 * Load the plugin config from ~/.aka. Env vars can't reach hooks (the host
 * spawns them as bare processes), so a file is the only channel; read fresh on
 * every call because hook processes are short-lived. Fully fail-open: a missing
 * or corrupt settings.json yields unonboarded defaults rather than throwing.
 *
 * `resolveProviderFn` defaults to Claude Code's `resolveProvider` for
 * backward compatibility with every existing call site. Each non-Claude plugin
 * passes its own resolver from the ONE hook that snapshots the provider onto
 * the session root — `resolveCodexProvider` from
 * plugins/codex/src/hooks/session-start.ts, `resolveAntigravityProvider` from
 * plugins/antigravity/src/hooks/pre-invocation.ts. Every other hook loads
 * config for its data dir / settings only and never reads `.provider`, so the
 * default is harmless there even though it's Claude-shaped.
 */
export function loadConfig(
  base: string = defaultDataDir(),
  resolveProviderFn: () =>
    ResolvedProvider | ResolvedCodexProvider | ResolvedAntigravityProvider = resolveProvider,
): PluginConfig {
  // Self-heal the store's at-rest modes on the plugin's entry path, so a
  // group/other-readable base or settings.json left by an older release (or the
  // pre-fix leftover-.tmp bug) is repaired on the next hook — the read-path
  // equivalent of the key self-healing on load and the db on open. Kept here, not
  // in readWorkspaceSettings, so that reader stays pure and a web-ui page render
  // never chmods. Best-effort and fail-open — a hook must never break on a home
  // it can't create.
  try {
    // openLocalDatabase only ensures the data/ leaf, so the base itself is
    // tightened here (creating it if absent).
    ensureDataDirSync(base);
    const settingsFile = join(settingsDir(base), 'settings.json');
    if (existsSync(settingsFile)) tightenFile(settingsFile);
  } catch {
    // fail-open: the readers below treat a missing home as unonboarded defaults
  }
  // First touch migrates any pre-layout flat files into settings/ (best-effort).
  migrateLegacyLayout(base);
  const settings = readWorkspaceSettings(base);
  return {
    settings,
    dataDir: dataDir(base),
    dbPath: dbPath(base),
    settingsDir: settingsDir(base),
    onboarded: settings.onboardedAt != null,
    provider: resolveProviderSafe(resolveProviderFn),
  };
}

/**
 * Run the given resolver fail-safe. All three resolvers (`resolveProvider`,
 * `resolveCodexProvider`, `resolveAntigravityProvider`) are already lenient
 * (they parse {} on a bad env), but we wrap once more so a config load — on
 * the fail-open hook path — can never throw on an unexpected error; default to
 * Anthropic-direct, matching the module's original fail-open default (harmless
 * for a Codex or Antigravity caller too, since this branch is only reached on a
 * genuinely unexpected resolver bug).
 */
function resolveProviderSafe(
  resolveProviderFn: () => ResolvedProvider | ResolvedCodexProvider | ResolvedAntigravityProvider,
): ResolvedProvider | ResolvedCodexProvider | ResolvedAntigravityProvider {
  try {
    return resolveProviderFn();
  } catch {
    return { provider: 'anthropic' };
  }
}
