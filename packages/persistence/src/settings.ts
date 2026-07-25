import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  WorkspaceSettings as WorkspaceSettingsSchema,
} from '@akasecurity/schema';

import { parseJsonObject } from './internal/json.ts';
import { defaultDataDir, settingsDir } from './local-layout.ts';
import { ensureDataDirSync, tightenFile, writeOwnerOnlyFileSync } from './paths.ts';

// Read/write of ~/.aka/settings/settings.json, shared by every local consumer
// — plugin hooks, the CLI, and the web-ui; the SDK re-exports these. The
// env-dependent half of config loading (provider resolution) stays in the SDK,
// which composes these readers into its PluginConfig. A config.json written by
// an earlier release may sit alongside settings.json; nothing reads it.

/**
 * Read settings.json under the base, default-filled when absent. Fully
 * fail-open: a missing or corrupt file yields unonboarded defaults rather than
 * throwing — this sits on the plugin's fail-open hook path.
 *
 * Self-heals the at-rest mode on read: a settings.json left group/other-readable
 * by an older release (or the pre-fix leftover-`.tmp` bug) is re-tightened to
 * 0600 whenever any consumer — plugin hook, CLI, or web-ui — reads it, mirroring
 * how the fingerprint key self-heals on load and the db on open. Best-effort and
 * only when the file exists, so an unonboarded read stays a pure no-op.
 */
export function readWorkspaceSettings(base: string = defaultDataDir()): WorkspaceSettings {
  const file = join(settingsDir(base), 'settings.json');
  if (existsSync(file)) tightenFile(file);
  const record = readJson(file);
  if (!record) return defaultWorkspaceSettings();
  try {
    // The schema default-fills every missing key, so an older settings.json
    // written before a new field was added still parses.
    return WorkspaceSettingsSchema.parse(record);
  } catch {
    // Corrupt/invalid → behave as unonboarded rather than break the hook path.
    return defaultWorkspaceSettings();
  }
}

/**
 * Persist onboarding answers to settings.json (the /aka:setup writer, and the
 * web-ui settings page). Merges over the existing file so each edit is
 * additive, re-validates through the versioned schema, and stamps onboardedAt
 * on first completion so `onboarded` flips true. Owner-only atomic write (tmp +
 * rename), so a settings.json (or a leftover `.tmp` from an earlier crash) that
 * pre-existed with looser permissions ends 0600 rather than carrying its mode
 * through the rename — see writeOwnerOnlyFileSync.
 */
export function applyOnboarding(
  answers: Partial<WorkspaceSettings>,
  base: string = defaultDataDir(),
): WorkspaceSettings {
  const dir = settingsDir(base);
  const current = readWorkspaceSettings(base);
  const merged = WorkspaceSettingsSchema.parse({
    ...current,
    ...answers,
    // First setup stamps the time; later edits keep the original completion mark.
    onboardedAt: answers.onboardedAt ?? current.onboardedAt ?? new Date().toISOString(),
  });
  ensureDataDirSync(dir);
  const file = join(dir, 'settings.json');
  writeOwnerOnlyFileSync(file, `${JSON.stringify(merged, null, 2)}\n`);
  return merged;
}

function readJson(file: string): Record<string, unknown> | null {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  return parseJsonObject(text) ?? null;
}
