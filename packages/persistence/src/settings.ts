import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  WorkspaceSettings as WorkspaceSettingsSchema,
} from '@akasecurity/schema';

import { parseJsonObject } from './internal/json.ts';
import { defaultDataDir, settingsDir } from './local-layout.ts';
import { DATA_FILE_MODE, ensureDataDirSync } from './paths.ts';

// Read/write of ~/.aka/settings/settings.json, shared by every local consumer
// — plugin hooks, the CLI, and the web-ui; the SDK re-exports these. The
// env-dependent half of config loading (provider resolution) stays in the SDK,
// which composes these readers into its PluginConfig. A config.json written by
// an earlier release may sit alongside settings.json; nothing reads it.

/**
 * Read settings.json under the base, default-filled when absent. Fully
 * fail-open: a missing or corrupt file yields unonboarded defaults rather than
 * throwing — this sits on the plugin's fail-open hook path.
 */
export function readWorkspaceSettings(base: string = defaultDataDir()): WorkspaceSettings {
  const record = readJson(join(settingsDir(base), 'settings.json'));
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
 * on first completion so `onboarded` flips true. Atomic write (tmp + rename),
 * owner-only.
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
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(merged, null, 2)}\n`, { mode: DATA_FILE_MODE });
  renameSync(tmp, file);
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
