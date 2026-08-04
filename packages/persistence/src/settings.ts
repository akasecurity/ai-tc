import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { WorkspaceSettings } from '@akasecurity/schema';
import {
  defaultWorkspaceSettings,
  WorkspaceSettings as WorkspaceSettingsSchema,
} from '@akasecurity/schema';

import { withFileLock } from './file-lock.ts';
import { parseJsonObject } from './internal/json.ts';
import { defaultDataDir, settingsDir } from './local-layout.ts';
import { ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';

// Read/write of ~/.aka/settings/settings.json, shared by every local consumer
// — plugin hooks, the CLI, and the web-ui; the SDK re-exports these. The
// env-dependent half of config loading (provider resolution) stays in the SDK,
// which composes these readers into its PluginConfig. A config.json written by
// an earlier release may sit alongside settings.json; nothing reads it.

export const SETTINGS_FILENAME = 'settings.json';

/**
 * Read settings.json under the base, default-filled when absent. Fully
 * fail-open: a missing or corrupt file yields unonboarded defaults rather than
 * throwing — this sits on the plugin's fail-open hook path. A pure reader with no
 * side effects: the at-rest mode is self-healed by the write/init/loadConfig
 * paths (see `aka init`'s ungated tighten and `loadConfig`), not on every read,
 * so a web-ui page render never chmods.
 */
export function readWorkspaceSettings(base: string = defaultDataDir()): WorkspaceSettings {
  const record = readJson(join(settingsDir(base), SETTINGS_FILENAME));
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
 * The answers to apply, either directly or derived from what is already on
 * disk. The function form is the one to reach for whenever an answer depends on
 * a current value — it runs INSIDE the write lock, so the settings it is handed
 * are the ones the merge is about to be applied to. Reading first and passing a
 * plain object puts that read outside the lock, which is the lost update this
 * writer exists to prevent, one caller further out.
 */
export type OnboardingAnswers =
  Partial<WorkspaceSettings> | ((current: WorkspaceSettings) => Partial<WorkspaceSettings>);

/**
 * Persist onboarding answers to settings.json (the /aka:setup writer, and the
 * web-ui settings page). Merges over the existing file so each edit is
 * additive, re-validates through the versioned schema, and stamps onboardedAt
 * on first completion so `onboarded` flips true. Owner-only atomic write (tmp +
 * rename), so a settings.json (or a leftover `.tmp` from an earlier crash) that
 * pre-existed with looser permissions ends 0600 rather than carrying its mode
 * through the rename — see writeOwnerOnlyFileSync.
 *
 * The read, the merge and the write are ONE critical section, held against
 * every other process on the machine (see withFileLock). tmp+rename alone makes
 * each publish indivisible but leaves the pair of them interleavable: the
 * wizard and the dashboard's Settings page are separate processes over one
 * file, and without the lock both read the same bytes and the second rename
 * discards the first one's answers with nothing raised at either end. The
 * fields at stake include the vault and model-judge consent grants, where the
 * lost write can be a REVOCATION — silently reinstating an egress the user
 * just withdrew.
 *
 * Throws rather than writing unlocked if the lock cannot be taken (see
 * FileLockError). Both callers surface that: the wizard exits non-zero with the
 * message, and the Settings action renders a save failure.
 */
export function applyOnboarding(
  answers: OnboardingAnswers,
  base: string = defaultDataDir(),
): WorkspaceSettings {
  const dir = settingsDir(base);
  // Ahead of the lock, not inside it: the lock file is a sibling of
  // settings.json, so the directory has to exist before one can be taken.
  ensureDataDirSync(dir);
  const file = join(dir, SETTINGS_FILENAME);
  return withFileLock(file, () => {
    const current = readWorkspaceSettings(base);
    const applied = typeof answers === 'function' ? answers(current) : answers;
    const merged = WorkspaceSettingsSchema.parse({
      ...current,
      ...applied,
      // First setup stamps the time; later edits keep the original completion mark.
      onboardedAt: applied.onboardedAt ?? current.onboardedAt ?? new Date().toISOString(),
    });
    writeOwnerOnlyFileSync(file, `${JSON.stringify(merged, null, 2)}\n`);
    return merged;
  });
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
