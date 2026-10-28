import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { ATTACHED_CAPTURE_SETTINGS_FILENAME } from '@akasecurity/persistence';
import { DATA_FILE_MODE, ensureDataDir } from '@akasecurity/plugin-sdk';
import type { CaptureSettings } from '@akasecurity/schema';
import { CaptureSettings as CaptureSettingsSchema } from '@akasecurity/schema';

import { publishByRename } from './atomic-publish.ts';

/** The capture settings a hook acts on without opening the policy cache. */
export type HookCaptureSettings = Pick<CaptureSettings, 'toolOutput' | 'sessionHold'>;

const HookCaptureSettingsSchema = CaptureSettingsSchema.pick({
  toolOutput: true,
  sessionHold: true,
});

/**
 * Writes the hook half of `capture` beside the policy cache, or removes the
 * file when the bundle sets nothing a hook reads. The review-value list stays
 * in the cache: only the gateway reads it.
 */
export async function writeHookCaptureSettings(
  dir: string,
  capture: CaptureSettings | undefined,
): Promise<void> {
  const file = join(dir, ATTACHED_CAPTURE_SETTINGS_FILENAME);
  const settings: HookCaptureSettings = {
    ...(capture?.toolOutput === undefined ? {} : { toolOutput: capture.toolOutput }),
    ...(capture?.sessionHold === undefined ? {} : { sessionHold: capture.sessionHold }),
  };
  if (Object.keys(settings).length === 0) {
    await rm(file, { force: true });
    return;
  }
  await ensureDataDir(dir);
  const tmp = `${file}.${randomUUID()}.tmp`;
  try {
    await writeFile(tmp, JSON.stringify({ v: 1, ...settings }), {
      encoding: 'utf8',
      mode: DATA_FILE_MODE,
      flag: 'wx',
    });
    await publishByRename(tmp, file);
  } catch (err) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
}

/** The settings on disk, or none: a missing, unreadable or malformed file sets nothing. */
export function readHookCaptureSettings(dir: string): HookCaptureSettings {
  try {
    const raw: unknown = JSON.parse(
      readFileSync(join(dir, ATTACHED_CAPTURE_SETTINGS_FILENAME), 'utf8'),
    );
    if (typeof raw !== 'object' || raw === null || (raw as { v?: unknown }).v !== 1) return {};
    const parsed = HookCaptureSettingsSchema.safeParse(raw);
    return parsed.success ? parsed.data : {};
  } catch {
    return {};
  }
}

/**
 * The forward mark for a capture keyed `repoKey`: the tool output cap, unless
 * the setting names repositories and this key is not one of them.
 */
export function toolOutputForwardFor(
  settings: HookCaptureSettings,
  repoKey: string | undefined,
): { maxChars: number } | undefined {
  const toolOutput = settings.toolOutput;
  if (toolOutput === undefined) return undefined;
  if (
    toolOutput.repos !== undefined &&
    (repoKey === undefined || !toolOutput.repos.includes(repoKey))
  ) {
    return undefined;
  }
  return { maxChars: toolOutput.maxChars };
}
