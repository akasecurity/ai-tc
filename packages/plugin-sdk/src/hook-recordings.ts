// Opt-in recording of what each hook run received and answered, for verifying
// a plugin against a live host.
//
// Off unless the directory `hook-recordings/` exists inside AKA's data
// directory (`~/.aka/data/hook-recordings/`); creating it turns recording on
// and removing it turns it off. While on, every call writes one file there
// holding the time, the event token, the raw stdin and the answer fields the
// plugin passes, spread beside them.
//
// A recording holds the payload exactly as the host sent it — prompts, tool
// arguments and tool output included, secrets and all — so each file is
// created owner-only and the directory is never created here. Recording never
// changes what the hook does: every failure is swallowed.
//
// Each name ends in random characters after the pid, so two runs in the same
// millisecond never collide; the exclusive create still refuses to overwrite.
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_FILE_MODE, dataDir } from './data-dir.ts';

/** The directory whose existence turns recording on, inside AKA's data directory. */
export const HOOK_RECORDINGS_DIR_NAME = 'hook-recordings';

/** The fields every recording carries, whatever the plugin records beside them. */
export interface HookRecordingBase {
  recordedAt: string;
  /** The event token argv carried, if any. */
  event: string | null;
  /** The stdin payload, parsed when it is JSON and kept as text otherwise. */
  stdin: unknown;
}

export interface RecordHookRunOptions {
  /** The recordings directory; defaults to `hook-recordings/` in the data directory. */
  dir?: string | undefined;
  now?: Date | undefined;
}

function parsedOrText(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

/**
 * Write one recording when the recordings directory exists. Returns the file
 * written, or `undefined` when recording is off or the write failed.
 */
export function recordHookRun(
  event: string | undefined,
  stdin: string,
  answer: Record<string, unknown>,
  options: RecordHookRunOptions = {},
): string | undefined {
  try {
    // Resolved inside the try, so a home it cannot resolve is swallowed too.
    const dir = options.dir ?? join(dataDir(), HOOK_RECORDINGS_DIR_NAME);
    if (!existsSync(dir)) return undefined;
    const now = options.now ?? new Date();
    const recording: HookRecordingBase = {
      recordedAt: now.toISOString(),
      event: event ?? null,
      stdin: parsedOrText(stdin),
    };
    const stamp = now.toISOString().replaceAll(':', '-');
    const suffix = randomBytes(4).toString('hex');
    const file = join(dir, `${stamp}-${event ?? 'unknown'}-${String(process.pid)}-${suffix}.json`);
    writeFileSync(file, `${JSON.stringify({ ...recording, ...answer }, null, 2)}\n`, {
      mode: DATA_FILE_MODE,
      flag: 'wx',
    });
    return file;
  } catch {
    return undefined;
  }
}
