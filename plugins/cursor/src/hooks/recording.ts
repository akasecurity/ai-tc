// Opt-in recording of what each hook run received and answered, for verifying
// this plugin against a live Cursor install.
//
// Off unless the directory `hook-recordings/` exists inside AKA's data
// directory (`~/.aka/data/hook-recordings/`); creating it turns recording on
// and removing it turns it off. While on, every hook run that reaches its
// handler's answer writes one file there holding the event token, the raw
// stdin and the output written to stdout. Every path exits 0, so no exit code
// is recorded; notices written to stderr are not recorded either.
//
// A recording holds the payload exactly as the host sent it — prompts, tool
// arguments and tool output included, secrets and all — so each file is
// created owner-only and the directory is never created here. Recording never
// changes what the hook does: every failure is swallowed.
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_FILE_MODE, dataDir } from '@akasecurity/plugin-sdk';

import type { HookHandler, HookOutput } from './shared.ts';

/** The directory whose existence turns recording on, inside AKA's data directory. */
export const RECORDINGS_DIR_NAME = 'hook-recordings';

/** One recorded hook run. */
export interface HookRecording {
  recordedAt: string;
  /** The event token argv carried, if any. */
  event: string | null;
  /** The stdin payload, parsed when it is JSON and kept as text otherwise. */
  stdin: unknown;
  /** What the handler wrote to stdout; `null` is a hook that said nothing. */
  output: HookOutput | null;
}

function parsedOrText(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw;
  }
}

/**
 * Write one recording when `<base>/hook-recordings/` exists. Returns the file
 * written, or `undefined` when recording is off or the write failed.
 */
export function recordHookRun(
  event: string | undefined,
  stdin: string,
  output: HookOutput | undefined,
  recordingsDir?: string,
  now: Date = new Date(),
): string | undefined {
  try {
    // Resolved inside the try, so a home it cannot resolve is swallowed too.
    const dir = recordingsDir ?? join(dataDir(), RECORDINGS_DIR_NAME);
    if (!existsSync(dir)) return undefined;
    const recording: HookRecording = {
      recordedAt: now.toISOString(),
      event: event ?? null,
      stdin: parsedOrText(stdin),
      output: output ?? null,
    };
    const stamp = now.toISOString().replaceAll(':', '-');
    const file = join(dir, `${stamp}-${event ?? 'unknown'}-${String(process.pid)}.json`);
    writeFileSync(file, `${JSON.stringify(recording, null, 2)}\n`, {
      mode: DATA_FILE_MODE,
      flag: 'wx',
    });
    return file;
  } catch {
    return undefined;
  }
}

/** Run the handler, record its answer when recording is on, and return the answer. */
export async function answerAndRecord(
  handler: HookHandler,
  event: string | undefined,
  stdin: string,
  recordingsDir?: string,
): Promise<HookOutput | undefined> {
  const output = await handler(event, stdin);
  recordHookRun(event, stdin, output, recordingsDir);
  return output;
}
