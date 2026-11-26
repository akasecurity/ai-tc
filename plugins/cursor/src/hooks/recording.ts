// What this plugin records of each hook run, through the SDK's opt-in hook
// recordings (on while `~/.aka/data/hook-recordings/` exists): the output the
// handler wrote to stdout. Every path exits 0, so no exit code is recorded;
// notices written to stderr are not recorded either.
import type { HookRecordingBase } from '@akasecurity/plugin-sdk';
import { recordHookRun as writeRecording } from '@akasecurity/plugin-sdk';

import type { HookHandler, HookOutput } from './shared.ts';

/** One recorded hook run. */
export interface HookRecording extends HookRecordingBase {
  /** What the handler wrote to stdout; `null` is a hook that said nothing. */
  output: HookOutput | null;
}

/**
 * Record one hook run when recording is on. Returns the file written, or
 * `undefined` when recording is off or the write failed.
 */
export function recordHookRun(
  event: string | undefined,
  stdin: string,
  output: HookOutput | undefined,
  recordingsDir?: string,
  now?: Date,
): string | undefined {
  return writeRecording(event, stdin, { output: output ?? null }, { dir: recordingsDir, now });
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
