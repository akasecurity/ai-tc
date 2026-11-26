// What this plugin records of each hook run, through the SDK's opt-in hook
// recordings (on while `~/.aka/data/hook-recordings/` exists): the verdict the
// handler returned and the exit code `runHookFailOpen` ends it with.
import type { HookRecordingBase } from '@akasecurity/plugin-sdk';
import { recordHookRun as writeRecording } from '@akasecurity/plugin-sdk';

import type { HookVerdict } from './shared.ts';
import { PROMPT_BLOCK_EXIT_CODE } from './shared.ts';

/** One recorded hook run. */
export interface HookRecording extends HookRecordingBase {
  /** What the handler returned; `null` is a hook that said nothing. */
  verdict: HookVerdict | null;
  /** The exit code the verdict ends in. */
  exitCode: number;
}

/** The exit code `runHookFailOpen` ends a verdict with. */
export function exitCodeFor(verdict: HookVerdict | undefined): number {
  return verdict !== undefined && 'promptBlock' in verdict ? PROMPT_BLOCK_EXIT_CODE : 0;
}

/**
 * Record one hook run when recording is on. Returns the file written, or
 * `undefined` when recording is off or the write failed.
 */
export function recordHookRun(
  event: string | undefined,
  stdin: string,
  verdict: HookVerdict | undefined,
  recordingsDir?: string,
  now?: Date,
): string | undefined {
  return writeRecording(
    event,
    stdin,
    { verdict: verdict ?? null, exitCode: exitCodeFor(verdict) },
    { dir: recordingsDir, now },
  );
}
