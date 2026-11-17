// Rewrites credential values injected in a session back to their handles in
// that session's transcript file. Claude Code records the PreToolUse answer,
// substituted input included, in the transcript, and a tool's output may echo a
// value. The rewrite goes through the at-rest transcript scrub, so it keeps the
// file valid JSONL, leaves untouched lines byte-identical, only touches files
// inside the transcript root, and gives up on a file that changed while it ran.
// The values come from this process's memory and are never written anywhere.
import type { CredentialSlug } from '@akasecurity/schema';
import { formatCredentialHandle } from '@akasecurity/schema';

import { scrubTranscriptTail } from '../history/tail-scrub.ts';
import { platformRedactionScope } from '../remediation/redact.ts';
import { valueScrubber } from './handles.ts';
import { sessionsWithValues } from './session-credentials.ts';

/** When a scheduled pass runs, after the call that scheduled it. */
export const TRANSCRIPT_PASS_DELAYS_MS: readonly number[] = [1_500, 5_000, 20_000, 60_000];

export async function restoreHandlesInTranscript(
  transcriptPath: string,
  injected: ReadonlyMap<CredentialSlug, string>,
  scope: ReturnType<typeof platformRedactionScope> = platformRedactionScope(),
): Promise<{ rewritten: number } | null> {
  if (injected.size === 0) return { rewritten: 0 };
  const scrubber = valueScrubber(injected);
  return scrubTranscriptTail(transcriptPath, {
    tokenizeText: (text) => {
      const result = scrubber.scrub(text);
      return Promise.resolve({
        text: result.text,
        pointers: result.slugs.map((slug) => formatCredentialHandle(slug)),
        degraded: [],
        redacted: [],
      });
    },
    scope,
  });
}

export interface TranscriptSweeper {
  /** Runs the pass for this session's transcript at each of the delays, starting over on each call. */
  schedule(sessionId: string | undefined): void;
  /** Cancels what is scheduled and runs the pass once now for every session holding values. */
  flush(): Promise<void>;
}

export function createTranscriptSweeper(
  options: {
    delaysMs?: readonly number[];
    restore?: typeof restoreHandlesInTranscript;
  } = {},
): TranscriptSweeper {
  const delays = options.delaysMs ?? TRANSCRIPT_PASS_DELAYS_MS;
  const restore = options.restore ?? restoreHandlesInTranscript;
  const timers = new Map<string, NodeJS.Timeout[]>();
  // One pass at a time per process: the scrub's temporary file is named per
  // process, so two passes over one transcript must not overlap.
  let running: Promise<void> = Promise.resolve();

  const passFor = (sessionId: string): Promise<void> => {
    running = running.then(async () => {
      try {
        const entry = sessionsWithValues().find((s) => s.sessionId === sessionId);
        const path = entry?.credentials.transcriptPath;
        if (entry === undefined || path === undefined) return;
        await restore(path, entry.credentials.values);
      } catch {
        // A pass that cannot run is retried by the next one.
      }
    });
    return running;
  };

  const cancel = (sessionId: string): void => {
    for (const timer of timers.get(sessionId) ?? []) clearTimeout(timer);
    timers.delete(sessionId);
  };

  return {
    schedule(sessionId) {
      if (sessionId === undefined || sessionId === '') return;
      cancel(sessionId);
      timers.set(
        sessionId,
        delays.map((delay) => {
          const timer = setTimeout(() => {
            void passFor(sessionId);
          }, delay);
          timer.unref();
          return timer;
        }),
      );
    },
    async flush() {
      for (const sessionId of [...timers.keys()]) cancel(sessionId);
      for (const { sessionId } of sessionsWithValues()) await passFor(sessionId);
    },
  };
}
