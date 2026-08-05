// Pure Stop-payload parsing, split out of the `stop.ts` entry script so it can be
// unit-tested WITHOUT importing the entry (whose top-level `main()` reads stdin and
// would block test collection forever). Hooks stay thin glue; their logic is tested
// here. See `stop.ts` for the runtime wiring. Identical to
// plugins/claude-code/src/hooks/stop-payload.ts — Codex's Stop payload carries
// the same session_id + transcript_path fields.
import { getString } from './shared.ts';

export interface StopTrigger {
  sessionId: string;
  transcriptPath: string;
}

// Pull the two fields the reconcile worker needs from a Stop payload. Returns
// undefined when either is missing/non-string so the caller fails open (no spawn) —
// a payload without a transcript path or session id can't be reconciled.
export function parseStopPayload(input: Record<string, unknown> | null): StopTrigger | undefined {
  if (input === null) return undefined;
  const sessionId = getString(input, 'session_id');
  const transcriptPath = getString(input, 'transcript_path');
  if (sessionId === undefined || transcriptPath === undefined) return undefined;
  return { sessionId, transcriptPath };
}
