// Pure reconcile-trigger parsing, split out of the `stop.ts` / `post-tool-use.ts`
// entry scripts so it can be unit-tested WITHOUT importing an entry (whose
// top-level main() reads stdin and would block test collection forever). Hooks
// stay thin glue; their logic is tested here.
//
// Antigravity names the two fields the reconcile worker needs `conversationId`
// and `transcriptPath` (camelCase), where Claude Code and Codex send
// `session_id` and `transcript_path`. Both Stop and PostToolUse carry them, so
// one parser serves both.
import { getString } from './shared.ts';

export interface ReconcileTrigger {
  sessionId: string;
  transcriptPath: string;
}

// Pull the two fields the reconcile worker needs. Returns undefined when either
// is missing/non-string so the caller fails open (no spawn) — a payload without
// a transcript path or conversation id can't be reconciled.
export function parseReconcileTrigger(
  input: Record<string, unknown> | null,
): ReconcileTrigger | undefined {
  if (input === null) return undefined;
  const sessionId = getString(input, 'conversationId');
  const transcriptPath = getString(input, 'transcriptPath');
  if (sessionId === undefined || transcriptPath === undefined) return undefined;
  return { sessionId, transcriptPath };
}
