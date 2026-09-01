// Prohibited-model governance for Codex, decision-only. Pure logic plus bounded
// reads, so it unit-tests without a hook process — hook ENTRY files run main()
// on import and must never be imported by tests (the same split as
// pre-tool-use-decision.ts).
//
// CODEX ENFORCES ONE HALF OF WHAT CLAUDE CODE DOES, and the gap is the host's
// rather than a shortcut. Codex exposes no model-switch event, so a switch
// cannot be refused before it takes effect; what is left is refusing a TURN
// whose session is already on a prohibited model. A user who switches keeps the
// model for the rest of the current turn and is refused from the next one.
import {
  codexModelFromRecord,
  modelFromTranscriptTail,
  readSessionModel,
} from '@akasecurity/plugin-sdk';

/**
 * The model this Codex session is running on, or undefined when it cannot be
 * told.
 *
 * The marker first, written by the Stop hook once a turn has completed, then
 * the rollout transcript. Codex names the model on a `turn_context` record
 * rather than per response, so the transcript answers as soon as one turn has
 * been recorded.
 *
 * Undefined is a real and expected answer on the FIRST turn of a session: no
 * turn has completed, so neither source can speak. That turn is allowed. It is
 * the known hole in this control on this host, and it is wider than Claude
 * Code's — there, a `SessionStart` model and a refusable switch can both close
 * it, and Codex has neither.
 */
export function resolveCodexSessionModel(
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): string | undefined {
  return (
    readSessionModel(dataDir, sessionId) ??
    modelFromTranscriptTail(transcriptPath, codexModelFromRecord)
  );
}
