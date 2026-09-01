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
import { randomUUID } from 'node:crypto';

import type { DataGateway } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';
import {
  buildModelRefusalEvent,
  codexModelFromRecord,
  decideProhibitedModelTurn,
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

/**
 * Resolve this session's model against the bundle's prohibition list, and
 * return the refusal when there is one.
 *
 * Importable rather than inline in the entry, so the whole containment path is
 * exercised: an entry runs `main()` on import and can never be imported by a
 * test, so logic left there is uncovered by construction.
 *
 * TOTAL AND FAIL-OPEN. A bundle that will not load, or a model that cannot be
 * resolved, returns null and the turn proceeds to the ordinary detection path.
 */
export async function refuseProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): Promise<{ decision: { decision: 'block'; reason: string }; model: string } | null> {
  try {
    const { prohibitedModels } = await gateway.getPolicyBundle();
    // Bundle FIRST: with no prohibition list there is nothing to enforce, and
    // resolving the model would be a transcript read spent to reach the same
    // allow.
    if (prohibitedModels === undefined || prohibitedModels.length === 0) return null;
    const model = resolveCodexSessionModel(dataDir, sessionId, transcriptPath);
    const decision = decideProhibitedModelTurn(model, prohibitedModels);
    // The model rides back with the verdict so the caller records WHICH model
    // was refused without resolving it twice — and so the audit row and the
    // message the user sees can never disagree about it.
    return decision === null || model === undefined ? null : { decision, model };
  } catch {
    return null;
  }
}

/**
 * The whole containment step: decide, and on a refusal close the gateway and
 * emit. Returns true when the turn was refused and the caller must stop.
 *
 * `emit` is a parameter rather than an import so this module stays free of the
 * stdout contract and testable without one.
 */
export async function handleProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle' | 'recordAuditEvent' | 'close'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
  emit: (output: { decision: 'block'; reason: string }) => Promise<void>,
): Promise<boolean> {
  const blocked = await refuseProhibitedTurn(gateway, dataDir, sessionId, transcriptPath);
  if (blocked === null) return false;
  // Recorded while the gateway is still open, and best-effort: a refusal that
  // cannot be written down is still a refusal, so a failed write must not reach
  // the entry's outer catch and turn this block into a fail-open allow.
  try {
    await gateway.recordAuditEvent(
      buildModelRefusalEvent({
        id: randomUUID(),
        sessionId,
        model: blocked.model,
        seam: 'turn',
        sourceTool: SOURCE_TOOL.Codex,
        occurredAt: new Date().toISOString(),
      }),
    );
  } catch {
    // Swallowed on purpose — see above.
  }
  // Closed here rather than left to the caller's runtime `finally`, which the
  // refusal path never reaches.
  await gateway.close();
  await emit(blocked.decision);
  return true;
}
