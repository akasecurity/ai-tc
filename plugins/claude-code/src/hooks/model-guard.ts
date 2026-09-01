// Prohibited-model governance, decision-only: the two refusals this feature can
// make and the model resolution they share. Pure logic plus bounded reads, so it
// unit-tests without a hook process — hook ENTRY files run main() on import and
// must never be imported by tests (the same split as pre-tool-use-decision.ts
// and user-prompt-submit-decision.ts).
//
// The two refusals answer DIFFERENT hooks in DIFFERENT vocabularies, which is
// the one thing to get right here — see each function's own note.
import type { DataGateway } from '@akasecurity/plugin-sdk';
import {
  decideProhibitedModelTurn,
  isModelProhibited,
  modelFromTranscript,
  prohibitedModelMessage,
  readSessionModel,
} from '@akasecurity/plugin-sdk';

// PreModelSwitch answers in the SAME permission vocabulary as PreToolUse —
// `permissionDecision: 'deny'` with a reason — rather than UserPromptSubmit's
// top-level `{decision:'block'}`. Two hooks, two shapes, and the harness honors
// only its own; getting them backwards produces a hook that emits valid JSON and
// silently allows.
export interface PreModelSwitchOutput {
  hookSpecificOutput: {
    hookEventName: 'PreModelSwitch';
    permissionDecision: 'deny';
    permissionDecisionReason: string;
  };
}

/**
 * Deny the switch when `toModel` is prohibited; otherwise say nothing.
 *
 * Null means NO OPINION, which the harness reads as allow — the correct answer
 * for every uncertain case, and there are three of them: an absent `to_model`, a
 * bundle with no prohibition list, and a model not on the list. Only a model
 * KNOWN to be prohibited produces a denial.
 */
export function decidePreModelSwitch(
  toModel: string | undefined,
  prohibitedModels: readonly string[] | undefined,
): PreModelSwitchOutput | null {
  // Narrowed BEFORE the prohibition check rather than asserted after it.
  // `isModelProhibited` already returns false for an absent model, so this
  // reads as redundant — but it is what lets the compiler see a `string` at the
  // message call, and the two escape hatches that would avoid it (a cast, a
  // non-null assertion) are both banned here precisely because they survive a
  // later change to that helper while this does not.
  if (toModel === undefined || toModel === '') return null;
  if (!isModelProhibited(toModel, prohibitedModels)) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreModelSwitch',
      permissionDecision: 'deny',
      permissionDecisionReason: prohibitedModelMessage(toModel, 'switch'),
    },
  };
}

// ---------------------------------------------------------------------------
// The containment half: a TURN already running on a prohibited model.
// ---------------------------------------------------------------------------

/**
 * The model this session is running on, or undefined when it cannot be told.
 *
 * Two sources, cheapest first. The recorded marker is written by the model-switch
 * hooks and by SessionStart, and is authoritative when present. The transcript is
 * the fallback for a session those never covered — one that predates this plugin
 * version, or whose marker a concurrent session clobbered.
 *
 * Undefined is a real and expected answer, most obviously on the FIRST turn of a
 * session that started on a prohibited model without announcing it: no switch has
 * happened and no assistant record exists yet. That turn is allowed. It is the
 * known hole in this control, and it closes on the second turn, when the
 * transcript can answer.
 */
export function resolveSessionModel(
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): string | undefined {
  return readSessionModel(dataDir, sessionId) ?? modelFromTranscript(transcriptPath);
}

/**
 * Resolve the session's model against the bundle's prohibition list, and return
 * the refusal when there is one.
 *
 * Importable rather than inline in the hook entry, so the whole containment path
 * is exercised by the suite: an entry runs `main()` on import and can never be
 * imported by a test, so logic left there is uncovered by construction.
 *
 * TOTAL AND FAIL-OPEN. A bundle that will not load, or a model that cannot be
 * resolved, returns null and the turn proceeds to the ordinary detection path —
 * this control refuses on knowledge, never on ignorance.
 */
export async function refuseProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): Promise<{ decision: 'block'; reason: string } | null> {
  try {
    const { prohibitedModels } = await gateway.getPolicyBundle();
    // Bundle FIRST: with no prohibition list there is nothing to enforce, and
    // resolving the model would be a transcript read spent to reach the same
    // allow.
    if (prohibitedModels === undefined || prohibitedModels.length === 0) return null;
    return decideProhibitedModelTurn(
      resolveSessionModel(dataDir, sessionId, transcriptPath),
      prohibitedModels,
    );
  } catch {
    return null;
  }
}

/**
 * The whole containment step: decide, and on a refusal close the gateway and
 * emit. Returns true when the turn was refused and the caller must stop.
 *
 * The emit and the close live HERE rather than in the hook entry for the same
 * reason the decision does — an entry runs `main()` on import, so a test can
 * never import one and anything left there is uncovered by construction. What
 * remains in the entry is the call and the early return.
 *
 * `emit` is a parameter rather than an import so this module stays free of the
 * stdout contract and testable without one.
 */
export async function handleProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle' | 'close'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
  emit: (output: { decision: 'block'; reason: string }) => Promise<void>,
): Promise<boolean> {
  const blocked = await refuseProhibitedTurn(gateway, dataDir, sessionId, transcriptPath);
  if (blocked === null) return false;
  // Closed here rather than left to the caller's runtime `finally`, which the
  // refusal path never reaches.
  await gateway.close();
  await emit(blocked);
  return true;
}
