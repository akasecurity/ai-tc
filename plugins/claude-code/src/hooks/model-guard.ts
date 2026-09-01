// Prohibited-model governance, decision-only: the two refusals this feature can
// make and the model resolution they share. Pure logic plus bounded reads, so it
// unit-tests without a hook process — hook ENTRY files run main() on import and
// must never be imported by tests (the same split as pre-tool-use-decision.ts
// and user-prompt-submit-decision.ts).
//
// The two refusals answer DIFFERENT hooks in DIFFERENT vocabularies, which is
// the one thing to get right here — see each function's own note.
import {
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
 * Refuse a turn whose session is running on a prohibited model.
 *
 * UserPromptSubmit's own shape — top-level `{decision:'block'}`, NOT
 * PreModelSwitch's `permissionDecision` above. The harness reads a different
 * field per event, so the two decisions in this file deliberately return
 * different types rather than one shared shape.
 *
 * Null (allow) for every uncertain case, same rule as the switch decision: an
 * unresolvable model is ignorance, and this control never blocks on ignorance.
 */
export function decideProhibitedModelTurn(
  model: string | undefined,
  prohibitedModels: readonly string[] | undefined,
): { decision: 'block'; reason: string } | null {
  // Narrowed first, for the reason the switch decision above spells out.
  if (model === undefined || model === '') return null;
  if (!isModelProhibited(model, prohibitedModels)) return null;
  return { decision: 'block', reason: prohibitedModelMessage(model, 'turn') };
}
