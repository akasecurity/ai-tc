// What the tool.call mod's helper tells the mod, built from what the PreToolUse
// pipeline emitted. Pure, so it unit-tests without a process.
import type { HookOutput } from '../hooks/shared.ts';

/** The helper's stdout (one JSON line). */
export interface ToolCallAnswer {
  v: 1;
  /** Refuse the call with this reason; the other fields are then null. */
  deny: string | null;
  /** The input the tool should run with (granted pointers dereferenced, secrets redacted). */
  input: Record<string, unknown> | null;
  /** A model-only note to add after the tool's result. */
  context: string | null;
  /** A line for the user (what PreToolUse would have shown as its systemMessage). */
  message: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Collapses the pipeline's outputs the way the host collapses a hook's. */
export function answerFromOutputs(outputs: readonly HookOutput[]): ToolCallAnswer {
  const answer: ToolCallAnswer = { v: 1, deny: null, input: null, context: null, message: null };
  const messages: string[] = [];
  for (const output of outputs) {
    if ('systemMessage' in output && typeof output.systemMessage === 'string') {
      messages.push(output.systemMessage);
    }
    if (!('hookSpecificOutput' in output)) continue;
    const specific = output.hookSpecificOutput as unknown as Record<string, unknown>;
    if (specific.hookEventName !== 'PreToolUse') continue;
    if (specific.permissionDecision === 'deny') {
      answer.deny =
        typeof specific.permissionDecisionReason === 'string' &&
        specific.permissionDecisionReason !== ''
          ? specific.permissionDecisionReason
          : 'Blocked by AKA.';
    } else if (specific.permissionDecision === 'allow' && isRecord(specific.updatedInput)) {
      answer.input = specific.updatedInput;
      if (typeof specific.additionalContext === 'string')
        answer.context = specific.additionalContext;
    }
  }
  if (answer.deny !== null) return { ...answer, input: null, context: null, message: null };
  answer.message = messages.length > 0 ? messages.join(' ') : null;
  return answer;
}
