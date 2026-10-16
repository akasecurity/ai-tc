// What the tool.call mod's helper tells the mod, built from what the PreToolUse
// pipeline emitted. Pure, so it unit-tests without a process.
import type { ModFinding } from '@akasecurity/schema';

import { EXCEPTION_POINTER_LEAD, REVEAL_DISCLOSURE_LEAD } from '../exception-guidance.ts';
import type { HookOutput } from '../hooks/shared.ts';
import { VAULT_UNAVAILABLE_DISCLOSURE } from '../protocol/notes.ts';

/** The helper's stdout (one JSON line). */
export interface ToolCallAnswer {
  v: 1;
  /** Refuse the call with this reason; the other fields are then null. */
  deny: string | null;
  /** The input the tool should run with (granted pointers dereferenced, secrets redacted). */
  input: Record<string, unknown> | null;
  /** A model-only note to add after the tool's result. */
  context: string | null;
  /**
   * A line for the user (what PreToolUse would have shown as its systemMessage),
   * or null when it says no more than the findings the mod's band shows.
   */
  message: string | null;
  /** What the pipeline found and acted on, for the mod's widgets. */
  findings: ModFinding[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// What a disclosure may carry beyond the redaction summary: a granted value
// revealed into the call, the command that would allow a value, a value lost
// because the vault was unavailable. None of them is a finding.
const NOTICES = [REVEAL_DISCLOSURE_LEAD, EXCEPTION_POINTER_LEAD, VAULT_UNAVAILABLE_DISCLOSURE];

/**
 * The message the mod is to show the user: all of it when it carries a notice,
 * or when there are no findings for the band to show; null otherwise.
 */
export function messageForUser(message: string | null, hasFindings: boolean): string | null {
  if (message === null || !hasFindings) return message;
  return NOTICES.some((notice) => message.includes(notice)) ? message : null;
}

/** Collapses the pipeline's outputs the way the host collapses a hook's. */
export function answerFromOutputs(outputs: readonly HookOutput[]): ToolCallAnswer {
  const answer: ToolCallAnswer = {
    v: 1,
    deny: null,
    input: null,
    context: null,
    message: null,
    findings: [],
  };
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
