// What a `beforeSubmitPrompt` scan decides, as a pure function of the capture
// result, so it unit-tests without a hook process.
//
// Cursor's `beforeSubmitPrompt` takes `continue: false` to stop a prompt from
// being sent. It has no field for rewriting the prompt, so the prompt is
// captured as unrewritable and a redact policy resolves inside the runtime to
// the workspace's `redactFallback`.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { blockMessage, exceptionPointer, tooLargeToScanMessage } from '../exception-guidance.ts';
import type { PromptBlockOutput } from './shared.ts';

export interface PromptDecision {
  output: PromptBlockOutput | null;
  notice?: string;
}

export const PROMPT_NO_REWRITE_NOTE =
  'This surface cannot rewrite a prompt, so the mask was not applied and this workspace’s fallback for that case is to block.';

function block(message: string): PromptDecision {
  return { output: { continue: false, user_message: message } };
}

export function promptDecision(
  result: Pick<CaptureResult, 'action' | 'findings'> & {
    blockedReferences?: readonly BlockedDetectionRef[] | undefined;
    scanIncomplete?: CaptureResult['scanIncomplete'];
    redactDegradedTo?: CaptureResult['redactDegradedTo'];
  },
): PromptDecision {
  if (result.scanIncomplete !== undefined) return block(tooLargeToScanMessage('prompt'));
  if (result.findings.length === 0) return { output: null };

  const ruleIds = uniqueRuleIds([...result.findings]);
  // A redact reaching here was not degraded by the runtime; with no rewrite
  // channel it is carried out as a block rather than sent unmasked.
  if (result.action === 'block' || result.action === 'redact') {
    const degraded = result.redactDegradedTo === 'block' || result.action === 'redact';
    return block(
      blockMessage({
        subject: 'prompt',
        ruleIds,
        blockedRef: result.blockedReferences?.[0],
        note: degraded ? PROMPT_NO_REWRITE_NOTE : undefined,
      }),
    );
  }
  if (result.action === 'warn') {
    return {
      output: null,
      notice: `AKA flagged sensitive content in this prompt (${ruleIds}) — sent unchanged.${exceptionPointer(result.blockedReferences)}`,
    };
  }
  return { output: null };
}
