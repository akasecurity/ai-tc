// The pure decision half of the UserPromptSubmit hook: collapse the runtime's
// capture result into the hook's stdout payload. Pure object building so it
// unit-tests without a hook process — hook entry files run main() on import
// and must NEVER be imported by tests (same split as pre-tool-use-decision.ts).
//
// The block shape is `{"decision":"block","reason"}` at the TOP LEVEL, which
// rejects this prompt and keeps the session going (see the hook entry's header
// for why `continue:false` is the wrong signal here).
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { blockMessage, exceptionPointer, tooLargeToScanMessage } from '../exception-guidance.ts';

export type UserPromptSubmitOutput =
  { decision: 'block'; reason: string } | { systemMessage: string };

// The payload to write, or null for "no opinion" — which the entry then uses
// as its onboarding-nudge slot.
export function decideUserPromptSubmit(result: CaptureResult): UserPromptSubmitOutput | null {
  // A prompt whose bounded scan did not finish is refused before anything else
  // reads the result: it arrives as a `block` with no findings, so the branch
  // below would name no rule.
  if (result.scanIncomplete !== undefined) {
    return { decision: 'block', reason: tooLargeToScanMessage('prompt') };
  }
  if (result.action === 'block' || result.action === 'redact') {
    // A redact policy blocks here too: this surface has no prompt-rewrite
    // channel, so the only way to honor "the raw value must not reach the
    // model" is to stop the prompt with removal-based guidance.
    return {
      decision: 'block',
      reason: blockMessage({
        subject: 'prompt',
        ruleIds: uniqueRuleIds(result.findings),
        blockedRef: result.blockedReferences?.[0],
      }),
    };
  }
  if (result.action === 'warn') {
    // A warn never escalates: the prompt continues, flagged. A warned value is
    // ledgered like a blocked one, so when a reference exists the message
    // points at the same out-of-band approve flow.
    return {
      systemMessage: `AKA flagged sensitive content (${uniqueRuleIds(result.findings)}) — sent unchanged.${exceptionPointer(result.blockedReferences)}`,
    };
  }
  return null;
}
