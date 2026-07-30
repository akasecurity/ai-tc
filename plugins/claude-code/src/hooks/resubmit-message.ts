/**
 * The block reason shown when a prompt was blocked AND the vault produced a
 * pointerized rewrite of it: instead of only "remove the flagged content", the
 * user gets their own prompt back with each secret replaced by a vault
 * pointer, ready to paste and resubmit. The rewrite in the message is the
 * source of truth — the clipboard copy is best-effort and only changes one
 * sentence.
 *
 * Pure string building (no I/O) so it unit-tests without a hook process, same
 * split as exception-guidance.ts: hook entry files run main() on import and
 * must never be imported by tests.
 */
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';

import { exceptionPointer } from '../exception-guidance.ts';

const REWRITE_OPEN = '----- safe prompt (copy everything between these lines) -----';
const REWRITE_CLOSE = '----- end safe prompt -----';

export function resubmitMessage(opts: {
  // Comma-joined unique rule ids (uniqueRuleIds output).
  ruleIds: string;
  // The pointerized rewrite of the user's own prompt.
  rewrite: string;
  // Whether the rewrite also landed on the system clipboard.
  clipboardWrote: boolean;
  // First ledger ref recorded for this capture; adds the approve guidance.
  blockedRef?: BlockedDetectionRef | undefined;
}): string {
  const paste = opts.clipboardWrote
    ? 'It is already on your clipboard — paste and resubmit.'
    : 'Copy it, then paste and resubmit.';
  return [
    `AKA blocked this prompt — flagged ${opts.ruleIds}. The flagged value never reached the model.`,
    `Here is your prompt with each detected secret replaced by a vault pointer. ${paste}`,
    REWRITE_OPEN,
    opts.rewrite,
    REWRITE_CLOSE,
    'The model works with the pointers; the real values stay in your local vault.' +
      exceptionPointer(opts.blockedRef ? [opts.blockedRef] : undefined),
  ].join('\n');
}
