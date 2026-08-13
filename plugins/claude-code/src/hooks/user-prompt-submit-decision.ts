// The pure decision half of the UserPromptSubmit hook: collapse the runtime's
// capture result into the hook's stdout payload. Pure object building — the
// vault and the clipboard arrive as injected seams — so it unit-tests without a
// hook process; hook entry files run main() on import and must NEVER be
// imported by tests (same split as pre-tool-use-decision.ts).
//
// Two things here are easy to get wrong by reading the neighbouring hook:
//
//   - The block shape is `{"decision":"block"}` at the TOP LEVEL, not
//     PreToolUse's `hookSpecificOutput.permissionDecision`. UserPromptSubmit
//     reads a different field, so borrowing the sibling's shape is silently a
//     no-opinion (allow).
//   - A `redact` policy BLOCKS here. Claude Code exposes no prompt-rewrite
//     channel on this event, so warning and passing the prompt through would
//     send the raw value to the model under a message claiming it was masked.
//     Blocking is the only outcome that is at least as strong as the policy.
//     True in-place redaction happens in pre-tool-use via updatedInput.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import { resubmitMessage } from './resubmit-message.ts';

// The two payloads this hook may write. Both are already arms of `HookOutput`
// in shared.ts, so this narrows what the entry can emit without widening what
// `emit` accepts.
export type UserPromptSubmitOutput =
  { decision: 'block'; reason: string } | { systemMessage: string };

// The vault seam: rewrite the prompt with each detected span replaced by a
// vault pointer. Mirrors `FieldTokenizer` in pre-tool-use-decision.ts, minus
// the `degraded` list, which this surface does not read: the prompt is blocked
// whether or not a span vaulted, so degradation cannot change the VERDICT.
//
// It does change what is TRUE of the rewrite, and that gap is not closed here.
// A span tokenizeText degrades is destroyed one-way, while resubmitMessage
// says "the real values stay in your local vault" — accurate for the pointers,
// false for the degraded spans. Widening this type is the first half of
// fixing that; the second is deciding what the message should say instead,
// which is a copy decision rather than a refactor.
export type PromptTokenizer = (
  prompt: string,
  findings: CaptureResult['findings'],
) => Promise<{ text: string; pointers: readonly string[] }>;

export interface UserPromptSubmitDeps {
  // Supplied ONLY when a valid vault-consent grant exists. Absence is what
  // enforces "no consent → the vault is never touched": there is no consent
  // flag to check here, because a missing tokenizer cannot touch anything.
  tokenizePrompt?: PromptTokenizer | undefined;
  // Best-effort clipboard write, whose result changes exactly one sentence of
  // the resubmit message. Absent (or false) → the message tells the user to
  // copy the rewrite by hand.
  writeClipboard?: ((text: string) => boolean) | undefined;
}

// The payload to write, or null for "no opinion" — which the entry then uses
// as its onboarding-nudge slot. Null covers monitor/log and allow alike,
// including an allow that carried findings.
export async function decideUserPromptSubmit(
  prompt: string,
  result: CaptureResult,
  deps: UserPromptSubmitDeps = {},
): Promise<UserPromptSubmitOutput | null> {
  if (result.action === 'block' || result.action === 'redact') {
    const ruleIds = uniqueRuleIds(result.findings);
    const blockedRef = result.blockedReferences?.[0];

    // Removal-based guidance is the floor. With consent it upgrades to the
    // resubmit message carrying a pointerized rewrite of the user's own
    // prompt — same block, strictly more the user can do about it.
    const rewrite = deps.tokenizePrompt
      ? await pointerizedRewrite(prompt, result.findings, deps.tokenizePrompt)
      : null;
    if (rewrite !== null) {
      // Only the pointerized text ever reaches the clipboard — never the raw
      // prompt. Guarded because this is an injected seam: a throw here would
      // escape into the entry's fail-open catch, which writes nothing and
      // exits 0 — and silence is how this host spells ALLOW, so a clipboard
      // fault would send the very prompt this branch is blocking. The
      // clipboard only decides one sentence; it may never decide the verdict.
      const clipboardWrote = writeClipboardSafely(rewrite, deps.writeClipboard);
      return {
        decision: 'block',
        reason: resubmitMessage({ ruleIds, rewrite, clipboardWrote, blockedRef }),
      };
    }
    return { decision: 'block', reason: blockMessage({ subject: 'prompt', ruleIds, blockedRef }) };
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

// A best-effort clipboard write that cannot change the verdict: any fault (or
// no seam at all) reads as "not copied", which downgrades one sentence of the
// resubmit message rather than losing the block.
function writeClipboardSafely(
  text: string,
  write: UserPromptSubmitDeps['writeClipboard'],
): boolean {
  try {
    return write?.(text) ?? false;
  } catch {
    return false;
  }
}

// The pointerized rewrite offered in the block reason, or null when it cannot
// be offered safely. Every DETECTED span is pointerized (not only the enforced
// ones) — the whole prompt is blocked regardless, so vaulting more never leaks
// more. Null on any fault, on a rewrite that minted no pointer, or — the
// never-leak gate — when any finding's raw match still appears in the
// rewritten text; the caller then falls back to the removal-based message.
//
// That gate is the reason this is a function rather than an inline await: a
// partial rewrite still reads like a success (it has pointers in it), and
// putting it in the block reason would print the raw value back to the user
// under a message saying it never reached the model.
export async function pointerizedRewrite(
  prompt: string,
  findings: CaptureResult['findings'],
  tokenize: PromptTokenizer,
): Promise<string | null> {
  try {
    const tokenized = await tokenize(prompt, findings);
    if (tokenized.pointers.length === 0) return null;
    for (const finding of findings) {
      if (finding.rawMatch !== '' && tokenized.text.includes(finding.rawMatch)) return null;
    }
    return tokenized.text;
  } catch {
    return null;
  }
}
