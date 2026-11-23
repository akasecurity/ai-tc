// Copy-paste-complete exception guidance for the enforcement messages. When a
// detection blocks (or redacts), the runtime has already recorded a
// fingerprint-only row in the short-lived blocked-detections ledger and handed
// back a rich reference on `CaptureResult.blockedReferences`; these builders
// turn that into the exact `aka exception approve` command so the user can
// grant an explicit, audited bypass from a terminal. Removal of the flagged
// content stays the first recommendation — the exception is the sanctioned
// escape hatch, offered at the point of failure, never promoted.
//
// The preview and the reference both come from the SAME ledger row
// (BlockedDetectionRef), so the masked value shown can never describe a
// different value than the one `approve <ref>` resolves — and no raw match
// text is handled here at all.
//
// The same messages the other plugins' exception-guidance.ts build: the
// messaging is host-agnostic (references `aka`, the CLI, never host-specific
// wording).
//
// Pure string building (no I/O) so it unit-tests without a hook process. Hook
// entry files run main() on import and must NEVER be imported by tests — that
// is exactly why this lives in its own module instead of inline in the hooks.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';

export interface BlockMessageInput {
  // What was blocked, as it reads mid-sentence: 'prompt' or 'Bash call'.
  subject: string;
  // Comma-joined unique rule ids (uniqueRuleIds output / a joined rule set).
  ruleIds: string;
  // First ledger ref recorded for this capture. Without one the approve
  // command degrades to its bare form, which lists recent blocks to pick from.
  blockedRef?: BlockedDetectionRef | undefined;
  // Extra sentence woven into the first line, between the flag preview and the
  // removal advice — e.g. why a redact policy escalated to a block on
  // executable command text (EXECUTABLE_REDACT_NOTE).
  note?: string | undefined;
}

// The block message (transcript-rendered, so it stays ≤ 5 lines): what was
// flagged (masked preview from the ledger row), removal as the primary fix,
// then the copy-paste-complete exception command with the ledger reference
// baked in, and one help pointer. With a reference the pasted-value form is
// offered as a second, aligned command line — the selector the user already
// has in their clipboard; it only appears when a ledger row is guaranteed,
// because approve-by-value resolves against that same row. Without one the
// command degrades to its bare form, which lists recent blocks to pick from.
export function blockMessage(input: BlockMessageInput): string {
  const preview = input.blockedRef ? ` (${input.blockedRef.maskedValue})` : '';
  const commands = input.blockedRef
    ? [
        `  aka exception approve ${input.blockedRef.reference}       (asks for scope + reason, then resubmit)`,
        '  aka exception approve <value>      (same flow, pasting the blocked value itself)',
      ]
    : ['  aka exception approve       (asks for scope + reason, then resubmit)'];
  const note = input.note ? ` ${input.note}` : '';
  return [
    `AKA blocked this ${input.subject} — flagged ${input.ruleIds}${preview}.${note} Remove the flagged content and resubmit.`,
    'If this is intentional and you accept the risk, grant an exception:',
    ...commands,
    'More: aka exception --help',
  ].join('\n');
}

// The refusal for a field the hook could not scan in the time it has: a field
// at or above the large-input threshold whose bounded scan timed out or found
// no worker to run it (`CaptureResult.scanIncomplete`). It names no rule —
// none ran to completion — and offers no exception, because there is no
// flagged value for one to approve. What the user can do is send less at once.
export function tooLargeToScanMessage(subject: string): string {
  return `This ${subject} is too large for AKA to scan within the time limit, so it was blocked. Shorten it or send it in smaller parts.`;
}

// The same fact for a surface that CANNOT refuse: a capture-only event (a
// prompt, a tool result) whose bounded scan did not finish. The field went
// through anyway, so this must never say it was blocked — and it must never
// read as clean either, because nothing in it was checked. `delivered` is the
// clause saying where the content went, e.g. 'it was sent to the model
// unchanged' or 'the output reached the model unchanged'. Like the refusal
// above it names no rule and offers no exception.
export function unscannedTooLargeMessage(subject: string, delivered: string): string {
  return (
    `AKA could not scan this ${subject} within the time limit because it is too large, ` +
    `so nothing in it was checked and ${delivered}. ` +
    'Shorten it or send it in smaller parts to have it scanned.'
  );
}

// The same capture-only fact when the cause is not time but the scan worker:
// it could not be started, died, or failed the job (`scanIncomplete:
// 'unavailable'`). That is a fault in AKA rather than in the field — a missing
// worker fails every field this large until the install is repaired — so the
// sentence points at the install and never at the size of what was sent. Like
// its siblings it never says blocked, names no rule and offers no exception.
export function unscannedWorkerUnavailableMessage(subject: string, delivered: string): string {
  return (
    `AKA's scan worker could not run, so this ${subject} was not scanned: nothing in it ` +
    `was checked and ${delivered}. This is a fault in AKA, not a limit on what was sent: ` +
    'if it happens again, reinstall the AKA plugin to repair it.'
  );
}

// The same capture-only fact when the cause is not time but the bounds a
// structured result is read under: text past the depth, item-count or size
// limits was never collected, so it was never scanned. Saying "within the time
// limit" there would send the user looking for a slow scan that never ran. Like
// its sibling above it never says blocked, names no rule and offers no
// exception.
export function unscannedPastWalkLimitsMessage(subject: string, delivered: string): string {
  return (
    `Part of this ${subject} lies past the depth, item-count or size limits AKA reads ` +
    `a structured result to, so that part was not checked and ${delivered}. ` +
    'Have the tool return less at once to have all of it scanned.'
  );
}

// One trailing sentence for the warn notices: redacted
// values land in the same ledger as blocked ones, so the same approve flow
// applies. Empty when nothing was ledgered — the message is only extended when
// the command would actually find the block.
export function exceptionPointer(references: readonly BlockedDetectionRef[] | undefined): string {
  const ref = references?.[0];
  if (ref === undefined) return '';
  return ` To allow this exact value intentionally, run: aka exception approve ${ref.reference}.`;
}
