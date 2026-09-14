// Exception guidance for the enforcement banner. When a detection blocks, the
// runtime has already recorded a fingerprint-only row in the short-lived
// blocked-detections ledger and handed back a reference on
// `CaptureResult.blockedReferences`; this turns that into the exact
// `aka exception approve` command, so a user who accepts the risk can grant an
// explicit, audited bypass from a terminal. Removal of the flagged content
// stays the first recommendation — the exception is the sanctioned escape
// hatch, offered at the point of failure, never promoted.
//
// The preview and the reference both come from the SAME ledger row
// (BlockedDetectionRef), so the masked value shown can never describe a
// different value than the one `approve <ref>` resolves, and no raw match text
// is handled here at all.
//
// Sibling of plugins/{claude-code,codex,antigravity}/src/exception-guidance.ts
// with one deliberate difference: those build terminal text and join it, while
// this returns the parts SEPARATELY. The banner renders into a shadow root, and
// the command has to be its own element for the user to select it — a reference
// nobody can copy is a reference nobody can use.
//
// Pure string building, no I/O, so it unit-tests without a page.
import type { BlockedDetectionRef } from '@akasecurity/plugin-sdk';

export interface BlockGuidanceInput {
  // Comma-joined unique rule ids, as they should read in the sentence.
  ruleIds: string;
  // First ledger ref recorded for this capture. Without one the command
  // degrades to its bare form, which lists recent blocks to pick from.
  blockedRef?: BlockedDetectionRef | undefined;
}

export interface BlockGuidance {
  headline: string;
  advice: string;
  approveIntro: string;
  command: string;
  help: string;
}

/** The parts of a block banner, in reading order. */
export function blockGuidance(input: BlockGuidanceInput): BlockGuidance {
  const preview = input.blockedRef ? ` (${input.blockedRef.maskedValue})` : '';
  return {
    headline: `AKA blocked this message — flagged ${input.ruleIds}${preview}.`,
    advice: 'Remove the flagged content and resend.',
    approveIntro: 'If this is intentional and you accept the risk, grant an exception:',
    command: input.blockedRef
      ? `aka exception approve ${input.blockedRef.reference}`
      : 'aka exception approve',
    help: 'More: aka exception --help',
  };
}

/**
 * One trailing sentence for the redact banner.
 *
 * A redacted value lands in the same ledger as a blocked one, so the same
 * approve flow applies. Empty when nothing was ledgered — the sentence is only
 * added when the command would actually find the block.
 *
 * NOT for a warn banner. A warn decision ledgers nothing (see the interceptor's
 * warn branch), so the reference this would name does not exist and the
 * sentence would send the user to a command that cannot find it.
 */
export function exceptionPointer(references: readonly BlockedDetectionRef[] | undefined): string {
  const ref = references?.[0];
  if (ref === undefined) return '';
  return ` To allow this exact value intentionally, run: aka exception approve ${ref.reference}.`;
}
