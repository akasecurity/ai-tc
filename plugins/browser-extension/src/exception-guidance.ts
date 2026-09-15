// Exception guidance for the enforcement banner. When a detection blocks or
// redacts, the runtime has already recorded a fingerprint-only row in the
// short-lived blocked-detections ledger and handed back a reference on
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
// this returns the parts SEPARATELY, for the block banner and the redact
// banners alike. The command never rides inside a banner's prose. The banner
// renders it as its own element with a copy button that writes the value handed
// over here, because ordinary selectable text is exactly what a page `copy`
// listener can swap on its way to the clipboard — and the command is what the
// user is about to paste into a terminal.
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

// The approve route as a banner renders it: a lead-in, the command on its own,
// and where to read more.
export interface ExceptionRoute {
  intro: string;
  command: string;
  help: string;
}

const APPROVE_COMMAND = 'aka exception approve';
const EXCEPTION_HELP = 'More: aka exception --help';

/** The parts of a block banner, in reading order. */
export function blockGuidance(input: BlockGuidanceInput): BlockGuidance {
  const preview = input.blockedRef ? ` (${input.blockedRef.maskedValue})` : '';
  return {
    headline: `AKA blocked this message — flagged ${input.ruleIds}${preview}.`,
    advice: 'Remove the flagged content and resend.',
    approveIntro: 'If this is intentional and you accept the risk, grant an exception:',
    command: input.blockedRef
      ? `${APPROVE_COMMAND} ${input.blockedRef.reference}`
      : APPROVE_COMMAND,
    help: EXCEPTION_HELP,
  };
}

/**
 * The approve route for a redact banner, or undefined when nothing was
 * ledgered.
 *
 * A redacted value lands in the same ledger as a blocked one, so the same
 * approve flow applies — including to a redact the page would not take, which
 * the interceptor turns into a block. Unlike a block, there is no bare-command
 * fallback: the route is only offered when the command would actually find the
 * row, so a banner without one has nothing to keep on screen.
 *
 * NOT for a warn banner. A warn decision ledgers nothing (see the interceptor's
 * warn branch), so the reference this would name does not exist and the route
 * would send the user to a command that cannot find it.
 */
export function redactExceptionRoute(
  blockedRef: BlockedDetectionRef | undefined,
): ExceptionRoute | undefined {
  if (blockedRef === undefined) return undefined;
  return {
    intro: 'To allow this exact value intentionally, run:',
    command: `${APPROVE_COMMAND} ${blockedRef.reference}`,
    help: EXCEPTION_HELP,
  };
}
