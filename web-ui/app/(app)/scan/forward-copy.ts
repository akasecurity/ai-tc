import { FORWARD_FAILURE_LINES, type SharesForwardOutcome } from '@akasecurity/local-ops';

// What the Scan page says about the register it just forwarded, or did not,
// and in what tone.
//
// It lives beside the action rather than inside it because a `'use server'`
// module may only export async functions — a helper declared there could be
// reached by neither the client component that renders it nor a test.
//
// The failure sentences are the shared ones every surface renders from, so a
// person who ran into a refusal in the CLI and then tries this page is told the
// same thing. What this module owns is the rest: the credential line, whose
// remedy differs here (attach is one click away, and there is no terminal),
// and the TONE of every line — decided in the same switch as the wording, so a
// status added to the union cannot get a sentence in one place and a colour
// from a second read of it somewhere else.

/** A note reads like the counts it follows; a warning is a refusal the user must act on. */
export type ForwardTone = 'note' | 'warning';

export interface ForwardLine {
  text: string;
  tone: ForwardTone;
}

/**
 * One line for what the forward did, or null when there is nothing to say.
 *
 * A machine attached to nothing renders NOTHING, which is what keeps a
 * standalone install's Scan page exactly as it was before this page could
 * forward at all. The Data Shares switch being off is silent for the same
 * reason: nothing was recorded either, so there is no register to talk about.
 * A scan the user ran with forwarding unticked says so, as a note.
 */
export function describeForward(outcome: SharesForwardOutcome): ForwardLine | null {
  switch (outcome.status) {
    case 'not-attached':
      return null;
    case 'disabled':
      return outcome.reason === 'opt-out'
        ? { text: 'Not forwarded: this scan was run without forwarding.', tone: 'note' }
        : null;
    case 'no-credential':
      return {
        text: `Not forwarded to ${outcome.endpoint}: no usable credential — re-attach from Settings.`,
        tone: 'warning',
      };
    case 'forwarded':
      return {
        text: `Forwarded to ${outcome.endpoint} · ${String(outcome.callSites)} call site(s).`,
        tone: 'note',
      };
    case 'failed':
      return {
        text: `Not forwarded to ${outcome.endpoint}: ${FORWARD_FAILURE_LINES[outcome.kind]}.`,
        tone: 'warning',
      };
  }
}
