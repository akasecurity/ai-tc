import type { SharesForwardOutcome } from '@akasecurity/local-ops';
import type { RemoteFailureKind } from '@akasecurity/schema';

// What the Scan page says about the register it just forwarded, or did not.
//
// It lives beside the action rather than inside it because a `'use server'`
// module may only export async functions — a helper declared there could be
// reached by neither the client component that renders it nor a test.
//
// The rule it keeps is the CLI's, and the sentences are deliberately the same
// ones: the two surfaces forward the same register through the same state
// machine, so a person who ran into a refusal in one and then tries the other
// must not be told two different things about it. Only the credential line
// differs, because the remedy differs — this surface has attach one click away
// and no terminal.

/**
 * What to do about each way the send can fail, in the words of the person who
 * has to do it.
 *
 * A `Record` over the whole enum rather than a switch with a fallback, so a
 * seventh kind fails to compile here instead of rendering as a shrug.
 */
export const FORWARD_FAILURE_COPY: Record<RemoteFailureKind, string> = {
  unauthorized: 'key rejected; re-attach with a valid plugin key',
  forbidden:
    'key is valid but not permitted for Data Shares ingest; a key minted before Data Shares ' +
    'ingest existed needs a re-attach, otherwise ask your org admin',
  'route-absent': 'the deployment predates Data Shares ingest; upgrade it, then re-run the scan',
  'invalid-request': 'this build assembled a request the contract refuses; please report it',
  rejected:
    'the deployment refused the request body; this build and the deployment are out of step — ' +
    'upgrade one of them',
  unreachable: 'control plane unreachable (timeout or server error); the next scan retries',
};

/**
 * One sentence for what the forward did, or null when there is nothing to say.
 *
 * A machine attached to nothing renders NOTHING, which is what keeps a
 * standalone install's Scan page exactly as it was before this page could
 * forward at all. `disabled` is null for a different reason: this page never
 * turns the forward off, so the outcome is unreachable from here and a sentence
 * for it would describe a control the user cannot see.
 */
export function describeForward(outcome: SharesForwardOutcome): string | null {
  switch (outcome.status) {
    case 'not-attached':
    case 'disabled':
      return null;
    case 'no-credential':
      return `Not forwarded to ${outcome.endpoint}: no usable credential — re-attach from Settings.`;
    case 'forwarded':
      return `Forwarded to ${outcome.endpoint} · ${String(outcome.callSites)} call site(s).`;
    case 'failed':
      return `Not forwarded to ${outcome.endpoint}: ${FORWARD_FAILURE_COPY[outcome.kind]}.`;
  }
}
