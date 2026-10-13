// What the worktree scanner needs to share the credential sightings it finds:
// the plan, the token, and a send through the attached transport. The scanner
// opens no socket of its own.
import type {
  CredentialSightingsSend,
  ForwardCredentialSightingsInput,
} from '@akasecurity/persistence';
import { forwardCredentialSightings } from '@akasecurity/persistence';
import { createCredentialSightingsSender } from '@akasecurity/remote';
import type { CredentialSightingsOutcome, ManagedSettings } from '@akasecurity/schema';

export type {
  CredentialSightingsSend,
  ScanSighting,
  SightingKey,
  SightingScanProject,
  SightingSharePlan,
} from '@akasecurity/persistence';
export { planSightingShare, sightingToken } from '@akasecurity/persistence';
export type { CredentialSightingsOutcome, ManagedSettings } from '@akasecurity/schema';
export { combineCredentialSightingsOutcomes } from '@akasecurity/schema';

export interface SendScanSightingsDeps {
  /** Replaces the attached transport. */
  send?: CredentialSightingsSend | undefined;
  /** Replaces the managed settings file; `null` reads a machine with no administrator. */
  managedSettings?: ManagedSettings | null | undefined;
}

/** Send one project's scan sightings for the AKA home `base`. Never throws. */
export function sendScanSightings(
  base: string,
  input: ForwardCredentialSightingsInput,
  deps: SendScanSightingsDeps = {},
): Promise<CredentialSightingsOutcome> {
  return forwardCredentialSightings(base, input, {
    send: deps.send ?? createCredentialSightingsSender(),
    managedSettings: deps.managedSettings,
  });
}
