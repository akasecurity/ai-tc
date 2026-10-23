import type { CredentialStatus } from '@akasecurity/schema';

/**
 * How each credential status reads in a chip, a column and a detail header,
 * and, as `state`, after "No credentials are" in an empty filtered list.
 */
export const CREDENTIAL_STATUS: Record<
  CredentialStatus,
  { label: string; state: string; variant: 'critical' | 'medium' }
> = {
  rotation_overdue: { label: 'Rotation overdue', state: 'overdue for rotation', variant: 'medium' },
  exposed: { label: 'Exposed', state: 'exposed', variant: 'critical' },
};

/** A status's label; a status this build does not know is shown as sent. */
export function credentialStatusLabel(status: string): string {
  return Object.hasOwn(CREDENTIAL_STATUS, status)
    ? CREDENTIAL_STATUS[status as CredentialStatus].label
    : status;
}

/** A status as a state ("overdue for rotation"); a status this build does not know is shown as sent. */
export function credentialStatusState(status: string): string {
  return Object.hasOwn(CREDENTIAL_STATUS, status)
    ? CREDENTIAL_STATUS[status as CredentialStatus].state
    : status;
}
