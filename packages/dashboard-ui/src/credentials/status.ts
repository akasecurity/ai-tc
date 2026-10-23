import type { CredentialStatus } from '@akasecurity/schema';

/** How each credential status reads in a chip, a column and a detail header. */
export const CREDENTIAL_STATUS: Record<
  CredentialStatus,
  { label: string; variant: 'critical' | 'medium' }
> = {
  rotation_overdue: { label: 'Rotation overdue', variant: 'medium' },
  exposed: { label: 'Exposed', variant: 'critical' },
};

/** A status's label; a status this build does not know is shown as sent. */
export function credentialStatusLabel(status: string): string {
  return Object.hasOwn(CREDENTIAL_STATUS, status)
    ? CREDENTIAL_STATUS[status as CredentialStatus].label
    : status;
}
