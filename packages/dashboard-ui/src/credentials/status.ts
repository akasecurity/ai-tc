import type { CredentialStatus } from '@akasecurity/schema';

/** How each credential status reads in a chip, a column and a detail header. */
export const CREDENTIAL_STATUS: Record<CredentialStatus, { label: string }> = {
  rotation_overdue: { label: 'Rotation overdue' },
};
