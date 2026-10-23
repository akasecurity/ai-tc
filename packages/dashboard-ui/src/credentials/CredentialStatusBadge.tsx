import type { CredentialStatus } from '@akasecurity/schema';
import { Badge } from '@akasecurity/ui-kit';

import { CREDENTIAL_STATUS } from './status.ts';

/** A credential status as a badge; a status this build does not know is shown as sent. */
export function CredentialStatusBadge({ status }: { status: CredentialStatus }) {
  if (!Object.hasOwn(CREDENTIAL_STATUS, status)) return <Badge variant="outline">{status}</Badge>;
  const { label, variant } = CREDENTIAL_STATUS[status];
  return <Badge variant={variant}>{label}</Badge>;
}
