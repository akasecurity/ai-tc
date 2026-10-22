import { Badge } from '@akasecurity/ui-kit';

import type { CredentialStatus } from './types.ts';

const BADGES: Record<CredentialStatus, { label: string; variant: 'critical' | 'success' }> = {
  exposed: { label: 'Exposed', variant: 'critical' },
  ok: { label: 'OK', variant: 'success' },
};

/** A credential's status as a badge. */
export function CredentialStatusBadge({ status }: { status: CredentialStatus }) {
  const { label, variant } = BADGES[status];
  return <Badge variant={variant}>{label}</Badge>;
}
