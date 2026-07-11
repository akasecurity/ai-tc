'use client';

import { ExceptionDetailView } from '@akasecurity/dashboard-ui';
import type { DetectionException } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { revokeException } from '../actions';

export function ExceptionDetailClient({ exception }: { exception: DetectionException }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();

  return (
    <ExceptionDetailView
      exception={exception}
      busy={busy}
      error={error}
      onRevoke={(reason) => {
        startTransition(async () => {
          const result = await revokeException(exception.id, reason);
          setError(result.ok ? null : (result.error ?? 'Could not revoke.'));
        });
      }}
    />
  );
}
