'use client';

import { ExceptionDetailView, useRenderClock } from '@akasecurity/dashboard-ui';
import type { ExceptionDescriptor } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { revokeException } from '../actions';

export function ExceptionDetailClient({
  exception,
  renderedAt,
}: {
  exception: ExceptionDescriptor;
  /** The instant the server rendered against. */
  renderedAt: number;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();
  // Starts at the server's instant so hydration reproduces the server's markup,
  // then moves, so a grant that expires while this page is open stops reading
  // `active` and the revoke form goes away on its own.
  const now = useRenderClock(renderedAt);

  return (
    <ExceptionDetailView
      exception={exception}
      renderedAt={now}
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
