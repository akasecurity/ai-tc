'use client';

import { SightingSharingView } from '@akasecurity/dashboard-ui';
import type { SightingSharing } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { setSightingShareConsent } from './actions';

/** The credential-sightings sharing card and its toggle. */
export function SightingSharingPanel({ state }: { state: SightingSharing }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();
  return (
    <div className="mt-7">
      <SightingSharingView
        state={state}
        busy={busy}
        error={error}
        onChange={(choice) => {
          startTransition(async () => {
            try {
              const result = await setSightingShareConsent({ choice });
              setError(result.ok ? null : (result.error ?? 'Could not save.'));
            } catch {
              setError('The change could not be sent — check your connection and try again.');
            }
          });
        }}
      />
    </div>
  );
}
