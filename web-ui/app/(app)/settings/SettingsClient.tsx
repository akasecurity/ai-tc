'use client';

import { WorkspaceSettingsFormView } from '@akasecurity/dashboard-ui';
import type { ManagedContext, WorkspaceSettings } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { attachToControlPlane, detachFromControlPlane, saveSettings } from './actions';

export function SettingsClient({
  settings,
  managed,
}: {
  settings: WorkspaceSettings;
  managed: ManagedContext;
}) {
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, startTransition] = useTransition();

  // One runner for all three actions: each returns the same result shape, and
  // three copies of this closure is how one of them ends up not clearing the
  // previous error.
  const run = (action: () => Promise<{ ok: boolean; error?: string }>): void => {
    startTransition(async () => {
      try {
        const result = await action();
        setError(result.ok ? null : (result.error ?? 'Could not save.'));
        setSaved(result.ok);
      } catch {
        // These actions are written to RETURN a failure rather than throw, but
        // that only covers what happens inside them. The call itself can still
        // reject — a dropped connection, a framework-level error — and an
        // unhandled rejection inside a transition takes the whole page to the
        // error boundary, losing every unsaved answer on the form for a fault
        // that a retry would clear.
        setError('The change could not be sent — check your connection and try again.');
        setSaved(false);
      }
    });
  };

  return (
    <WorkspaceSettingsFormView
      settings={settings}
      managed={managed}
      busy={busy}
      error={error}
      saved={saved}
      onSave={(changes) => {
        run(() => saveSettings(changes));
      }}
      onAttach={(endpoint, label) => {
        run(() => attachToControlPlane({ endpoint, label }));
      }}
      onDetach={() => {
        run(() => detachFromControlPlane());
      }}
    />
  );
}
