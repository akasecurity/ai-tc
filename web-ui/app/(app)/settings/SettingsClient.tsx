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
      const result = await action();
      setError(result.ok ? null : (result.error ?? 'Could not save.'));
      setSaved(result.ok);
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
