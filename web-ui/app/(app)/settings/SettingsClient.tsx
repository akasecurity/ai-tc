'use client';

import { WorkspaceSettingsFormView } from '@akasecurity/dashboard-ui';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { useState, useTransition } from 'react';

import { saveSettings } from './actions';

export function SettingsClient({ settings }: { settings: WorkspaceSettings }) {
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, startTransition] = useTransition();

  return (
    <WorkspaceSettingsFormView
      settings={settings}
      busy={busy}
      error={error}
      saved={saved}
      onSave={(changes) => {
        startTransition(async () => {
          const result = await saveSettings(changes);
          setError(result.ok ? null : (result.error ?? 'Could not save.'));
          setSaved(result.ok);
        });
      }}
    />
  );
}
