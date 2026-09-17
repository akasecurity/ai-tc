import { PageHead } from '@akasecurity/dashboard-ui';
import {
  managedConnectionHold,
  readControlPlaneCredentialState,
  readEffectiveSettings,
  settingsDir,
} from '@akasecurity/persistence';

import { renderInstant } from '../../lib/rendered-at.ts';
import { SettingsClient } from './SettingsClient';
import { readSyncPanel } from './sync-panel-data.ts';
import { SyncPanel } from './SyncPanel';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Settings' };

export default function SettingsPage() {
  const { settings, managed } = readEffectiveSettings();
  const credentialState = readControlPlaneCredentialState(settingsDir(), settings.controlPlane);
  // Through the decision the attach and detach actions refuse on, not off the
  // managed context: a mode an administrator PINNED without locking it leaves
  // `lockedFields` empty, and the row would offer a detach the action refuses.
  const connectionHeld = managedConnectionHold() !== null;
  // NULL ON A STANDALONE MACHINE, and then nothing is rendered at all. The
  // panel describes a relationship with a deployment: a machine without one has
  // no lanes, no backlog and no button, and a card of zeros saying so is a
  // different claim from silence.
  const renderedAt = renderInstant();
  const sync = readSyncPanel(settings, credentialState, renderedAt);
  return (
    <div className="p-6">
      <PageHead title="Settings" sub="Workspace configuration for this machine." />
      <SettingsClient
        settings={settings}
        managed={managed}
        credentialState={credentialState}
        connectionHeld={connectionHeld}
      />
      {/* BELOW the form, and the panel's own copy depends on it: a stale grant
          reads "Review it above to resume", which names the control in the
          section this sits under. */}
      {sync !== null && (
        <div className="mt-4">
          <SyncPanel sync={sync} renderedAt={renderedAt} />
        </div>
      )}
    </div>
  );
}
