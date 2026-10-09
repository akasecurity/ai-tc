import { PageHead } from '@akasecurity/dashboard-ui';
import {
  managedConnectionHold,
  managedScopedRefusal,
  readControlPlaneAttachmentMode,
  readControlPlaneCredentialState,
  readEffectiveSettings,
  settingsDir,
  webChatWithholding,
} from '@akasecurity/persistence';

import { renderLocale } from '../../lib/render-locale.ts';
import { renderInstant } from '../../lib/rendered-at.ts';
import { SettingsClient } from './SettingsClient';
import { readSyncPanel } from './sync-panel-data.ts';
import { SyncPanel } from './SyncPanel';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Settings' };

export default async function SettingsPage() {
  const { settings, managed } = readEffectiveSettings();
  const credentialState = readControlPlaneCredentialState(settingsDir(), settings.controlPlane);
  // The MODE of the credential, alone: the key stays on the server. Undefined
  // unless a usable credential is held for the connection the settings name.
  const attachmentMode = readControlPlaneAttachmentMode(settingsDir(), settings.controlPlane);
  // Through the decision the attach and detach actions refuse on, not off the
  // managed context: a mode an administrator PINNED without locking it leaves
  // `lockedFields` empty, and the row would offer a detach the action refuses.
  const connectionHeld = managedConnectionHold() !== null;
  // Through the decision the attach action refuses a scoped attach on, for the
  // same reason: a connection pinned with nothing locked governs the machine
  // all the same, and the form must not offer a choice the action refuses.
  const machineOnly = managedScopedRefusal() !== null;
  // Why the browser extension records less from a web chat here than the
  // web-chat consent says, or nothing, or null. The same reading the native
  // host makes.
  const webChatWithheld = webChatWithholding(settingsDir(), settings);
  const renderedAt = renderInstant();
  // NULL ON A STANDALONE MACHINE, and then nothing is rendered at all. The
  // panel describes a relationship with a deployment: a machine without one has
  // no lanes, no backlog and no button, and a card of zeros saying so is a
  // different claim from silence.
  //
  // The panel is handed the mode the form is handed, so its bars count only what
  // this attachment covers: on a scoped one, the enrolled repositories' rows.
  const sync = readSyncPanel(settings, credentialState, renderedAt, attachmentMode);
  const locale = await renderLocale();
  return (
    // ONE width for the page: the heading, the form and the panel below it all
    // sit in this container rather than each naming a width. A second copy is
    // how the panel came to overhang the form it sits under.
    //
    // `box-content` is load-bearing: `max-w-3xl` otherwise caps the BORDER box,
    // so the padding would come out of the column and the cards would measure
    // 720px rather than 768px. It is what lets the width and the padding share
    // one element, which keeps this page a flat list of children — the shape
    // its route tests read.
    <div className="box-content max-w-3xl p-6">
      <PageHead title="Settings" sub="Workspace configuration for this machine." />
      {/* `settings` reaches the browser whole, its scope record included: the
          repositories this machine enrolled, and the organization and account
          name that record is bound to. They belong to this machine's own user,
          on their own dashboard, and no credential is among them. */}
      <SettingsClient
        settings={settings}
        managed={managed}
        credentialState={credentialState}
        connectionHeld={connectionHeld}
        attachmentMode={attachmentMode}
        machineOnly={machineOnly}
        webChatWithheld={webChatWithheld ?? undefined}
      />
      {/* BELOW the form, and the panel's own copy depends on it: a stale grant
          reads "Review it above to resume", which names the control in the
          section this sits under. */}
      {sync !== null && (
        <div className="mt-7">
          <SyncPanel sync={sync} renderedAt={renderedAt} locale={locale} />
        </div>
      )}
    </div>
  );
}
