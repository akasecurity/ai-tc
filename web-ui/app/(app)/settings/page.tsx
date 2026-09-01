import { PageHead } from '@akasecurity/dashboard-ui';
import {
  readControlPlaneCredentialState,
  readEffectiveSettings,
  settingsDir,
} from '@akasecurity/persistence';

import { SettingsClient } from './SettingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Settings' };

export default function SettingsPage() {
  // The EFFECTIVE settings, not the user's raw file: an administrator's managed
  // file overlays it, and the page has to render what is actually in force plus
  // which of it the user may change. Reading the raw file here would show an
  // editable control for a value the writer then refuses.
  const { settings, managed } = readEffectiveSettings();

  // The other half of an attachment. `runMode: 'attached'` is a stored answer;
  // whether this machine can actually use the connection also depends on a
  // credential file, and without this read the page called a machine attached
  // while it sent and received nothing. The CLI could always say so — this is
  // the dashboard catching up to `aka status`.
  //
  // Passed the descriptor so an endpoint MISMATCH is detectable: a credential
  // minted for another deployment parses perfectly and is still unusable, and
  // that comparison is the only thing this argument enables.
  //
  // Read here, in the server component, because it touches the filesystem.
  // Nothing secret crosses to the client: the state is a verdict plus, on a
  // mismatch, the two endpoints — never the key. `dynamic = 'force-dynamic'`
  // above already means this is re-read on every visit rather than baked in.
  const credentialState = readControlPlaneCredentialState(settingsDir(), settings.controlPlane);

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead title="Settings" sub="Workspace configuration for this machine." />
      <SettingsClient settings={settings} managed={managed} credentialState={credentialState} />
    </div>
  );
}
