import { PageHead } from '@akasecurity/dashboard-ui';
import { readEffectiveSettings } from '@akasecurity/persistence';

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

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead title="Settings" sub="Workspace configuration for this machine." />
      <SettingsClient settings={settings} managed={managed} />
    </div>
  );
}
