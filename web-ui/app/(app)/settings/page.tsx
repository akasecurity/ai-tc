import { PageHead } from '@akasecurity/dashboard-ui';
import { readWorkspaceSettings } from '@akasecurity/persistence';

import { SettingsClient } from './SettingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Settings' };

export default function SettingsPage() {
  const settings = readWorkspaceSettings();

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Settings"
        sub="Workspace configuration — the same knobs as the /aka:setup wizard, applied on the next hook"
      />
      <SettingsClient settings={settings} />
    </div>
  );
}
