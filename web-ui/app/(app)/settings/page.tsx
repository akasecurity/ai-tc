import { PageHead, SETTINGS_PAGE_SUB } from '@akasecurity/dashboard-ui';
import { readWorkspaceSettings } from '@akasecurity/persistence';

import { SettingsClient } from './SettingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Settings' };

export default function SettingsPage() {
  const settings = readWorkspaceSettings();

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead title="Settings" sub={SETTINGS_PAGE_SUB} />
      <SettingsClient settings={settings} />
    </div>
  );
}
