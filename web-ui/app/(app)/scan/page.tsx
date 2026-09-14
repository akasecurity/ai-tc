import { PageHead } from '@akasecurity/dashboard-ui';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import { controlPlaneName, isAttached } from '@akasecurity/schema';

import { db } from '../../lib/db';
import { ScanClient } from './ScanClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Scan' };

export default function ScanPage() {
  const ruleset = db().installedPacks.installedRuleset();
  // Read here, in the Server Component, so the page can say BEFORE a click that
  // a scan on this machine forwards — the client never touches settings.
  const settings = readWorkspaceSettings();
  const attachedTo =
    isAttached(settings) && settings.controlPlane !== undefined
      ? controlPlaneName(settings.controlPlane)
      : null;

  return (
    <div className="p-6">
      <PageHead
        title="Scan"
        sub="Run the installed detection rules over a local file or directory — the web twin of `aka scan`"
      />
      <ScanClient enabledRuleCount={ruleset.rules.length} attachedTo={attachedTo} />
    </div>
  );
}
