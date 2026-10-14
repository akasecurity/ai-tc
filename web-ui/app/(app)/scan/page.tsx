import { PageHead } from '@akasecurity/dashboard-ui';
import {
  readControlPlaneAttachmentMode,
  readWorkspaceSettings,
  settingsDir,
} from '@akasecurity/persistence';
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
  const connection = isAttached(settings) ? settings.controlPlane : undefined;
  const attachedTo = connection === undefined ? null : controlPlaneName(connection);
  // The mode alone, never the credential: on a scoped machine the register goes
  // only for an enrolled project, and the notice has to say so before the click.
  const attachmentMode =
    connection === undefined
      ? undefined
      : readControlPlaneAttachmentMode(settingsDir(), connection);

  return (
    <div className="p-6">
      <PageHead
        title="Scan"
        sub="Run the installed detection rules over a local file or directory — the web twin of `aka scan`"
      />
      <ScanClient
        enabledRuleCount={ruleset.rules.length}
        attachedTo={attachedTo}
        attachmentMode={attachmentMode}
      />
    </div>
  );
}
