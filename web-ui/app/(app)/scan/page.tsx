import { PageHead } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { ScanClient } from './ScanClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export default function ScanPage() {
  const ruleset = db().installedPacks.installedRuleset();

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Scan"
        sub="Run the installed detection rules over a local file or directory — the web twin of `aka scan`"
      />
      <ScanClient enabledRuleCount={ruleset.rules.length} />
    </div>
  );
}
