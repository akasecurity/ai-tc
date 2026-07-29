import { PageHead } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { VaultDashboardClient } from './VaultDashboardClient';
import { VaultLookupClient } from './VaultLookupClient';

// node:sqlite (via @akasecurity/persistence) runs only on the Node.js runtime.
export const runtime = 'nodejs';
// Reads the local store on every request — never statically prerendered.
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Vault' };

export default function VaultPage() {
  const inventory = db().secretVault.listInventory();
  // Both audit variants up front, so the batched-rows toggle swaps locally
  // instead of re-querying.
  const derefs = db().secretVault.listDerefs();
  const allDerefs = db().secretVault.listDerefs({ includeBatched: true });

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Vault"
        sub="Every value this machine holds, where its pointers have been written, and every de-reference. Reveals are audited."
      />
      <div className="flex flex-col gap-8">
        <VaultLookupClient />
        <VaultDashboardClient
          inventory={inventory}
          derefRows={derefs.rows}
          hiddenBatched={derefs.hiddenBatched}
          allDerefRows={allDerefs.rows}
        />
      </div>
    </div>
  );
}
