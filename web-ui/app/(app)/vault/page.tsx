import { PageHead } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { renderInstant } from '../../lib/rendered-at';
import { VaultDashboardClient } from './VaultDashboardClient';
import { VaultLookupClient } from './VaultLookupClient';

// node:sqlite (via @akasecurity/persistence) runs only on the Node.js runtime.
export const runtime = 'nodejs';
// Reads the local store on every request — never statically prerendered.
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Vault' };

// Three FIRST PAGES, not three whole tables. The inventory grows one row per
// distinct value ever detected on this machine — thousands on a working
// install, each carrying its own sightings array — so loading it whole cost
// seconds of serialization and tens of thousands of table rows before anything
// was on screen. Later pages arrive through the load-more Server Actions in
// ./actions.ts, which append in client state rather than re-rendering the route.
//
// The reuse list is its OWN read rather than a filter over the inventory page:
// reuse is a property of the whole store, and deriving it from the newest 50
// rows would quietly under-report the values a reader most needs to see.
export default function VaultPage() {
  const inventory = db().secretVault.listInventory();
  const reuse = db().secretVault.listReuse();
  // Only the default (batched-hidden) variant up front. The toggle re-queries
  // through an action — fetching both whole trails to save one round-trip was
  // the wrong trade once either of them could be long.
  const derefs = db().secretVault.listDerefs();
  // One instant for the whole route: every relative label below is measured
  // against it during the server render and again during hydration.
  const renderedAt = renderInstant();

  return (
    <div className="p-6">
      <PageHead
        title="Vault"
        sub="Every value this machine holds, where its pointers have been written, and every de-reference. Reveals are audited."
      />
      <div className="flex flex-col gap-8">
        <VaultLookupClient />
        <VaultDashboardClient
          inventory={inventory}
          reuse={reuse}
          derefs={derefs}
          renderedAt={renderedAt}
        />
      </div>
    </div>
  );
}
