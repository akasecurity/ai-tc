import { PageHead } from '@akasecurity/dashboard-ui';

import { VaultLookupClient } from './VaultLookupClient';

// node:sqlite (via @akasecurity/persistence, reached from the server action)
// runs only on the Node.js runtime.
export const runtime = 'nodejs';
// Reads the local store on every request — never statically prerendered.
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Vault' };

export default function VaultPage() {
  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Vault"
        sub="Resolve a pointer to its stored value. Every reveal is audited."
      />
      <VaultLookupClient />
    </div>
  );
}
