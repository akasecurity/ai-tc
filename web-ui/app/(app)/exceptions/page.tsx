import { BLOCKED_WINDOW_MS, resolveBlockedWindow } from '@akasecurity/dashboard-ui';
import { dataDir, readFingerprintKey } from '@akasecurity/persistence';

import { db } from '../../lib/db';
import { ExceptionsClient } from './ExceptionsClient';

// node:sqlite (via @akasecurity/persistence) runs only on the Node.js runtime.
export const runtime = 'nodejs';
// Reads the local store on every request — never statically prerendered.
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Exceptions' };

export default async function ExceptionsPage({
  searchParams,
}: {
  searchParams: Promise<{ all?: string; window?: string }>;
}) {
  const params = await searchParams;
  const includeTerminal = params.all === '1';
  const blockedWindow = resolveBlockedWindow(params.window);
  const [items, blocked] = await Promise.all([
    db().exceptions.list({ includeTerminal }),
    db().exceptions.recentBlocked(BLOCKED_WINDOW_MS[blockedWindow]),
  ]);

  // Key version for the rotate dialog; a corrupt key file must not take the
  // page down (the rotate action surfaces the recovery guidance).
  const keyVersion = ((): number | null => {
    try {
      return readFingerprintKey(dataDir())?.version ?? null;
    } catch {
      return null;
    }
  })();

  const activePermanent = items.filter(
    (ex) =>
      ex.scope === 'permanent' &&
      ex.revokedAt === null &&
      (ex.maxUses === null || ex.useCount < ex.maxUses),
  );

  return (
    <ExceptionsClient
      items={items}
      blocked={blocked}
      includeTerminal={includeTerminal}
      blockedWindow={blockedWindow}
      keyVersion={keyVersion}
      activePermanent={activePermanent}
    />
  );
}
