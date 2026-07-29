import { BLOCKED_WINDOW_MS, resolveBlockedWindow } from '@akasecurity/dashboard-ui';
import { dataDir, keyStateOf, readFingerprintKey } from '@akasecurity/persistence';
import type { FingerprintKeyState } from '@akasecurity/schema';

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

  // The key as three distinct states, not `number | null`: an unreadable key
  // file is not a missing one, and collapsing them is what would have the strip
  // tell someone with a permissions problem that their key "changed" and to
  // trigger the detection again — neither of which is true, and the obvious
  // next step from it (delete the key) destroys every grant on the machine.
  // A corrupt or unreadable file must still not take the page down.
  const keyState = ((): FingerprintKeyState => {
    try {
      return keyStateOf(readFingerprintKey(dataDir()));
    } catch {
      return { status: 'unreadable' };
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
      keyState={keyState}
      activePermanent={activePermanent}
    />
  );
}
