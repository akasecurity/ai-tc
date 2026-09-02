import {
  BLOCKED_WINDOW_MS,
  isBlockedRowApprovable,
  resolveBlockedWindow,
} from '@akasecurity/dashboard-ui';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  dataDir,
  keyStateOf,
  readFingerprintKey,
} from '@akasecurity/persistence';
import type { FingerprintKeyState } from '@akasecurity/schema';
import { toBlockedDetectionDescriptor, toExceptionDescriptor } from '@akasecurity/schema';

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
  // Two ledger reads, two different questions. The strip shows the window the
  // user picked; the rotate dialog has to name what rotation costs, and that is
  // the whole retention window — the same one approveBlocked looks a reference
  // up against. Counting only the selected chip (30 minutes by default, against
  // a day of retention) would understate a one-way action.
  //
  // The store rows carry the keyed valueFingerprint — a correlation key that
  // must never reach the browser. `items` and `blocked` cross into a client
  // component (and so into the RSC payload), so they are projected to their
  // fingerprint-free descriptors here, at the server boundary; `retained`
  // stays server-side and only its count crosses.
  const [items, blocked, retained] = await Promise.all([
    db()
      .exceptions.list({ includeTerminal })
      .then((rows) => rows.map(toExceptionDescriptor)),
    db()
      .exceptions.recentBlocked(BLOCKED_WINDOW_MS[blockedWindow])
      .then((rows) => rows.map(toBlockedDetectionDescriptor)),
    db().exceptions.recentBlocked(BLOCKED_DETECTIONS_RETENTION_MS),
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

  // Only the rows rotation actually takes something from: one already recorded
  // under an older key (or under a key that is now missing) is unapprovable
  // already, so counting it would overstate the loss.
  const approvableBlocked = retained.filter((b) => isBlockedRowApprovable(b, keyState)).length;
  // A relative label must be calculated against the exact same instant during
  // SSR and hydration; otherwise crossing a minute boundary can change its text.
  // eslint-disable-next-line react-hooks/purity -- serialized to the client for hydration parity
  const renderedAt = Date.now();

  return (
    <ExceptionsClient
      items={items}
      blocked={blocked}
      includeTerminal={includeTerminal}
      blockedWindow={blockedWindow}
      keyState={keyState}
      activePermanent={activePermanent}
      approvableBlocked={approvableBlocked}
      renderedAt={renderedAt}
    />
  );
}
