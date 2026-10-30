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
import { renderInstant } from '../../lib/rendered-at';
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

  // Vault entries left off the current fingerprint key — a rotation whose
  // per-row re-key did not reach them. Read from the store rather than taken
  // from what `rotateKey` returned, because the rows stay stale long after that
  // call: a reload, a trip into a grant detail route, or a rotation run from
  // `aka exception rotate-key` all leave a returned count with nowhere to live,
  // while the condition itself persists until some later rotation clears it.
  //
  // Only meaningful against a key that is actually present. With the key absent
  // or unreadable there is no current version to compare rows to, and every
  // surface on this page already says so for its own rows — claiming a vault
  // shortfall as well would be a second, worse account of the same one fault.
  //
  // Unguarded on purpose: every other store read on this route is too, so a
  // `secret_vault` that cannot be read fails the page the same way an
  // `exceptions` table that cannot be read already does. Swallowing it to 0
  // would be the silent zero this disclosure exists to abolish.
  const vaultFingerprints =
    keyState.status === 'present'
      ? {
          stale: db().secretVault.countStaleFingerprints(keyState.version),
          total: db().secretVault.countEntries(),
        }
      : { stale: 0, total: 0 };
  // A relative label must be calculated against the exact same instant during
  // SSR and hydration; otherwise crossing a minute boundary can change its text.
  // One instant for the whole route, so both child views measure against it.
  const renderedAt = renderInstant();

  return (
    <ExceptionsClient
      items={items}
      blocked={blocked}
      includeTerminal={includeTerminal}
      blockedWindow={blockedWindow}
      keyState={keyState}
      activePermanent={activePermanent}
      approvableBlocked={approvableBlocked}
      vaultFingerprints={vaultFingerprints}
      renderedAt={renderedAt}
    />
  );
}
