// Keeps an attached machine's sighting key current. Runs in the detached sync
// child, never on a hook path.
import type { SightingKeyStore } from '@akasecurity/persistence';
import {
  createSightingKeyStore,
  keysDir,
  previousVersionFirstSeenAtMs,
  previousVersionUsableUntil,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type { SightingKeyResponse, StoredSightingKeys } from '@akasecurity/schema';
import { isAttached } from '@akasecurity/schema';

import { endpointFingerprint } from './history-sync.ts';
import { withTimeout } from './with-timeout.ts';

/** A stored key at least this old is fetched again. */
export const SIGHTING_KEY_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export const SIGHTING_KEY_REQUEST_TIMEOUT_MS = 30_000;

/**
 * `fresh`    the stored key is younger than {@link SIGHTING_KEY_MAX_AGE_MS} and no previous
 *            version in it has passed its `acceptedUntil`; nothing was fetched.
 * `fetched`  a new map was fetched and replaced the stored one.
 * `failed`   the fetch or the write failed; the stored key is unchanged.
 */
export type SightingKeySyncOutcome = 'fresh' | 'fetched' | 'failed';

export interface RunSightingKeySyncDeps {
  /** The ~/.aka root. */
  base: string;
  settingsDir: string;
  now?: (() => number) | undefined;
  /** Replaces the custody store `vaultKeyCustody` selects. */
  store?: SightingKeyStore | undefined;
}

/**
 * Whether `stored` was issued by the endpoint with `fingerprint`, fetched
 * within the last day by a clock that has not run backwards past it, and holds
 * no previous version whose use ended after the map was fetched: a refetch then
 * drops that version as soon as the deployment stops accepting it. A map
 * fetched once that window had already closed is not fetched again for it, and
 * a version without a readable `acceptedUntil` counts as fresh; neither is
 * ever used, whatever the map holds.
 */
function isFresh(
  stored: StoredSightingKeys | undefined,
  fingerprint: string,
  nowMs: number,
): boolean {
  if (stored?.endpointFingerprint !== fingerprint) return false;
  const age = nowMs - stored.fetchedAtMs;
  if (age < 0 || age >= SIGHTING_KEY_MAX_AGE_MS) return false;
  return (stored.previous ?? []).every((version) => {
    const end = previousVersionUsableUntil(stored, version);
    return Number.isNaN(end) || nowMs < end || stored.fetchedAtMs >= end;
  });
}

/**
 * The first-seen instant of each previous version in `response`: the one
 * `stored` records for a version it already held as previous, and `nowMs`
 * for one that is new to that list.
 *
 * The store takes no lock, so two syncs that overlap can stamp a newly demoted
 * version up to one request window apart. Only this instant can differ: the key
 * material always comes from the response, never from `stored`.
 */
function carryFirstSeen(
  response: SightingKeyResponse,
  stored: StoredSightingKeys | undefined,
  fingerprint: string,
  nowMs: number,
): Record<string, number> | undefined {
  const previous = response.previous ?? [];
  if (previous.length === 0) return undefined;
  const sameEndpoint = stored?.endpointFingerprint === fingerprint ? stored : undefined;
  const held = new Set((sameEndpoint?.previous ?? []).map((p) => p.keyVersion));
  return Object.fromEntries(
    previous.map((p) => [
      String(p.keyVersion),
      sameEndpoint !== undefined && held.has(p.keyVersion)
        ? previousVersionFirstSeenAtMs(sameEndpoint, p.keyVersion)
        : nowMs,
    ]),
  );
}

function readStored(store: SightingKeyStore): StoredSightingKeys | undefined {
  try {
    return store.read();
  } catch {
    return undefined;
  }
}

/**
 * Fetch the sighting key when none is stored, the stored one is a day old, or
 * a previous version in it has passed its `acceptedUntil`.
 *
 * Returns null, and calls nothing, unless the machine is attached: both the
 * settings descriptor and a credential minted for its endpoint. Machine-wide
 * and scoped attachments both fetch. Never throws; a failure leaves the stored
 * key as it was.
 */
export async function runSightingKeySync(
  deps: RunSightingKeySyncDeps,
): Promise<SightingKeySyncOutcome | null> {
  try {
    const settings = readWorkspaceSettings(deps.base);
    const connection = isAttached(settings) ? settings.controlPlane : undefined;
    const state =
      connection === undefined
        ? undefined
        : readControlPlaneCredentialFile(deps.settingsDir, connection);
    if (connection === undefined || !state?.usable) return null;

    const nowMs = (deps.now ?? Date.now)();
    const store =
      deps.store ?? createSightingKeyStore(settings.vaultKeyCustody, keysDir(deps.base));
    const fingerprint = endpointFingerprint(connection.endpoint);
    const stored = readStored(store);
    if (isFresh(stored, fingerprint, nowMs)) return 'fresh';

    const { apiKey } = state.credential;
    const client = createRemoteClient({
      endpoint: connection.endpoint,
      apiKey,
      timeoutMs: SIGHTING_KEY_REQUEST_TIMEOUT_MS,
    });
    const response = await withTimeout(client.getSightingKey(), SIGHTING_KEY_REQUEST_TIMEOUT_MS);
    const firstSeen = carryFirstSeen(response, stored, fingerprint, nowMs);
    store.replace({
      ...response,
      fetchedAtMs: nowMs,
      endpointFingerprint: fingerprint,
      ...(firstSeen === undefined ? {} : { previousFirstSeenAtMs: firstSeen }),
    });
    return 'fetched';
  } catch {
    return 'failed';
  }
}
