import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_SYNC_STATE_FILENAME,
  ensureDataDirSync,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';

import type { PolicySyncOutcome, PolicySyncResult } from './policy-sync.ts';

/**
 * Where the last sync attempt's OUTCOME is recorded, for `status` to render.
 *
 * NOT `attached-state.json` — that name is already taken by `forward-policy.ts`
 * for the circuit breaker, whose reader treats a foreign shape as CLOSED and
 * whose writer rewrites the file wholesale on every breaker transition. Storing
 * anything else there would be silently destroyed, and that file's own doc
 * states it never holds a credential, a property this one has to preserve too.
 */
// Defined in @akasecurity/persistence, which sits below both detach surfaces
// (`aka detach` and the dashboard's settings action) and owns the list they
// both clear. Re-exported under this package's own name so its consumers are
// unaffected by where the string lives.
export const SYNC_STATE_FILENAME = ATTACHED_SYNC_STATE_FILENAME;

/** The persisted form. Deliberately tiny, and deliberately free of any error text. */
interface PersistedSyncState {
  outcome: PolicySyncOutcome;
  atMs: number;
}

/**
 * The renderable set, validated on read.
 *
 * Growing it is DOWNGRADE-SAFE in the direction that matters: a state written by
 * a build that knows `forbidden` and read back by one that does not fails this
 * check, and `readSyncState` returns null — status then says "no attempt
 * recorded yet". Silence rather than a wrong verdict, which is the same
 * direction every other guard in this package fails in.
 */
const OUTCOMES: ReadonlySet<string> = new Set<PolicySyncOutcome>([
  'ok',
  'not-modified',
  'unauthorized',
  'forbidden',
  'unreachable',
  'invalid-bundle',
]);

export function syncStatePath(dataDir: string): string {
  return join(dataDir, SYNC_STATE_FILENAME);
}

/**
 * Record an attempt. Best-effort: a sync whose result cannot be written is still
 * a sync that happened, and the child is about to exit either way.
 *
 * Only the coarse enum and a timestamp are persisted. The raw error is
 * deliberately dropped rather than stored-and-redacted: a request failure's
 * message can carry the URL, a header echo, or a body fragment, and the only way
 * to be sure none of that reaches a rendered status is never to write it down.
 */
export function writeSyncState(dataDir: string, result: PolicySyncResult): void {
  try {
    ensureDataDirSync(dataDir);
    const state: PersistedSyncState = { outcome: result.outcome, atMs: result.atMs };
    writeOwnerOnlyFileSync(syncStatePath(dataDir), `${JSON.stringify(state)}\n`);
  } catch {
    // Best-effort — never let telemetry bookkeeping fail the sync.
  }
}

/** The last recorded attempt, or `null` when there is none or it is unreadable. */
export function readSyncState(dataDir: string): PolicySyncResult | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(syncStatePath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as { outcome?: unknown; atMs?: unknown };
    // Validate the enum rather than trusting the file: this value is rendered,
    // so an arbitrary string from a hand-edited file must not reach the output.
    if (typeof record.outcome !== 'string' || !OUTCOMES.has(record.outcome)) return null;
    if (typeof record.atMs !== 'number') return null;
    return { outcome: record.outcome as PolicySyncOutcome, atMs: record.atMs };
  } catch {
    return null;
  }
}
