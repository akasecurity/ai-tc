import { epochMillisToIso } from '../time.ts';
import { type FindingDelivery, SyncFailureReason } from './finding.ts';

/** The audit_events columns a finding's delivery state is derived from. */
export interface FindingDeliveryInputs {
  /** `event_type` of the event the finding was most recently detected in. */
  kind: string;
  /** `synced_at`: NULL undelivered, positive epoch ms delivered, otherwise terminal. */
  syncedAt: number | null;
  /** `sync_claimed_at`: set while a pass is sending the row. */
  syncClaimedAt: number | null;
  /** `sync_failed_at`: when a terminal stamp was written. */
  syncFailedAt: number | null;
  /** `sync_failure`: why a terminal stamp was written. */
  syncFailure: string | null;
  /** `outbox_owed`: 1 when the live forward could not confirm delivery. */
  outboxOwed: number | null;
}

const KNOWN_REASONS: readonly string[] = SyncFailureReason.options;

function knownReason(value: string | null): SyncFailureReason | undefined {
  return value !== null && KNOWN_REASONS.includes(value) ? (value as SyncFailureReason) : undefined;
}

/**
 * A finding's delivery state, from the sync columns of the event it was most
 * recently detected in. The first matching rule wins:
 *
 *   1. a `code_change` event is a local scan — scanned files are never sent
 *   2. a positive `synced_at` is a delivery time
 *   3. any other `synced_at` is a terminal stamp
 *   4. an owed or claimed row is waiting to be sent
 *   5. anything else was never queued
 */
export function deriveFindingDelivery(row: FindingDeliveryInputs): FindingDelivery {
  if (row.kind === 'code_change') return { state: 'local_scan' };
  if (row.syncedAt !== null && row.syncedAt > 0) {
    return { state: 'sent', at: epochMillisToIso(row.syncedAt) };
  }
  if (row.syncedAt !== null) {
    const reason = knownReason(row.syncFailure);
    return {
      state: 'not_sent',
      ...(row.syncFailedAt === null ? {} : { at: epochMillisToIso(row.syncFailedAt) }),
      ...(reason === undefined ? {} : { reason }),
    };
  }
  if (row.outboxOwed === 1 || row.syncClaimedAt !== null) return { state: 'queued' };
  return { state: 'never_offered' };
}
