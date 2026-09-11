/**
 * Why a row this machine owed the deployment will not be sent again as it is.
 *
 * ONE SOURCE, because two consumers must agree and they live on opposite sides
 * of the store: the migration builds this list into a CHECK constraint on
 * `audit_events.sync_failure`, and the ledger writes values into it. A second
 * spelling would be a constraint violation at runtime rather than a type error
 * at build, on a write path whose whole job is to record why something failed.
 *
 * WHY AN ENUM AND NOT FREE TEXT. The tree already gives this reason three
 * times — `forward-policy.ts` keeps its `lastFailure` an enum because "a
 * message from a failed request can carry the URL", and `history-state.ts` and
 * `sync-state.ts` repeat it. Here it is stricter still: this column sits in the
 * same row as `content`, it is queryable, it is exported with the store, and a
 * surface renders it. CHECK-enforced, so the store is structurally incapable of
 * holding anything else rather than merely trusted not to.
 *
 * THE MEMBERS, and the distinction that matters:
 *
 * - `deployment_refused` — THIS deployment understood the request and rejected
 *   it (HTTP 400/413/422). Its verdict, not a fact about the row: another
 *   deployment with a different body limit may take the same bytes. So it is
 *   terminal only for as long as this machine points at this deployment, and
 *   the structural re-arm clears it when the deployment changes.
 * - `payload_invalid` — this machine could not express the row on the wire at
 *   all: a capture that cannot be rebuilt, or a body the client itself refused
 *   to send. It fails identically against every deployment, so it is terminal
 *   everywhere and the re-arm leaves it alone.
 * - `detached_undelivered` — the attached window closed with the row still
 *   undelivered, so it was never offered to anyone. Not a fault of the row or
 *   of a deployment. Terminal for the attachment that closed over it, and freed
 *   by a change of deployment like a refusal, since the next deployment has seen
 *   none of this machine's history.
 *
 * A row carrying one of these keeps `synced_at` at the skip sentinel. The
 * column answers "why", never "whether" — nothing reads `sync_failure` to
 * decide if a row is outstanding.
 */
export const SYNC_FAILURE_REASONS = [
  'deployment_refused',
  'payload_invalid',
  'detached_undelivered',
] as const;

export type SyncFailureReason = (typeof SYNC_FAILURE_REASONS)[number];

/**
 * The condition a write must NOT satisfy, built from the list so the guard and
 * the writers cannot drift.
 *
 * ENFORCED BY A TRIGGER PAIR RATHER THAN A CHECK, and the reason is a measured
 * one about where this column is installed. A CHECK can only arrive with the
 * column, and `ALTER TABLE ADD COLUMN` carrying one makes SQLite scan the whole
 * table to validate rows that are all NULL: measured linear in table size, and
 * 23 seconds on a real 6 GB store. A plain ADD COLUMN is constant-time at 0.1 ms
 * whatever the size, and creating the triggers is free.
 *
 * That difference decides it, because this runs inside the call every hook
 * makes to open the store, under a host timeout of ten seconds — and on a host
 * that reads a killed hook as a refusal, a migration that cannot finish inside
 * the timeout does not merely fail, it blocks the user's work and then rolls
 * back and does it again on the next hook.
 *
 * The guarantee is unchanged: a value outside the set is refused by the database
 * on INSERT and on UPDATE alike, so the store stays structurally incapable of
 * holding one rather than trusted not to.
 *
 * Single-quoted literals, and the members are compile-time constants from this
 * file — never anything that reached the process from outside it.
 */
export function syncFailureRejectCondition(column = 'sync_failure'): string {
  const members = SYNC_FAILURE_REASONS.map((r) => `'${r}'`).join(', ');
  return `NEW.${column} IS NOT NULL AND NEW.${column} NOT IN (${members})`;
}
