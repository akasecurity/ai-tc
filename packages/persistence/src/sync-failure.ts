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
 *   undelivered. Declared here so the CHECK admits it; nothing writes it yet,
 *   and that is deliberate rather than an oversight. A CHECK cannot be widened
 *   in place on SQLite — admitting one more member means rewriting the table —
 *   so a member the detach path is going to need is cheaper to admit now than
 *   to add later.
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
 * The CHECK predicate, built from the list so the constraint and the writers
 * cannot drift.
 *
 * `IS NULL OR … IN (…)` rather than a bare `IN`: the column is added by
 * `ALTER TABLE ADD COLUMN` to a table that already holds rows, and every one of
 * them reads NULL. SQLite does not validate existing rows at ALTER time, but a
 * later `UPDATE` that touched such a row would have to satisfy the constraint,
 * and a bare `IN` would refuse the NULL the row legitimately carries.
 *
 * Single-quoted literals, and the members are compile-time constants from this
 * file — never anything that reached the process from outside it.
 */
export function syncFailureCheckPredicate(column = 'sync_failure'): string {
  const members = SYNC_FAILURE_REASONS.map((r) => `'${r}'`).join(', ');
  return `${column} IS NULL OR ${column} IN (${members})`;
}
