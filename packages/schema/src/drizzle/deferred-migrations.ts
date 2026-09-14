// Migrations the local-store opener skips unless its caller opts in.
//
// Each one creates only indexes whose build reads every capture row's attribute
// bag. `audit_events` keeps a body of up to tens of kilobytes in `content`,
// declared before `attributes`, and the columns these indexes carry are VIRTUAL
// generated columns over that bag — so building one walks every capture row's
// overflow chain. That is tens of seconds on a large store, and a plugin hook
// opens the store under its host's timeout; a hook killed mid-build rolls the
// index back and the next hook starts it again.
//
// Every read that names one of these indexes carries a fallback statement for
// the index being absent, so skipping them changes what a read costs and never
// what it returns.
//
// Two rules keep the set honest, and deferred-migrations.test.ts holds both: a
// listed migration contains nothing but CREATE INDEX statements (a skipped
// column or table would break every reader of it), and no migration outside the
// set creates an index a listed one creates (the applier builds any missing
// index a migration names, which would put the build back on the hook path).
export const DEFERRED_MIGRATION_TAGS = [
  '0031_audit_capture_by_time_index',
  '0032_audit_capture_by_id_index',
  '0033_audit_capture_location_index',
  '0034_findings_read_indexes',
] as const;

export type DeferredMigrationTag = (typeof DEFERRED_MIGRATION_TAGS)[number];
