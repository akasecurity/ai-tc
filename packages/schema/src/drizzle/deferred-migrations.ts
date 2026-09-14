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
// The build also holds the store's write lock for its whole duration, and a
// default open writes on its way in. So any other process that opens the store
// meanwhile waits out its busy timeout and throws `database is locked`; a hook
// that meets a build waits that long and then scans and records nothing. Opting
// in belongs in a pass that runs with no session live, never on a request path.
//
// A read that names one of these indexes must carry a fallback statement for the
// index being absent, so that skipping them changes what a read costs and never
// what it returns.
//
// The applier never re-runs a ledgered migration, so an index one of these built
// stays gone if a later migration removes it. A drizzle table-recreate of a table
// they are on does that, because it drops the table and its indexes with it.
//
// Three rules keep the set honest, and deferred-migrations.test.ts holds all
// three:
//  - a listed migration contains nothing but CREATE INDEX statements, since a
//    skipped column or table would break every reader of it;
//  - no migration outside the set creates an index a listed one creates, since
//    the applier builds any missing index a migration names, which would put the
//    build back on the hook path;
//  - no later migration drops or renames a table these indexes are on, or drops
//    one of the indexes.
export const DEFERRED_MIGRATION_TAGS = [
  '0031_audit_capture_by_time_index',
  '0032_audit_capture_by_id_index',
  '0033_audit_capture_location_index',
  '0034_findings_read_indexes',
] as const;

export type DeferredMigrationTag = (typeof DEFERRED_MIGRATION_TAGS)[number];
