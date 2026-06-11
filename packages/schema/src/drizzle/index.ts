// Drizzle schema re-exports.
//
// The local store tables (events, findings, policies, installed_packs) are defined
// in ./local/sqlite.ts and consumed via the row mappers in zod/local.ts — the
// plugin/CLI/web-ui read them through @akasecurity/persistence (node:sqlite), not
// Drizzle. What is exported here are the shared column helpers and the base
// storage-row contracts used to keep those definitions consistent.

// Shared column-name constants.
export * from './columns.ts';

// Base storage-row contracts — the column set of every local-store table.
// Consumed by the local-store adherence guard (drizzle/adherence.test.ts).
export * from './base-rows.ts';
