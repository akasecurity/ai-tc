/**
 * The drain's progress file, which now lives in `@akasecurity/persistence`.
 *
 * Re-exported here because two surfaces read it from opposite sides of a package
 * wall — the CLI's status block and the dashboard's sync panel — and the
 * dashboard may not import this package. Kept as a re-export rather than moving
 * every caller so the reader and the writer stay one module: they share a
 * SPEC_VERSION, and a validator split from its writer drifts on the next bump.
 */
export {
  HISTORY_SYNC_STATE_FILENAME,
  type HistorySyncOutcome,
  type HistorySyncPhase,
  type HistorySyncState,
  historySyncStatePath,
  readHistorySyncState,
  writeHistorySyncState,
} from '@akasecurity/persistence';
