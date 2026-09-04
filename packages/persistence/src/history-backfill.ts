import { openLocalDatabase } from './database.ts';

/**
 * Mark every capture already on disk as owed, as of `beforeMs`.
 *
 * The consent-time backfill for the existing-history grant's capture half.
 * Three surfaces record a fresh `historySyncConsent` — `aka attach`,
 * `aka sync-history --on`, and the dashboard's settings action — and each
 * calls this once, right after that write succeeds, with its own "now" as
 * `beforeMs`. What gets marked owed is exactly what is on disk at that
 * instant, never a boundary a later pass could widen; see
 * `SqliteHistorySyncRepository.markCaptureBacklogOwed` for why a marker
 * rather than a time window is what the drain reads at all.
 *
 * BEST-EFFORT and deliberately silent, for the reason
 * `clearAttachmentDerivedState` gives for its own callers: the grant has
 * already been recorded by the time anything reaches this, and a store that
 * cannot be opened or written must not turn a successful consent into a
 * reported failure. A miss here is not permanent — the next grant (a
 * re-attach, or running this command again) calls this again with a newer
 * bound and covers whatever this pass missed, on top of whatever it already
 * marked.
 */
export function seedCaptureBacklogOwed(dataDir: string, beforeMs: number): void {
  try {
    const db = openLocalDatabase(dataDir);
    try {
      db.historySync.markCaptureBacklogOwed(beforeMs);
    } finally {
      db.close();
    }
  } catch {
    // See above: a ledger write that fails here does not undo the grant that
    // was just recorded, and the next one retries it.
  }
}
