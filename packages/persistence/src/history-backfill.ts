import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from './database.ts';
import { DB_FILENAME } from './paths.ts';

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
 *
 * NO STORE IS NOT A STORE THAT FAILED TO OPEN — the same distinction
 * `readLocalHistoryPreview` draws on the same `aka attach` prompt path, and
 * for the same reason: a machine that has never run `aka init` has no
 * capture backlog to mark by definition, so opening `openLocalDatabase` here
 * would create the file and run every migration in the ledger — synchronously,
 * inside this catch, after the attach has already been reported successful —
 * to mark zero rows. Skip before that call ever runs, exactly as the preview
 * does with `existsSync`.
 */
export function seedCaptureBacklogOwed(dataDir: string, beforeMs: number): void {
  if (!existsSync(join(dataDir, DB_FILENAME))) return;
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
