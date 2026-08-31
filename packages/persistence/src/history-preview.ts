import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { getRow } from './internal/rows.ts';
import { DB_FILENAME } from './paths.ts';

// A contended store must not hold up an interactive prompt: fail fast and ask
// the less specific question instead.
const PREVIEW_BUSY_TIMEOUT_MS = 250;

const MS_PER_DAY = 86_400_000;

/** What this machine has already recorded, in the terms a prompt can describe. */
export interface LocalHistoryPreview {
  /** Session roots recorded in the local store. */
  readonly sessions: number;
  /** Whole days between the earliest recorded session and now; 0 when none. */
  readonly days: number;
}

/**
 * How much activity is already recorded on this machine, so a consent prompt can
 * say what it is asking about.
 *
 * Opened only when the store already exists, READ-ONLY, with a short busy
 * timeout, and running no migrations. Asking a question must never create a
 * store, never upgrade one, and never be the reason the surrounding command
 * fails — which is why this takes its own handle rather than going through the
 * usual open.
 *
 * Returns undefined when the store cannot answer, which every caller must treat
 * as "ask without numbers" rather than as zero: a damaged or locked store has
 * unknown history, and describing it as none would understate what a grant
 * covers. A readable store with no sessions returns a zero count, which is a
 * different answer and lets a caller skip the question entirely.
 */
export function readLocalHistoryPreview(
  dataDir: string,
  nowMs: number = Date.now(),
): LocalHistoryPreview | undefined {
  const file = join(dataDir, DB_FILENAME);
  if (!existsSync(file)) return undefined;
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(file, { readOnly: true });
    db.exec(`PRAGMA busy_timeout = ${String(PREVIEW_BUSY_TIMEOUT_MS)}`);
    // count(*) over an empty table is 0; MIN() over one is NULL.
    const row = getRow<{ n: number; earliest: number | null }>(
      db.prepare(
        `SELECT count(*) AS n, MIN(started_at) AS earliest
           FROM audit_events
          WHERE event_type = 'session'`,
      ),
    );
    if (row === undefined) return undefined;
    const earliest = row.earliest;
    return {
      sessions: row.n,
      days: earliest === null ? 0 : Math.max(0, Math.floor((nowMs - earliest) / MS_PER_DAY)),
    };
  } catch {
    // Damaged, locked, or written by a binary whose schema this one predates.
    return undefined;
  } finally {
    db?.close();
  }
}
