import type { DatabaseSync, StatementSync } from 'node:sqlite';

// One recorded scan of one file: its identity on disk (path), the cheap change
// signals (mtime, content hash), and the ruleset it was scanned under.
export interface ScanLedgerEntry {
  path: string; // absolute path
  mtime: string; // ISO timestamp at scan time
  contentHash: string;
  rulesetHash: string;
}

// What the scanner needs to decide "unchanged, skip": the previous mtime (skip
// without reading) and content hash (skip detection after a touch-only mtime bump).
export interface ScanLedgerState {
  mtime: string;
  contentHash: string;
}

/**
 * scan_ledger writer/reader, bound to one open DB. Tracks every file the
 * worktree scanner has processed — including clean ones, which never become
 * events — so a re-run skips unchanged files instead of re-reading the whole
 * tree. One row per path (latest scan wins); rows written under a different
 * ruleset are excluded from reads, so adding a detection rule rescans
 * everything. The local store is tenant-free (single tenant), so there is no
 * tenant predicate on any query.
 */
export class SqliteScanLedgerRepository {
  private readonly upsertStmt: StatementSync;
  private readonly readStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.upsertStmt = db.prepare(
      `INSERT INTO scan_ledger (path, mtime, content_hash, ruleset_hash, scanned_at)
       VALUES (:path, :mtime, :contentHash, :rulesetHash, :scannedAt)
       ON CONFLICT (path) DO UPDATE SET
         mtime = excluded.mtime,
         content_hash = excluded.content_hash,
         ruleset_hash = excluded.ruleset_hash,
         scanned_at = excluded.scanned_at`,
    );
    this.readStmt = db.prepare(
      `SELECT path, mtime, content_hash AS contentHash
       FROM scan_ledger WHERE ruleset_hash = :rulesetHash`,
    );
  }

  // Previously scanned files under THIS ruleset, keyed by path. Rows from an
  // older ruleset are simply absent, which reads as "never scanned".
  entriesForRuleset(rulesetHash: string): Map<string, ScanLedgerState> {
    const rows = this.readStmt.all({ rulesetHash }) as unknown as {
      path: string;
      mtime: string;
      contentHash: string;
    }[];
    return new Map(rows.map((r) => [r.path, { mtime: r.mtime, contentHash: r.contentHash }]));
  }

  upsertEntries(entries: ScanLedgerEntry[]): void {
    if (entries.length === 0) return;
    const scannedAt = Date.now();
    try {
      this.db.exec('BEGIN');
      try {
        for (const entry of entries) {
          this.upsertStmt.run({
            path: entry.path,
            mtime: entry.mtime,
            contentHash: entry.contentHash,
            rulesetHash: entry.rulesetHash,
            scannedAt,
          });
        }
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw err;
      }
    } catch {
      // Fail-open: losing scan bookkeeping only costs a rescan next run; it must
      // never abort the scan itself (mirrors recordCapture/upsertPacks).
    }
  }
}
