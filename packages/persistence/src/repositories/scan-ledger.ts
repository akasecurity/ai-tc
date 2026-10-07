import type { DatabaseSync, StatementSync } from 'node:sqlite';

import { allRows } from '../internal/rows.ts';
import { failOpenTransaction } from '../internal/transactions.ts';

// One recorded scan of one file: its identity on disk (path), the cheap change
// signals (mtime, content hash), the ruleset it was scanned under, and the
// repository it was in when it was read.
export interface ScanLedgerEntry {
  path: string; // absolute path
  mtime: string; // ISO timestamp at scan time
  contentHash: string;
  rulesetHash: string;
  // The canonical `host/owner/repo` of the repository the file was in when it
  // was read. Absent for a file in no repository with a remote, which is stored
  // as NULL: an entry without one REPLACES the key an earlier read recorded.
  scopeKey?: string | undefined;
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
 * ruleset are excluded from `entriesForRuleset`, so adding a detection rule
 * rescans everything, while `allPaths` still lists them for the deletion
 * sweep. Every query reads the whole store — no row carries an owner column to scope by.
 */
export class SqliteScanLedgerRepository {
  private readonly upsertStmt: StatementSync;
  private readonly readStmt: StatementSync;
  private readonly pathsStmt: StatementSync;
  private readonly pathKeysStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.upsertStmt = db.prepare(
      `INSERT INTO scan_ledger (path, mtime, content_hash, ruleset_hash, scope_key, scanned_at)
       VALUES (:path, :mtime, :contentHash, :rulesetHash, :scopeKey, :scannedAt)
       ON CONFLICT (path) DO UPDATE SET
         mtime = excluded.mtime,
         content_hash = excluded.content_hash,
         ruleset_hash = excluded.ruleset_hash,
         scope_key = excluded.scope_key,
         scanned_at = excluded.scanned_at`,
    );
    this.readStmt = db.prepare(
      `SELECT path, mtime, content_hash AS contentHash
       FROM scan_ledger WHERE ruleset_hash = :rulesetHash`,
    );
    this.pathsStmt = db.prepare(`SELECT path FROM scan_ledger`);
    this.pathKeysStmt = db.prepare(`SELECT path, scope_key AS scopeKey FROM scan_ledger`);
  }

  // Previously scanned files under THIS ruleset, keyed by path. Rows from an
  // older ruleset are simply absent, which reads as "never scanned".
  entriesForRuleset(rulesetHash: string): Map<string, ScanLedgerState> {
    const rows = allRows<{ path: string; mtime: string; contentHash: string }>(this.readStmt, {
      rulesetHash,
    });
    return new Map(rows.map((r) => [r.path, { mtime: r.mtime, contentHash: r.contentHash }]));
  }

  // Every ledgered path, whatever ruleset it was scanned under — the set a
  // deletion sweep checks against disk. A file deleted before a ruleset change
  // keeps a row under the old hash forever, so reading only the current hash
  // would never notice it is gone.
  allPaths(): string[] {
    return allRows<{ path: string }>(this.pathsStmt).map((r) => r.path);
  }

  // Every ledgered path with the repository it was in when it was last read,
  // whatever ruleset it was scanned under: what a deletion sweep needs to say
  // which repository a vanished file belonged to. `undefined` for a row with no
  // key, which is every row written before the column existed.
  pathKeys(): Map<string, string | undefined> {
    const rows = allRows<{ path: string; scopeKey: string | null }>(this.pathKeysStmt);
    return new Map(rows.map((r) => [r.path, r.scopeKey ?? undefined]));
  }

  upsertEntries(entries: ScanLedgerEntry[]): void {
    if (entries.length === 0) return;
    const scannedAt = Date.now();
    // Fail-open: losing scan bookkeeping only costs a rescan next run; it must
    // never abort the scan itself (mirrors recordCapture/upsertPacks).
    failOpenTransaction(this.db, () => {
      for (const entry of entries) {
        this.upsertStmt.run({
          path: entry.path,
          mtime: entry.mtime,
          contentHash: entry.contentHash,
          rulesetHash: entry.rulesetHash,
          scopeKey: entry.scopeKey ?? null,
          scannedAt,
        });
      }
    });
  }
}
