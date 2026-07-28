import { randomUUID } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import { FindingStatus, ResolutionMethod } from '@akasecurity/schema';

import { allRows, getRow } from '../internal/rows.ts';
import { latestResolutionStatusSql } from './resolution-sql.ts';

// What a caller supplies to record one disposition of a finding. `status`/
// `method` are typed as @akasecurity/schema's FindingStatus / ResolutionMethod enum
// values, so a caller cannot compile in a string outside the schema vocabulary;
// insertResolution additionally re-parses both against the enums at the write
// boundary, so a value smuggled past the types (a cast, an untyped caller)
// fails loudly instead of persisting garbage. Kept as a bare interface (not a
// registered zod object) per the local-store DTO convention — see
// packages/schema/src/zod/local.ts's read-projection note.
export interface ResolutionInput {
  findingKey: string;
  status: FindingStatus;
  method: ResolutionMethod;
  resolvedAt: number;
  evidence: string;
}

// The newest disposition recorded for a finding key.
export interface Resolution {
  status: FindingStatus;
  method: ResolutionMethod;
  resolvedAt: number;
  evidence: string;
}

interface ResolutionRow {
  status: string;
  method: string;
  resolved_at: number;
  evidence: string | null;
}

interface FindingKeyRow {
  finding_key: string;
}

/**
 * finding_resolution writer/reader, bound to one open DB. Like scan_ledger,
 * finding_resolution is a plugin-local table outside the canonical drizzle
 * schema read/write helpers — queried raw here (mirrors
 * SqliteSecurityRepository), not via the @akasecurity/schema row builders findings.ts
 * uses.
 *
 * Rows are keyed by finding_key (findings.finding_key), NOT the row-specific
 * findings.id, so a disposition recorded against one scan's finding survives
 * a later re-scan re-detecting the same underlying issue under a fresh id.
 * Append-only: every call to `insertResolution` writes a new row rather than
 * updating in place, so the history of dispositions for a key is retained;
 * `latestByKey` reads the newest by created_at. The clock is injectable so
 * created_at is deterministic under test (mirrors SqliteSecurityRepository's
 * injectable `now`). Single-tenant: no tenant predicate on any query.
 *
 * LATEST-RESOLUTION-WINS: `openAtRestKeysForPath` / `resolvedAtRestKeysForPath`
 * classify a key by its NEWEST row only (max created_at, tie-broken by rowid),
 * not by "does ANY row exist" — otherwise a key that was fixed-at-source and
 * later redetected (the same secret re-added) would stay invisibly "caught"
 * under its stale resolved row forever (see scan.ts's reopenRedetectedFindings,
 * which writes a superseding status:'open' row the moment a currently-detected
 * key's latest disposition comes back as resolved). The invariant this
 * maintains: a finding_key present in the current scan is OPEN, regardless of
 * any past resolution history.
 *
 * NOTE for future manual-resolution writers: once
 * acknowledged/dismissed/false-positive dispositions can be written by a human
 * (not just the auto-resolver), "latest status is handled" must keep meaning
 * exactly `status = 'resolved'` here and in SqliteSecurityRepository —
 * 'acknowledged' is accepted risk, not a fix, and must NOT be folded into the
 * same bucket as 'resolved'/caught.
 */
export class SqliteResolutionsRepository {
  private readonly insertStmt: StatementSync;
  private readonly latestStmt: StatementSync;
  private readonly openAtRestStmt: StatementSync;
  private readonly resolvedAtRestStmt: StatementSync;

  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.insertStmt = db.prepare(
      `INSERT INTO finding_resolution (id, finding_key, status, method, resolved_at, evidence, created_at)
       VALUES (:id, :findingKey, :status, :method, :resolvedAt, :evidence, :createdAt)`,
    );
    this.latestStmt = db.prepare(
      `SELECT status, method, resolved_at, evidence
         FROM finding_resolution
        WHERE finding_key = :findingKey
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1`,
    );
    // At-rest = the finding's parent audit event is a code_change whose
    // attributes.file_path matches. "Open" = the key's LATEST resolution row
    // (if any) does not have status 'resolved' — see the class doc for why
    // this is "latest wins", not "any row exists".
    this.openAtRestStmt = db.prepare(
      `SELECT DISTINCT f.finding_key AS finding_key
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
        WHERE e.event_type = 'code_change'
          AND json_extract(e.attributes, '$.file_path') = :path
          AND f.finding_key IS NOT NULL
          AND ${latestResolutionStatusSql('f')} IS NOT 'resolved'`,
    );
    // The complement of openAtRestStmt: keys whose latest resolution status IS
    // 'resolved' — i.e. currently caught. Used by the scanner to find redetect
    // candidates (a currently-produced key that needs re-opening).
    this.resolvedAtRestStmt = db.prepare(
      `SELECT DISTINCT f.finding_key AS finding_key
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
        WHERE e.event_type = 'code_change'
          AND json_extract(e.attributes, '$.file_path') = :path
          AND f.finding_key IS NOT NULL
          AND ${latestResolutionStatusSql('f')} = 'resolved'`,
    );
  }

  /**
   * Insert one disposition row. The repo mints the id and stamps created_at.
   * `status`/`method` are typed AND re-parsed here against @akasecurity/schema's
   * FindingStatus/ResolutionMethod, so the persisted vocabulary can never drift
   * from the schema enums. NOTE for future manual-resolution writers: this is
   * also how a redetected finding gets re-opened (status:'open',
   * method:'redetected') — see the class doc's LATEST-RESOLUTION-WINS note.
   * When acknowledged/dismissed/false-positive writers land, they call this the
   * same way; only `status: 'resolved'` is ever treated as "caught" by the read
   * paths above.
   */
  insertResolution(r: ResolutionInput): void {
    this.insertStmt.run({
      id: randomUUID(),
      findingKey: r.findingKey,
      status: FindingStatus.parse(r.status),
      method: ResolutionMethod.parse(r.method),
      resolvedAt: r.resolvedAt,
      evidence: r.evidence,
      createdAt: this.now(),
    });
  }

  /** The newest disposition recorded for a finding key, or undefined if none. */
  latestByKey(key: string): Resolution | undefined {
    const row = getRow<ResolutionRow>(this.latestStmt, { findingKey: key });
    if (!row) return undefined;
    return {
      // Safe narrows: insertResolution enum-parses both columns on every write,
      // so a stored value outside the schema vocabulary cannot exist.
      status: row.status as FindingStatus,
      method: row.method as ResolutionMethod,
      resolvedAt: row.resolved_at,
      evidence: row.evidence ?? '',
    };
  }

  /**
   * Distinct finding_keys of at-rest (code_change) findings for `path` that
   * have no finding_resolution row yet — the "still open" backlog a scan (or
   * the CLI) surfaces for that file.
   */
  openAtRestKeysForPath(path: string): string[] {
    const rows = allRows<FindingKeyRow>(this.openAtRestStmt, { path });
    return rows.map((r) => r.finding_key);
  }

  /**
   * Distinct finding_keys of at-rest (code_change) findings for `path` whose
   * latest disposition IS 'resolved' — the complement of
   * `openAtRestKeysForPath`. The scanner uses this to detect redetection: a
   * key it just produced again that shows up here needs a superseding 'open'
   * resolution row (see scan.ts).
   */
  resolvedAtRestKeysForPath(path: string): string[] {
    const rows = allRows<FindingKeyRow>(this.resolvedAtRestStmt, { path });
    return rows.map((r) => r.finding_key);
  }
}
