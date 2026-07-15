import { randomUUID } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type {
  BlockedDetection,
  BlockedDetectionInput,
  DetectionCategory,
  DetectionException as DetectionExceptionType,
  ExceptionBundleEntry as ExceptionBundleEntryType,
} from '@akasecurity/schema';
import {
  DetectionException,
  epochMillisToIso,
  ExceptionBundleEntry,
  isoToEpochMillis,
} from '@akasecurity/schema';

import { escapeLikePattern } from './sql-utils.ts';

// What the caller supplies to grant an exception; the repo mints the id and
// stamps created_at/updated_at, and a fresh grant always starts unused.
export type CreateExceptionInput = Pick<
  DetectionExceptionType,
  | 'ruleId'
  | 'category'
  | 'valueFingerprint'
  | 'keyVersion'
  | 'maskedValue'
  | 'scope'
  | 'expiresAt'
  | 'maxUses'
  | 'justification'
  | 'conditions'
  | 'createdBy'
  | 'createdVia'
>;

// The ledger-entry shapes live in @akasecurity/schema (zod/exception.ts), shared with
// the web-ui's approve flow; re-exported so persistence consumers keep importing
// them from here.
export type { BlockedDetection, BlockedDetectionInput };

// The default lookback for `recentBlocked` (the CLI's `aka exception approve`
// picker) — rows older than this are excluded from reads by default.
export const BLOCKED_DETECTIONS_TTL_MS = 30 * 60 * 1000;

// How long a blocked-detections ledger row is retained in storage before it's
// swept on write. Longer than the default TTL so the web dashboard's wider
// lookback windows (up to 24h) still have rows to show — the ledger is a
// short-lived convenience, not a durable record (the findings table is).
export const BLOCKED_DETECTIONS_RETENTION_MS = 24 * 60 * 60 * 1000;

/**
 * Thrown by {@link SqliteExceptionsRepository.create} when an ACTIVE grant
 * already exists for the same (ruleId, valueFingerprint, keyVersion) — the
 * `uq_exceptions_active` partial unique index. Tagged by `code` so callers can
 * match without `instanceof` across bundle boundaries.
 */
export class DuplicateActiveExceptionError extends Error {
  readonly code = 'duplicate-active-exception';
  constructor(ruleId: string) {
    super(
      `duplicate-active-exception: an active exception already exists for rule "${ruleId}" and this value — revoke it before granting a new one`,
    );
    this.name = 'DuplicateActiveExceptionError';
  }
}

/**
 * Thrown by {@link SqliteExceptionsRepository.getByIdPrefix} when the prefix
 * matches more than one exception. The CLI turns this into "ambiguous id, be
 * more specific". Tagged by `code`, like {@link DuplicateActiveExceptionError}.
 */
export class AmbiguousExceptionIdError extends Error {
  readonly code = 'ambiguous-exception-id';
  constructor(prefix: string) {
    super(
      `ambiguous-exception-id: "${prefix}" matches more than one exception — add more characters`,
    );
    this.name = 'AmbiguousExceptionIdError';
  }
}

// node:sqlite surfaces constraint violations as ERR_SQLITE_ERROR carrying the
// SQLite extended result code; 2067 is SQLITE_CONSTRAINT_UNIQUE.
const SQLITE_CONSTRAINT_UNIQUE = 2067;

function isUniqueConstraintError(err: unknown): boolean {
  return (
    err instanceof Error &&
    ((err as { errcode?: number }).errcode === SQLITE_CONSTRAINT_UNIQUE ||
      err.message.includes('UNIQUE constraint failed'))
  );
}

interface ExceptionRow {
  id: string;
  rule_id: string;
  category: string;
  value_fingerprint: string;
  key_version: number;
  masked_value: string;
  scope: string;
  expires_at: number | null;
  max_uses: number | null;
  use_count: number;
  last_used_at: number | null;
  justification: string;
  conditions: string | null;
  created_by: string;
  created_via: string;
  created_at: number;
  updated_at: number;
  revoked_at: number | null;
  revoked_by: string | null;
  revoke_reason: string | null;
}

interface BlockedDetectionRow {
  reference: string;
  rule_id: string;
  category: string;
  value_fingerprint: string;
  key_version: number;
  masked_value: string;
  session_id: string | null;
  repo: string | null;
  blocked_at: number;
}

// A grant applies while it is unrevoked, unexpired, and under its use budget.
// State is DERIVED from these columns, never stored — a status column would be
// a second source of truth that a crashed sweep could leave stale. This
// predicate is the single definition of "active"; correctness never depends on
// a cleanup sweep.
const ACTIVE_PREDICATE = `revoked_at IS NULL
     AND (expires_at IS NULL OR expires_at > :now)
     AND (max_uses IS NULL OR use_count < max_uses)`;

/**
 * Detection-exception grants + the short-lived blocked-detections ledger,
 * bound to one open DB. An exception is keyed by (ruleId, keyed fingerprint of
 * the exact detected value): rows carry the HMAC fingerprint and a masked
 * preview — never the raw value, and never a reversible copy. Consumed,
 * expired, and revoked rows are audit evidence: nothing here hard-deletes
 * except the retention sweep over long-terminal rows and the 30-minute
 * blocked-detections sweep. The local store is tenant-free (single tenant),
 * so there is no tenant predicate on any query.
 */
export class SqliteExceptionsRepository {
  private readonly consumeStmt: StatementSync;
  private readonly insertBlockedStmt: StatementSync;
  private readonly sweepBlockedStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // The fail-secure primitive: one-time semantics ride a single conditional
    // UPDATE (SQLite serializes writers, so this is race-free on one machine).
    // changes === 1 → the grant applies; 0 rows or any error → enforce as usual.
    this.consumeStmt = db.prepare(
      `UPDATE exceptions
          SET use_count = use_count + 1, last_used_at = :now, updated_at = :now
        WHERE id = :id AND ${ACTIVE_PREDICATE}`,
    );
    this.insertBlockedStmt = db.prepare(
      // OR REPLACE: `reference` is caller-supplied and this write is
      // best-effort bookkeeping on the hook path — a reused reference must
      // update the row, never surface an error to enforcement.
      `INSERT OR REPLACE INTO blocked_detections (reference, rule_id, category, value_fingerprint, key_version, masked_value, session_id, repo, blocked_at)
       VALUES (:reference, :ruleId, :category, :valueFingerprint, :keyVersion, :maskedValue, :sessionId, :repo, :blockedAt)`,
    );
    this.sweepBlockedStmt = db.prepare(
      'DELETE FROM blocked_detections WHERE blocked_at <= :cutoff',
    );
  }

  /**
   * Insert one exception grant. The repo mints the id and stamps
   * created_at/updated_at. A collision on the one-unrevoked-grant-per
   * (rule, fingerprint, keyVersion) index is resolved by inspecting the
   * collider: a TERMINAL one (expired or budget-exhausted — it still occupies
   * the partial-index slot until swept) is auto-revoked as superseded and the
   * insert retried, so re-granting after a consumed `once` just works. A
   * genuinely ACTIVE collider rejects with
   * {@link DuplicateActiveExceptionError}.
   */
  create(input: CreateExceptionInput): Promise<DetectionExceptionType> {
    // Thin promise shell over the sync sqlite work so EVERY failure path is a
    // rejection (a bare sync throw would escape a promise-chain caller before
    // .catch attaches).
    try {
      return Promise.resolve(this.createSync(input));
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private createSync(input: CreateExceptionInput): DetectionExceptionType {
    // No capture fact carries a provider yet, so a provider-conditioned grant
    // could never match — reject at creation rather than store a grant that
    // silently never fires. Lift once the provider fact is threaded through.
    if (input.conditions?.provider !== undefined) {
      throw new Error(
        'provider conditions are not supported yet — a grant with one would never apply',
      );
    }
    const id = randomUUID();
    const now = Date.now();
    try {
      this.insertExceptionRow(id, input, now);
    } catch (err) {
      if (!isUniqueConstraintError(err)) throw err;
      // The index guards UNREVOKED rows, which is wider than ACTIVE: a
      // consumed/expired grant holds the slot until swept. Supersede a
      // terminal collider and retry, inside one transaction so two concurrent
      // creates cannot both claim the freed slot.
      // Skip our own BEGIN/COMMIT/ROLLBACK when already nested inside an
      // outer db.transaction() — node:sqlite forbids nested BEGIN, and an
      // outer rollback already covers this retry's work on throw.
      const nested = this.db.isTransaction;
      if (!nested) this.db.exec('BEGIN IMMEDIATE');
      try {
        const superseded = this.db
          .prepare(
            `UPDATE exceptions
                SET revoked_at = :now, revoked_by = :revokedBy,
                    revoke_reason = 'superseded by a new grant for the same value',
                    updated_at = :now
              WHERE rule_id = :ruleId AND value_fingerprint = :valueFingerprint
                AND key_version = :keyVersion AND revoked_at IS NULL
                AND ((expires_at IS NOT NULL AND expires_at <= :now)
                  OR (max_uses IS NOT NULL AND use_count >= max_uses))`,
          )
          .run({
            now,
            revokedBy: input.createdBy,
            ruleId: input.ruleId,
            valueFingerprint: input.valueFingerprint,
            keyVersion: input.keyVersion,
          });
        if (Number(superseded.changes) !== 1) {
          // Nothing terminal to free — the collider is genuinely active.
          throw new DuplicateActiveExceptionError(input.ruleId);
        }
        this.insertExceptionRow(id, input, now);
        if (!nested) this.db.exec('COMMIT');
      } catch (retryErr) {
        if (!nested) this.db.exec('ROLLBACK');
        throw retryErr;
      }
    }
    // Read the row back so the returned shape goes through the same
    // column↔contract mapping as every other read.
    const row = this.db
      .prepare('SELECT * FROM exceptions WHERE id = :id')
      .get({ id }) as unknown as ExceptionRow;
    return parseExceptionRow(row);
  }

  private insertExceptionRow(id: string, input: CreateExceptionInput, now: number): void {
    this.db
      .prepare(
        `INSERT INTO exceptions (
             id, rule_id, category, value_fingerprint, key_version, masked_value,
             scope, expires_at, max_uses, use_count, last_used_at, justification,
             conditions, created_by, created_via, created_at, updated_at
           ) VALUES (
             :id, :ruleId, :category, :valueFingerprint, :keyVersion, :maskedValue,
             :scope, :expiresAt, :maxUses, 0, NULL, :justification,
             :conditions, :createdBy, :createdVia, :now, :now
           )`,
      )
      .run({
        id,
        ruleId: input.ruleId,
        category: input.category,
        valueFingerprint: input.valueFingerprint,
        keyVersion: input.keyVersion,
        maskedValue: input.maskedValue,
        scope: input.scope,
        expiresAt: input.expiresAt === null ? null : isoToEpochMillis(input.expiresAt),
        maxUses: input.maxUses,
        justification: input.justification,
        conditions: input.conditions === null ? null : JSON.stringify(input.conditions),
        createdBy: input.createdBy,
        createdVia: input.createdVia,
        now,
      });
  }

  /**
   * Exceptions newest-first. Default is ACTIVE rows only (the derived-state
   * predicate); `includeTerminal` returns everything — consumed, expired, and
   * revoked rows are retained as audit evidence.
   */
  list(opts?: { includeTerminal?: boolean }): Promise<DetectionExceptionType[]> {
    const where = opts?.includeTerminal ? '' : `WHERE ${ACTIVE_PREDICATE}`;
    const rows = this.db
      .prepare(`SELECT * FROM exceptions ${where} ORDER BY created_at DESC, rowid DESC`)
      .all(opts?.includeTerminal ? {} : { now: Date.now() }) as unknown as ExceptionRow[];
    const exceptions: DetectionExceptionType[] = [];
    for (const row of rows) {
      try {
        exceptions.push(parseExceptionRow(row));
      } catch {
        // Skip a malformed/foreign exception row rather than failing the read.
      }
    }
    return Promise.resolve(exceptions);
  }

  /**
   * Exact id or unique prefix match (regardless of active state — show/revoke
   * must reach terminal rows too). Unknown prefix → undefined; a prefix
   * matching more than one row throws {@link AmbiguousExceptionIdError}.
   */
  getByIdPrefix(prefix: string): Promise<DetectionExceptionType | undefined> {
    if (prefix.length === 0) return Promise.resolve(undefined);
    // The prefix is matched LITERALLY: ids are UUIDs, so an unescaped %/_
    // (e.g. `aka exception show %`) would wildcard-match an arbitrary row or
    // trip the ambiguity error instead of finding nothing.
    const rows = this.db
      .prepare(String.raw`SELECT * FROM exceptions WHERE id LIKE :pattern ESCAPE '\' LIMIT 2`)
      .all({ pattern: `${escapeLikePattern(prefix)}%` }) as unknown as ExceptionRow[];
    // Ids are equal-length UUIDs, so a full id can never also be a strict
    // prefix of another — no exact-match tiebreak is needed: >1 hit is
    // genuinely ambiguous.
    if (rows.length > 1) {
      return Promise.reject(new AmbiguousExceptionIdError(prefix));
    }
    const match = rows[0];
    if (!match) return Promise.resolve(undefined);
    try {
      return Promise.resolve(parseExceptionRow(match));
    } catch {
      // A malformed/foreign row reads as absent, like list() skipping it.
      return Promise.resolve(undefined);
    }
  }

  /**
   * Revoke an active grant (terminal; the row is retained as audit evidence).
   * True when a row transitioned — false if the id is unknown or the grant was
   * already revoked.
   */
  revoke(id: string, revokedBy: string, reason?: string): Promise<boolean> {
    const now = Date.now();
    const result = this.db
      .prepare(
        `UPDATE exceptions
            SET revoked_at = :now, revoked_by = :revokedBy, revoke_reason = :reason, updated_at = :now
          WHERE id = :id AND revoked_at IS NULL`,
      )
      .run({ id, revokedBy, reason: reason ?? null, now });
    return Promise.resolve(Number(result.changes) === 1);
  }

  /**
   * The fail-secure primitive: atomically claim one use of a grant. True (one
   * row updated) means the exception applies; false — or a throw, which
   * callers must treat identically — means it does not and the detection is
   * enforced as usual. Deliberately NOT wrapped in try/catch.
   */
  consume(id: string, now = Date.now()): Promise<boolean> {
    const result = this.consumeStmt.run({ id, now });
    return Promise.resolve(Number(result.changes) === 1);
  }

  /**
   * The evaluation subset of every active grant under one fingerprint key
   * version — what rides the policy bundle to the hook. Grants written under
   * a different (rotated-away) key never match, so they are excluded at read.
   */
  activeBundleEntries(keyVersion: number, now = Date.now()): Promise<ExceptionBundleEntryType[]> {
    const rows = this.db
      .prepare(
        `SELECT * FROM exceptions
          WHERE key_version = :keyVersion AND ${ACTIVE_PREDICATE}
          ORDER BY created_at DESC, rowid DESC`,
      )
      .all({ keyVersion, now }) as unknown as ExceptionRow[];
    const entries: ExceptionBundleEntryType[] = [];
    for (const row of rows) {
      try {
        const conditions: unknown = row.conditions === null ? null : JSON.parse(row.conditions);
        entries.push(
          ExceptionBundleEntry.parse({
            id: row.id,
            ruleId: row.rule_id,
            valueFingerprint: row.value_fingerprint,
            keyVersion: row.key_version,
            expiresAt: row.expires_at === null ? null : epochMillisToIso(row.expires_at),
            maxUses: row.max_uses,
            useCount: row.use_count,
            conditions,
          }),
        );
      } catch {
        // Skip a malformed/foreign exception row rather than failing the read.
      }
    }
    return Promise.resolve(entries);
  }

  /**
   * Record a just-blocked/redacted detection so the CLI approve flow can grant
   * an exception from the stored fingerprint — the user never retypes the
   * value, and the value itself never reaches this ledger. Sweeps rows older
   * than the retention window on every write, so the ledger self-limits.
   */
  recordBlocked(entry: BlockedDetectionInput): Promise<void> {
    const now = Date.now();
    this.sweepBlockedStmt.run({ cutoff: now - BLOCKED_DETECTIONS_RETENTION_MS });
    this.insertBlockedStmt.run({
      reference: entry.reference,
      ruleId: entry.ruleId,
      category: entry.category,
      valueFingerprint: entry.valueFingerprint,
      keyVersion: entry.keyVersion,
      maskedValue: entry.maskedValue,
      sessionId: entry.sessionId,
      repo: entry.repo,
      blockedAt: now,
    });
    return Promise.resolve();
  }

  /** Blocked detections within the window (default: the 30-minute TTL), newest-first. */
  recentBlocked(windowMs = BLOCKED_DETECTIONS_TTL_MS): Promise<BlockedDetection[]> {
    const rows = this.db
      .prepare(
        `SELECT * FROM blocked_detections
          WHERE blocked_at > :cutoff
          ORDER BY blocked_at DESC, rowid DESC`,
      )
      .all({ cutoff: Date.now() - windowMs }) as unknown as BlockedDetectionRow[];
    return Promise.resolve(
      rows.map((row) => ({
        reference: row.reference,
        ruleId: row.rule_id,
        category: row.category as DetectionCategory,
        valueFingerprint: row.value_fingerprint,
        keyVersion: row.key_version,
        maskedValue: row.masked_value,
        sessionId: row.session_id,
        repo: row.repo,
        blockedAt: epochMillisToIso(row.blocked_at),
      })),
    );
  }

  /**
   * Retention sweep: delete TERMINAL rows (revoked, expired, or use-budget
   * exhausted) whose last transition is older than the retention window.
   * Active grants are never touched — evaluation ignores terminal rows by
   * predicate, so correctness never depends on this sweep; it only bounds how
   * long the audit evidence is kept locally. Returns the deleted count.
   */
  sweepTerminal(retentionMs: number, now = Date.now()): Promise<number> {
    const result = this.db
      .prepare(
        `DELETE FROM exceptions
          WHERE updated_at < :cutoff
            AND (revoked_at IS NOT NULL
                 OR (expires_at IS NOT NULL AND expires_at <= :now)
                 OR (max_uses IS NOT NULL AND use_count >= max_uses))`,
      )
      .run({ cutoff: now - retentionMs, now });
    return Promise.resolve(Number(result.changes));
  }
}

// Map a DB row (ms-epoch integers, JSON text) onto the contract shape (ISO
// datetime strings, parsed conditions), validated by DetectionException.parse.
function parseExceptionRow(row: ExceptionRow): DetectionExceptionType {
  const conditions: unknown = row.conditions === null ? null : JSON.parse(row.conditions);
  return DetectionException.parse({
    id: row.id,
    ruleId: row.rule_id,
    category: row.category,
    valueFingerprint: row.value_fingerprint,
    keyVersion: row.key_version,
    maskedValue: row.masked_value,
    scope: row.scope,
    expiresAt: row.expires_at === null ? null : epochMillisToIso(row.expires_at),
    maxUses: row.max_uses,
    useCount: row.use_count,
    lastUsedAt: row.last_used_at === null ? null : epochMillisToIso(row.last_used_at),
    justification: row.justification,
    conditions,
    createdBy: row.created_by,
    createdVia: row.created_via,
    createdAt: epochMillisToIso(row.created_at),
    updatedAt: epochMillisToIso(row.updated_at),
    revokedAt: row.revoked_at === null ? null : epochMillisToIso(row.revoked_at),
    revokedBy: row.revoked_by,
    revokeReason: row.revoke_reason,
  });
}
