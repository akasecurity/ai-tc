// The SQLite store behind the reversible secret vault: one row per detected
// VALUE in `secret_vault`, plus the append-only de-reference audit in
// `secret_vault_deref`.
//
// Two invariants this module owns:
//
//  1. One value, one row, one pointer. `value_fingerprint` carries a unique
//     index, and a repeat detection bumps the counters on the EXISTING row
//     instead of minting a second one. The caller's category and freshly sealed
//     ciphertext on that repeat call are discarded — re-minting would put a
//     second wire token in circulation for the same secret.
//  2. Purging values never erases the audit. `secret_vault_deref` has no foreign
//     key to `secret_vault`, and `purgeAll` deletes only the value rows, so the
//     record that a de-reference happened outlives the values themselves.
//
// Timestamps cross this boundary as epoch milliseconds and are stored as SQLite
// integers.
import { randomUUID } from 'node:crypto';
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type {
  DetokenizeTarget,
  ListVaultDerefsQuery,
  ListVaultDerefsResponse,
  ListVaultInventoryQuery,
  ListVaultInventoryResponse,
  ListVaultReuseQuery,
  ListVaultReuseResponse,
  VaultDeref,
  VaultDerefOutcome,
  VaultDerefReason,
  VaultInventoryEntry,
  VaultSighting,
  VaultSightingKind,
} from '@akasecurity/schema';
import {
  DEFAULT_VAULT_DEREFS_LIMIT,
  DEFAULT_VAULT_INVENTORY_LIMIT,
  MAX_VAULT_PAGE_LIMIT,
  POINTER_FORMAT_VERSION,
} from '@akasecurity/schema';

import { parseJsonObject } from '../internal/json.ts';
import { decodeKeysetCursor, encodeKeysetCursor } from '../internal/keyset-cursor.ts';
import { allRows, bindParams, countScalar, getRow } from '../internal/rows.ts';
import { placeholders } from '../internal/sql-text.ts';
import { withTransaction } from '../internal/transactions.ts';
import { ACTIVE_REVEAL_GRANT_PREDICATE } from './exceptions.ts';

/**
 * The page size a read will actually use.
 *
 * The Server Actions parse `limit` against the same ceiling before it reaches
 * here, so on the web path this is redundant — but the ceiling protects an
 * invariant of the STORE rather than of that one caller: `sightingsFor` hydrates
 * a page through one `IN (…)` carrying a bind variable per row, and SQLite
 * refuses to prepare past 32766 of them. Anything constructing this repository
 * directly would otherwise reach that as a thrown prepare.
 *
 * `trunc` and the floor of 1 are not decoration. A fractional limit binds as a
 * SQLite `datatype mismatch`, and 0 asks for one row, keeps none, and reports no
 * next cursor — a silently empty page that reads as the end of the list.
 */
function pageLimit(requested: number | undefined, fallback: number): number {
  if (requested === undefined) return fallback;
  return Math.min(Math.max(1, Math.trunc(requested)), MAX_VAULT_PAGE_LIMIT);
}

/** What a caller supplies when it asks for a value to be vaulted. */
export interface VaultRowInsert {
  pointerId: string;
  valueFingerprint: string;
  fingerprintKeyVersion: number;
  keyVersion: number;
  // The pointer-format generation the row's AAD is bound under — the AAD only,
  // never a wire tag. Optional on insert; the store defaults it to format
  // version 2, which is what every row written before the column existed was
  // sealed under.
  formatVersion?: number | undefined;
  category: string;
  ruleId: string;
  maskedMatch: string;
  provider?: string | undefined;
  // base64
  ciphertext: string;
  nonce: string;
  authTag: string;
  // True when a PERSON asked for this value to be replaced, rather than a pack
  // enforcing its assignment. Optional on insert; absent means an enforcing
  // path, which is what every row written before the column existed was.
  //
  // Passing `false` on a value already marked does NOT clear it — see `upsert`.
  userAuthorized?: boolean | undefined;
}

/** A stored row: the insert fields plus the counters the store maintains. */
export interface VaultRow extends VaultRowInsert {
  // Always present on a read — the column is NOT NULL with a default.
  formatVersion: number;
  userAuthorized: boolean;
  occurrenceCount: number;
  // epoch millis
  firstSeen: number;
  lastSeen: number;
}

/** One de-reference to record, whatever its outcome. */
export interface VaultDerefInsert {
  id: string;
  pointerId: string;
  at: number;
  target: DetokenizeTarget;
  reason: VaultDerefReason;
  outcome: VaultDerefOutcome;
  grantId?: string | undefined;
  // How many pointers ONE batched render resolved; defaults to 1.
  pointerCount?: number | undefined;
}

// SQLite hands back `provider` as null and `user_authorized` as 0/1; the row
// type above keeps the first optional and the second a boolean, so the read
// boundary normalizes both.
interface RawVaultRow extends Omit<VaultRow, 'provider' | 'userAuthorized'> {
  provider: string | null;
  userAuthorized: number;
}

// The reuse list sorts on an occurrence COUNT, not a timestamp, so it cannot
// borrow the shared keyset codec without calling that count `startedAtMs`. A
// second codec is the precedent here (findings.ts carries its own for the same
// reason). Like the shared one, a cursor that does not decode restarts from the
// top rather than throwing: it is opaque state a client hands back, and a bad
// one only reaches us from a hand-edited request or a store that has since been
// reset — in both cases the first page is the useful answer.
interface ReuseCursor {
  occurrences: number;
  pointerId: string;
}

function encodeReuseCursor(payload: ReuseCursor): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function decodeReuseCursor(cursor: string): ReuseCursor | null {
  const parsed = parseJsonObject(Buffer.from(cursor, 'base64url').toString('utf8'));
  if (
    parsed !== undefined &&
    // `Number.isInteger`, not `typeof === 'number'`: a payload carrying
    // ±Infinity or a fraction binds cleanly and returns an EMPTY page with a
    // null cursor, which the caller reads as "end of list" — the one outcome a
    // malformed cursor must never produce, since restarting from the top is the
    // documented behaviour and the only recoverable one. (`1e999` is valid JSON
    // and parses to Infinity; a bare `NaN` is not, so it cannot arrive here.)
    Number.isInteger(parsed.occurrences) &&
    typeof parsed.pointerId === 'string'
  ) {
    return { occurrences: parsed.occurrences as number, pointerId: parsed.pointerId };
  }
  return null;
}

// A value counts as reused when it was detected more than once or its pointer
// was written in more than one place. Kept as SQL so the signal is computed over
// the WHOLE store rather than over whichever page the inventory is showing —
// the view applies the same test to what it receives.
const REUSED_PREDICATE = `(v.occurrence_count > 1
     OR (SELECT count(*) FROM secret_vault_sighting s WHERE s.pointer_id = v.pointer_id) > 1)`;

// The inventory's raw-free projection. Never selects value_fingerprint or the
// sealed columns — the keyed HMAC is correlation material and must not reach a
// view layer, and the ciphertext must not leave the vault at all.
const INVENTORY_COLUMNS = `v.pointer_id, v.category, v.rule_id, v.masked_match, v.provider,
          v.occurrence_count, v.first_seen, v.last_seen`;

interface RawInventoryRow {
  pointer_id: string;
  category: string;
  rule_id: string;
  masked_match: string;
  provider: string | null;
  occurrence_count: number;
  first_seen: number;
  last_seen: number;
  grant_id: string | null;
}

interface RawSightingRow {
  pointer_id: string;
  location: string;
  kind: string;
  first_seen: number;
  last_seen: number;
}

function toSighting(row: RawSightingRow): VaultSighting {
  return {
    location: row.location,
    kind: row.kind as VaultSightingKind,
    firstSeen: new Date(row.first_seen).toISOString(),
    lastSeen: new Date(row.last_seen).toISOString(),
  };
}

const SELECT_COLUMNS = `
  pointer_id AS pointerId,
  value_fingerprint AS valueFingerprint,
  fingerprint_key_version AS fingerprintKeyVersion,
  key_version AS keyVersion,
  format_version AS formatVersion,
  category,
  rule_id AS ruleId,
  masked_match AS maskedMatch,
  provider,
  ciphertext,
  nonce,
  auth_tag AS authTag,
  user_authorized AS userAuthorized,
  occurrence_count AS occurrenceCount,
  first_seen AS firstSeen,
  last_seen AS lastSeen`;

function toRow(raw: RawVaultRow): VaultRow {
  const { provider, userAuthorized, ...rest } = raw;
  const row = { ...rest, userAuthorized: userAuthorized !== 0 };
  return provider === null ? row : { ...row, provider };
}

/**
 * `secret_vault` / `secret_vault_deref` reader and writer, bound to one open DB.
 * Every query reads the whole store — no row carries an owner column to scope by.
 */
export class SqliteSecretVaultRepository {
  private readonly insertStmt: StatementSync;
  private readonly bumpStmt: StatementSync;
  private readonly byPointerStmt: StatementSync;
  private readonly byFingerprintStmt: StatementSync;
  private readonly listStmt: StatementSync;
  private readonly replaceCiphertextStmt: StatementSync;
  private readonly refreshFingerprintStmt: StatementSync;
  private readonly deleteByPointerStmt: StatementSync;
  private readonly derefStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT INTO secret_vault (
         pointer_id, value_fingerprint, fingerprint_key_version, key_version,
         format_version, category, rule_id, masked_match, provider,
         ciphertext, nonce, auth_tag,
         user_authorized, occurrence_count, first_seen, last_seen
       ) VALUES (
         :pointerId, :valueFingerprint, :fingerprintKeyVersion, :keyVersion,
         :formatVersion, :category, :ruleId, :maskedMatch, :provider,
         :ciphertext, :nonce, :authTag,
         :userAuthorized, 1, :now, :now
       )`,
    );
    // Deliberately touches only the counters and the provenance marker:
    // pointer_id, category, key_version and the sealed bytes are fixed at mint.
    //
    // `max` is what makes the marker STICKY, and it is the invariant rather than
    // an optimization: one value is one row, so an automatic vaulting of a value
    // a person already asked to have replaced arrives here as
    // `userAuthorized: 0` against a row holding 1. Assigning the parameter would
    // erase that person's instruction, and the prune sweep — which reads the
    // marker to decide what it may destroy — would then restore the value into
    // the very file they asked to have it taken out of. It only ever goes 0 → 1.
    this.bumpStmt = db.prepare(
      `UPDATE secret_vault
       SET occurrence_count = occurrence_count + 1, last_seen = :now,
           user_authorized = max(user_authorized, :userAuthorized)
       WHERE value_fingerprint = :valueFingerprint`,
    );
    this.byPointerStmt = db.prepare(
      `SELECT ${SELECT_COLUMNS} FROM secret_vault WHERE pointer_id = :pointerId`,
    );
    this.byFingerprintStmt = db.prepare(
      `SELECT ${SELECT_COLUMNS} FROM secret_vault WHERE value_fingerprint = :valueFingerprint`,
    );
    this.listStmt = db.prepare(`SELECT ${SELECT_COLUMNS} FROM secret_vault ORDER BY first_seen`);
    this.replaceCiphertextStmt = db.prepare(
      `UPDATE secret_vault
       SET key_version = :keyVersion, ciphertext = :ciphertext, nonce = :nonce, auth_tag = :authTag
       WHERE pointer_id = :pointerId`,
    );
    this.refreshFingerprintStmt = db.prepare(
      `UPDATE secret_vault
       SET value_fingerprint = :valueFingerprint, fingerprint_key_version = :fingerprintKeyVersion
       WHERE pointer_id = :pointerId`,
    );
    this.deleteByPointerStmt = db.prepare(`DELETE FROM secret_vault WHERE pointer_id = :pointerId`);
    this.derefStmt = db.prepare(
      `INSERT INTO secret_vault_deref (id, pointer_id, at, target, reason, outcome, grant_id, pointer_count)
       VALUES (:id, :pointerId, :at, :target, :reason, :outcome, :grantId, :pointerCount)`,
    );
  }

  /**
   * Vault a value, or record another sighting of one already vaulted. Keyed on
   * `valueFingerprint`, never on the caller's pointer id: a value seen again
   * bumps `occurrence_count` and `last_seen` and comes back with its ORIGINAL
   * pointer, category and ciphertext, so the same secret always resolves to one
   * wire token. `minted` is true only when this call created the row.
   *
   * `userAuthorized` is the one field a repeat call may still change, and only
   * upwards: it records that a PERSON asked for this value to be replaced, and
   * the row is shared with every automatic path that vaults the same value. See
   * `bumpStmt` for why clearing it is the defect this shape exists to refuse.
   *
   * The read-then-write runs in one IMMEDIATE transaction so two concurrent
   * writers cannot both decide they are minting.
   */
  upsert(input: VaultRowInsert, now: number): { row: VaultRow; minted: boolean } {
    let minted = false;
    withTransaction(
      this.db,
      () => {
        const existing = getRow<RawVaultRow>(this.byFingerprintStmt, {
          valueFingerprint: input.valueFingerprint,
        });
        if (existing === undefined) {
          this.insertStmt.run(
            bindParams({
              pointerId: input.pointerId,
              valueFingerprint: input.valueFingerprint,
              fingerprintKeyVersion: input.fingerprintKeyVersion,
              keyVersion: input.keyVersion,
              formatVersion: input.formatVersion ?? POINTER_FORMAT_VERSION,
              category: input.category,
              ruleId: input.ruleId,
              maskedMatch: input.maskedMatch,
              provider: input.provider,
              ciphertext: input.ciphertext,
              nonce: input.nonce,
              authTag: input.authTag,
              userAuthorized: input.userAuthorized === true ? 1 : 0,
              now,
            }),
          );
          minted = true;
          return;
        }
        this.bumpStmt.run({
          valueFingerprint: input.valueFingerprint,
          userAuthorized: input.userAuthorized === true ? 1 : 0,
          now,
        });
      },
      'IMMEDIATE',
    );

    // Re-read rather than reconstruct, so the returned row is exactly what a
    // later reader will see — counters included.
    const row = getRow<RawVaultRow>(this.byFingerprintStmt, {
      valueFingerprint: input.valueFingerprint,
    });
    if (row === undefined) throw new Error('vault: row vanished immediately after write');
    return { row: toRow(row), minted };
  }

  byPointerId(pointerId: string): VaultRow | null {
    const raw = getRow<RawVaultRow>(this.byPointerStmt, { pointerId });
    return raw === undefined ? null : toRow(raw);
  }

  byValueFingerprint(fingerprint: string): VaultRow | null {
    const raw = getRow<RawVaultRow>(this.byFingerprintStmt, { valueFingerprint: fingerprint });
    return raw === undefined ? null : toRow(raw);
  }

  /** Append one audit row. Carries no raw value and no ciphertext, by shape. */
  recordDeref(entry: VaultDerefInsert): void {
    this.derefStmt.run(
      bindParams({
        id: entry.id,
        pointerId: entry.pointerId,
        at: entry.at,
        target: entry.target,
        reason: entry.reason,
        outcome: entry.outcome,
        grantId: entry.grantId,
        pointerCount: entry.pointerCount ?? 1,
      }),
    );
  }

  listAll(): VaultRow[] {
    return allRows<RawVaultRow>(this.listStmt).map(toRow);
  }

  /** Re-seal an entry under a new key epoch, leaving its identity untouched. */
  replaceCiphertext(
    pointerId: string,
    next: { keyVersion: number; ciphertext: string; nonce: string; authTag: string },
  ): void {
    this.replaceCiphertextStmt.run({ pointerId, ...next });
  }

  /** Re-derive an entry's fingerprint under a new fingerprint-key epoch. */
  refreshFingerprint(
    pointerId: string,
    next: { valueFingerprint: string; fingerprintKeyVersion: number },
  ): void {
    this.refreshFingerprintStmt.run({ pointerId, ...next });
  }

  /**
   * Destroy every vaulted value and report how many were destroyed. The deref
   * audit is left alone on purpose — see the table note above.
   */
  purgeAll(): number {
    let destroyed = 0;
    withTransaction(
      this.db,
      () => {
        destroyed = this.countEntries();
        this.db.exec('DELETE FROM secret_vault');
      },
      'IMMEDIATE',
    );
    return destroyed;
  }

  /**
   * Destroy the named entries and report WHICH ones went — the scoped
   * counterpart to `purgeAll`, for a caller that has already put those specific
   * values back where they came from. Ids the store does not hold are absent
   * from the answer rather than an error, so a set assembled from a stale read
   * is not a fault. The deref audit is left alone, exactly as the purge leaves
   * it.
   *
   * The ids come back rather than a count because the caller's next act is to
   * write a purge row per destroyed entry, and a record of destruction has to
   * be a record of what was really destroyed: a selection is a claim about a
   * read that has since gone stale, and auditing from it invents a purge for an
   * entry still sitting in the vault.
   *
   * One transaction over the whole set rather than a statement per id: the
   * caller hands this the result of a restore pass it has completed, and a
   * fault partway through must leave the vault as it was found rather than
   * destroying a prefix of it. The vault holds the only copy of what a pointer
   * stands for, so half a delete is not a state anything can recover from.
   */
  deleteByPointerIds(pointerIds: readonly string[]): string[] {
    if (pointerIds.length === 0) return [];
    const deleted: string[] = [];
    withTransaction(
      this.db,
      () => {
        for (const pointerId of pointerIds) {
          if (Number(this.deleteByPointerStmt.run({ pointerId }).changes) > 0) {
            deleted.push(pointerId);
          }
        }
      },
      'IMMEDIATE',
    );
    return deleted;
  }

  /**
   * Record (or re-stamp) one place a pointer has been written. One row per
   * (pointer, location); a re-sighting bumps last_seen. Best-effort bookkeeping
   * on hook paths — a failure must never affect the rewrite that triggered it,
   * so callers wrap this, not the other way around.
   */
  recordSighting(
    entry: { pointerId: string; location: string; kind: VaultSightingKind },
    now: number,
  ): void {
    this.db
      .prepare(
        `INSERT INTO secret_vault_sighting (id, pointer_id, location, kind, first_seen, last_seen)
         VALUES (:id, :pointerId, :location, :kind, :now, :now)
         ON CONFLICT (pointer_id, location) DO UPDATE SET last_seen = :now`,
      )
      .run({
        id: randomUUID(),
        pointerId: entry.pointerId,
        location: entry.location,
        kind: entry.kind,
        now,
      });
  }

  /**
   * Sightings for a whole page of pointers, in ONE query grouped in JS rather
   * than one query per row. A pointer with no sightings still gets an entry, so
   * the caller never has to distinguish "none" from "missing".
   *
   * The `IN` list is sized to the page, so this statement cannot be cached on
   * the instance the way the fixed-shape ones in the constructor are.
   */
  private sightingsFor(pointerIds: string[]): Map<string, VaultSighting[]> {
    const byPointer = new Map<string, VaultSighting[]>(pointerIds.map((id) => [id, []]));
    // An empty `IN ()` is invalid SQL.
    if (pointerIds.length === 0) return byPointer;

    const rows = allRows<RawSightingRow>(
      this.db.prepare(
        `SELECT pointer_id, location, kind, first_seen, last_seen
           FROM secret_vault_sighting
          WHERE pointer_id IN (${placeholders(pointerIds.length)})
          ORDER BY last_seen DESC`,
      ),
      pointerIds,
    );
    for (const row of rows) byPointer.get(row.pointer_id)?.push(toSighting(row));
    return byPointer;
  }

  /** Hydrate a page of raw inventory rows with their sightings, batched. */
  private toInventoryEntries(rows: RawInventoryRow[]): VaultInventoryEntry[] {
    const sightings = this.sightingsFor(rows.map((r) => r.pointer_id));
    return rows.map((r) => ({
      pointerId: r.pointer_id,
      category: r.category as VaultInventoryEntry['category'],
      ...(r.provider === null ? {} : { provider: r.provider }),
      maskedMatch: r.masked_match,
      occurrences: r.occurrence_count,
      firstSeen: new Date(r.first_seen).toISOString(),
      lastSeen: new Date(r.last_seen).toISOString(),
      revealGrantId: r.grant_id,
      sightings: sightings.get(r.pointer_id) ?? [],
    }));
  }

  /**
   * The dashboard inventory, newest-first, ONE PAGE at a time: every vaulted
   * value's descriptor data joined with its sightings and the active
   * reveal-to-model grant when one exists. Raw-free by construction — neither
   * the fingerprint nor the ciphertext columns are selected.
   *
   * `totals.values` counts the whole store, not the page, so the count a reader
   * sees never depends on how far they have paged.
   */
  listInventory(query: ListVaultInventoryQuery = {}, now = Date.now()): ListVaultInventoryResponse {
    const limit = pageLimit(query.limit, DEFAULT_VAULT_INVENTORY_LIMIT);
    const cursor = query.cursor === undefined ? null : decodeKeysetCursor(query.cursor);

    // Keyset pagination, expanded tuple comparison (node:sqlite has no row-value
    // syntax): strictly-older last_seen, or the same last_seen and a lower
    // pointer id.
    //
    // What this buys over an offset, precisely: an INSERT between two page
    // requests cannot shift the window, so no row is skipped or repeated
    // because of one. It does NOT make the walk a snapshot, because `last_seen`
    // is not immutable — `upsert` bumps it on every repeat detection, and the
    // plugin hooks write while the reader pages.
    //
    // Measured, not reasoned: a bump moves a row toward page 1, i.e. ABOVE the
    // cursor. A row already served stays above it and is never served twice; a
    // row the walk had not yet reached is MISSED until the next read. So the
    // everyday hazard here is a short walk, not a duplicate. `totals.values`
    // counts the store rather than the walk, so it stays right and the shortfall
    // is visible rather than silent. (A duplicate needs a row to move DOWN past
    // the cursor, which takes a clock going backwards between two writers, since
    // `bumpStmt` assigns `last_seen = :now` rather than `max(last_seen, :now)`.)
    // Both are inherent to ordering on a mutable column and are the accepted
    // trade for showing most-recently-seen first.
    const where =
      cursor === null
        ? ''
        : 'WHERE (v.last_seen < :cursorLastSeen OR (v.last_seen = :cursorLastSeen AND v.pointer_id < :cursorPointerId))';

    // One extra row detects a next page without a second COUNT.
    const rows = allRows<RawInventoryRow>(
      this.db.prepare(
        `SELECT ${INVENTORY_COLUMNS},
                (SELECT e.id FROM exceptions e
                  WHERE e.rule_id = v.rule_id
                    AND e.value_fingerprint = v.value_fingerprint
                    AND e.key_version = v.fingerprint_key_version
                    AND ${ACTIVE_REVEAL_GRANT_PREDICATE}
                  LIMIT 1) AS grant_id
           FROM secret_vault v
           ${where}
          ORDER BY v.last_seen DESC, v.pointer_id DESC
          LIMIT :limit`,
      ),
      bindParams({
        now,
        limit: limit + 1,
        ...(cursor === null
          ? {}
          : { cursorLastSeen: cursor.startedAtMs, cursorPointerId: cursor.id }),
      }),
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    const last = page[page.length - 1];

    return {
      totals: { values: this.countEntries() },
      items: this.toInventoryEntries(page),
      // Minted from the last row of the PAGE, never the extra probe row.
      nextCursor:
        hasMore && last
          ? encodeKeysetCursor({ startedAtMs: last.last_seen, id: last.pointer_id })
          : null,
    };
  }

  /**
   * Values reused on this machine — detected more than once, or written to more
   * than one location — most-reused first, one page at a time.
   *
   * Its own read rather than a filter over an inventory page: reuse is a
   * property of the whole store, and deriving it from 50 newest rows would
   * under-report exactly the values a reader most needs to see.
   */
  listReuse(query: ListVaultReuseQuery = {}, now = Date.now()): ListVaultReuseResponse {
    const limit = pageLimit(query.limit, DEFAULT_VAULT_INVENTORY_LIMIT);
    const cursor = query.cursor === undefined ? null : decodeReuseCursor(query.cursor);

    // Same expanded tuple comparison as above, over (occurrence_count DESC,
    // pointer_id DESC) — this list ranks by how often a value recurs, not by
    // when it was last seen. It carries the same mutable-sort-key caveat, from
    // the same writer: `upsert` increments `occurrence_count`, so a repeat
    // detection moves a row toward page 1 and a row the walk had not yet
    // reached is missed. One case is its own: a value crossing from not-reused
    // to reused mid-walk ENTERS the set, at a rank that may already be behind
    // the cursor — counted by `totals.reused`, not returned until a fresh read.
    const after =
      cursor === null
        ? ''
        : `AND (v.occurrence_count < :cursorOccurrences
              OR (v.occurrence_count = :cursorOccurrences AND v.pointer_id < :cursorPointerId))`;

    const rows = allRows<RawInventoryRow>(
      this.db.prepare(
        `SELECT ${INVENTORY_COLUMNS},
                (SELECT e.id FROM exceptions e
                  WHERE e.rule_id = v.rule_id
                    AND e.value_fingerprint = v.value_fingerprint
                    AND e.key_version = v.fingerprint_key_version
                    AND ${ACTIVE_REVEAL_GRANT_PREDICATE}
                  LIMIT 1) AS grant_id
           FROM secret_vault v
          WHERE ${REUSED_PREDICATE} ${after}
          ORDER BY v.occurrence_count DESC, v.pointer_id DESC
          LIMIT :limit`,
      ),
      bindParams({
        now,
        limit: limit + 1,
        ...(cursor === null
          ? {}
          : { cursorOccurrences: cursor.occurrences, cursorPointerId: cursor.pointerId }),
      }),
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    const last = page[page.length - 1];

    return {
      totals: { reused: this.countReused() },
      items: this.toInventoryEntries(page),
      nextCursor:
        hasMore && last
          ? encodeReuseCursor({ occurrences: last.occurrence_count, pointerId: last.pointer_id })
          : null,
    };
  }

  /**
   * The de-reference trail, newest first, one page at a time. By default the
   * batched, high-volume reasons (display, view-render) are hidden and counted
   * instead — the rows that matter as a signal are the model crossings, and
   * burying them under render noise would defeat the audit's purpose.
   *
   * `hiddenBatched` counts the whole trail rather than the page: it is what the
   * view's "N hidden" line and its toggle speak for, so it must not shrink as
   * the reader pages.
   */
  listDerefs(query: ListVaultDerefsQuery = {}): ListVaultDerefsResponse {
    const limit = pageLimit(query.limit, DEFAULT_VAULT_DEREFS_LIMIT);
    const cursor = query.cursor === undefined ? null : decodeKeysetCursor(query.cursor);

    const conditions: string[] = [];
    if (query.includeBatched !== true) {
      conditions.push(`reason NOT IN ('display', 'view-render')`);
    }
    if (cursor !== null) {
      conditions.push('(at < :cursorAt OR (at = :cursorAt AND id < :cursorId))');
    }
    const where = conditions.length === 0 ? '' : `WHERE ${conditions.join(' AND ')}`;

    // Ordered by (at, id) rather than (at, rowid): rowid is not stable for a
    // table whose primary key is not INTEGER, and a cursor naming one would
    // silently resume in the wrong place after a VACUUM.
    const rows = allRows<{
      id: string;
      pointer_id: string;
      at: number;
      target: string;
      reason: string;
      outcome: string;
      grant_id: string | null;
      pointer_count: number;
    }>(
      this.db.prepare(
        `SELECT id, pointer_id, at, target, reason, outcome, grant_id, pointer_count
           FROM secret_vault_deref ${where}
          ORDER BY at DESC, id DESC LIMIT :limit`,
      ),
      bindParams({
        limit: limit + 1,
        ...(cursor === null ? {} : { cursorAt: cursor.startedAtMs, cursorId: cursor.id }),
      }),
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    const last = page[page.length - 1];

    const hiddenBatched =
      query.includeBatched === true
        ? 0
        : countScalar(
            this.db,
            `SELECT count(*) AS n FROM secret_vault_deref WHERE reason IN ('display', 'view-render')`,
          );

    return {
      items: page.map((r) => ({
        id: r.id,
        pointerId: r.pointer_id,
        at: new Date(r.at).toISOString(),
        target: r.target as VaultDeref['target'],
        reason: r.reason as VaultDeref['reason'],
        outcome: r.outcome as VaultDeref['outcome'],
        ...(r.grant_id === null ? {} : { grantId: r.grant_id }),
        pointerCount: r.pointer_count,
      })),
      nextCursor:
        hasMore && last ? encodeKeysetCursor({ startedAtMs: last.at, id: last.id }) : null,
      hiddenBatched,
    };
  }

  countEntries(): number {
    return countScalar(this.db, 'SELECT COUNT(*) AS n FROM secret_vault');
  }

  /** Values reused on this machine — the reuse list's page-independent total. */
  countReused(): number {
    return countScalar(
      this.db,
      `SELECT COUNT(*) AS n FROM secret_vault v WHERE ${REUSED_PREDICATE}`,
    );
  }
}
