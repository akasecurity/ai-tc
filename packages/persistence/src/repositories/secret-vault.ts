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
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { DetokenizeTarget, VaultDerefOutcome, VaultDerefReason } from '@akasecurity/schema';

import { allRows, bindParams, countScalar, getRow } from '../internal/rows.ts';
import { withTransaction } from '../internal/transactions.ts';

/** What a caller supplies when it asks for a value to be vaulted. */
export interface VaultRowInsert {
  pointerId: string;
  valueFingerprint: string;
  fingerprintKeyVersion: number;
  keyVersion: number;
  category: string;
  ruleId: string;
  maskedMatch: string;
  provider?: string | undefined;
  // base64
  ciphertext: string;
  nonce: string;
  authTag: string;
}

/** A stored row: the insert fields plus the counters the store maintains. */
export interface VaultRow extends VaultRowInsert {
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

// SQLite hands back `provider` as null; the row type above keeps it optional,
// so the read boundary normalizes it.
interface RawVaultRow extends Omit<VaultRow, 'provider'> {
  provider: string | null;
}

const SELECT_COLUMNS = `
  pointer_id AS pointerId,
  value_fingerprint AS valueFingerprint,
  fingerprint_key_version AS fingerprintKeyVersion,
  key_version AS keyVersion,
  category,
  rule_id AS ruleId,
  masked_match AS maskedMatch,
  provider,
  ciphertext,
  nonce,
  auth_tag AS authTag,
  occurrence_count AS occurrenceCount,
  first_seen AS firstSeen,
  last_seen AS lastSeen`;

function toRow(raw: RawVaultRow): VaultRow {
  const { provider, ...rest } = raw;
  return provider === null ? rest : { ...rest, provider };
}

/**
 * `secret_vault` / `secret_vault_deref` reader and writer, bound to one open DB.
 * The local store is single-tenant, so no query carries a tenant predicate.
 */
export class SqliteSecretVaultRepository {
  private readonly insertStmt: StatementSync;
  private readonly bumpStmt: StatementSync;
  private readonly byPointerStmt: StatementSync;
  private readonly byFingerprintStmt: StatementSync;
  private readonly listStmt: StatementSync;
  private readonly replaceCiphertextStmt: StatementSync;
  private readonly refreshFingerprintStmt: StatementSync;
  private readonly derefStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT INTO secret_vault (
         pointer_id, value_fingerprint, fingerprint_key_version, key_version,
         category, rule_id, masked_match, provider,
         ciphertext, nonce, auth_tag,
         occurrence_count, first_seen, last_seen
       ) VALUES (
         :pointerId, :valueFingerprint, :fingerprintKeyVersion, :keyVersion,
         :category, :ruleId, :maskedMatch, :provider,
         :ciphertext, :nonce, :authTag,
         1, :now, :now
       )`,
    );
    // Deliberately touches only the counters: pointer_id, category, key_version
    // and the sealed bytes are fixed at mint.
    this.bumpStmt = db.prepare(
      `UPDATE secret_vault
       SET occurrence_count = occurrence_count + 1, last_seen = :now
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
              category: input.category,
              ruleId: input.ruleId,
              maskedMatch: input.maskedMatch,
              provider: input.provider,
              ciphertext: input.ciphertext,
              nonce: input.nonce,
              authTag: input.authTag,
              now,
            }),
          );
          minted = true;
          return;
        }
        this.bumpStmt.run({ valueFingerprint: input.valueFingerprint, now });
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

  countEntries(): number {
    return countScalar(this.db, 'SELECT COUNT(*) AS n FROM secret_vault');
  }
}
