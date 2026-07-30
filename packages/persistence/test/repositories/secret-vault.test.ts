import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import { beforeEach, describe, expect, it } from 'vitest';

import type { VaultRowInsert } from '../../src/repositories/secret-vault.ts';
import { SqliteSecretVaultRepository } from '../../src/repositories/secret-vault.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const NOW = Date.parse('2026-06-29T12:00:00.000Z');

// The package's shared store harness owns the temp tree and closes every handle
// it hands out at teardown.
const store = useTempStore('aka-vault-');
let raw: DatabaseSync;
let vault: SqliteSecretVaultRepository;

beforeEach(() => {
  // Applies the migrations; the repository under test runs on a second
  // connection to the same migrated file.
  store.open();
  raw = store.openRaw();
  vault = new SqliteSecretVaultRepository(raw);
});

const FINGERPRINT_A = 'a'.repeat(64);
const FINGERPRINT_B = 'b'.repeat(64);

function entry(overrides: Partial<VaultRowInsert> = {}): VaultRowInsert {
  return {
    pointerId: 'pointer-a',
    valueFingerprint: FINGERPRINT_A,
    fingerprintKeyVersion: 1,
    keyVersion: 1,
    category: 'secret',
    ruleId: 'aka.secret.aws-key',
    maskedMatch: 'AKIA…XYZQ',
    provider: 'aws',
    ciphertext: 'Y2lwaGVy',
    nonce: 'bm9uY2U=',
    authTag: 'dGFn',
    ...overrides,
  };
}

describe('SqliteSecretVaultRepository.upsert', () => {
  it('bumps the existing row instead of minting a second one', () => {
    const first = vault.upsert(entry(), NOW);
    const second = vault.upsert(entry(), NOW + 1_000);

    expect(first.minted).toBe(true);
    expect(second.minted).toBe(false);
    expect(vault.countEntries()).toBe(1);
    expect(second.row.pointerId).toBe(first.row.pointerId);
    expect(second.row.occurrenceCount).toBe(2);
    expect(second.row.firstSeen).toBe(NOW);
    expect(second.row.lastSeen).toBe(NOW + 1_000);
  });

  it('keeps the minted category, pointer and ciphertext on a repeat sighting', () => {
    const first = vault.upsert(entry(), NOW);
    const second = vault.upsert(
      entry({
        pointerId: 'pointer-second-attempt',
        category: 'pii',
        ruleId: 'aka.pii.email',
        ciphertext: 'ZGlmZmVyZW50',
        nonce: 'ZGlmZmVyZW50Tg==',
        authTag: 'ZGlmZmVyZW50VA==',
        keyVersion: 7,
      }),
      NOW + 1_000,
    );

    expect(second.row.pointerId).toBe(first.row.pointerId);
    expect(second.row.category).toBe('secret');
    expect(second.row.ciphertext).toBe(first.row.ciphertext);
    expect(second.row.nonce).toBe(first.row.nonce);
    expect(second.row.authTag).toBe(first.row.authTag);
    expect(second.row.keyVersion).toBe(1);
    // The discarded pointer never becomes addressable.
    expect(vault.byPointerId('pointer-second-attempt')).toBeNull();
  });

  it('mints a separate row per distinct fingerprint', () => {
    const a = vault.upsert(entry(), NOW);
    const b = vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);

    expect(b.minted).toBe(true);
    expect(vault.countEntries()).toBe(2);
    expect(b.row.pointerId).not.toBe(a.row.pointerId);
    expect(vault.listAll().map((r) => r.pointerId)).toEqual(['pointer-a', 'pointer-b']);
  });
});

describe('SqliteSecretVaultRepository lookups', () => {
  it('round-trips a full row by pointer id and by fingerprint', () => {
    const { row } = vault.upsert(entry(), NOW);

    expect(vault.byPointerId('pointer-a')).toEqual(row);
    expect(vault.byValueFingerprint(FINGERPRINT_A)).toEqual(row);
    expect(row).toMatchObject({
      pointerId: 'pointer-a',
      valueFingerprint: FINGERPRINT_A,
      fingerprintKeyVersion: 1,
      keyVersion: 1,
      category: 'secret',
      ruleId: 'aka.secret.aws-key',
      maskedMatch: 'AKIA…XYZQ',
      provider: 'aws',
      ciphertext: 'Y2lwaGVy',
      nonce: 'bm9uY2U=',
      authTag: 'dGFn',
      occurrenceCount: 1,
      firstSeen: NOW,
      lastSeen: NOW,
    });
  });

  it('returns null on a miss', () => {
    expect(vault.byPointerId('nope')).toBeNull();
    expect(vault.byValueFingerprint(FINGERPRINT_B)).toBeNull();
  });
});

describe('SqliteSecretVaultRepository.recordDeref', () => {
  it('writes an audit row carrying neither the raw value nor the ciphertext', () => {
    vault.upsert(entry(), NOW);
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'model',
      reason: 'model-input',
      outcome: 'revealed',
      grantId: 'grant-1',
    });

    const rows = raw.prepare('SELECT * FROM secret_vault_deref').all();
    expect(rows).toHaveLength(1);
    const stored = rows[0] as Record<string, unknown>;
    expect(stored).toMatchObject({
      pointer_id: 'pointer-a',
      at: NOW,
      target: 'model',
      reason: 'model-input',
      outcome: 'revealed',
      grant_id: 'grant-1',
      // Unbatched crossings count one pointer.
      pointer_count: 1,
    });
    const columns = Object.keys(stored);
    expect(columns).not.toContain('ciphertext');
    expect(columns).not.toContain('value_fingerprint');
    expect(JSON.stringify(stored)).not.toContain('Y2lwaGVy');
  });

  it('stores a supplied batched pointer count as given', () => {
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'human',
      reason: 'display',
      outcome: 'revealed',
      pointerCount: 4,
    });

    const stored = raw
      .prepare('SELECT pointer_count AS n, grant_id AS g FROM secret_vault_deref')
      .get();
    expect(stored).toMatchObject({ n: 4, g: null });
  });
});

describe('SqliteSecretVaultRepository re-key writes', () => {
  it('replaceCiphertext changes only the sealed fields', () => {
    const { row } = vault.upsert(entry(), NOW);
    vault.replaceCiphertext('pointer-a', {
      keyVersion: 2,
      ciphertext: 'cmVzZWFsZWQ=',
      nonce: 'bmV3bm9uY2U=',
      authTag: 'bmV3dGFn',
    });

    expect(vault.byPointerId('pointer-a')).toEqual({
      ...row,
      keyVersion: 2,
      ciphertext: 'cmVzZWFsZWQ=',
      nonce: 'bmV3bm9uY2U=',
      authTag: 'bmV3dGFn',
    });
  });

  it('refreshFingerprint changes only the fingerprint fields', () => {
    const { row } = vault.upsert(entry(), NOW);
    vault.refreshFingerprint('pointer-a', {
      valueFingerprint: FINGERPRINT_B,
      fingerprintKeyVersion: 3,
    });

    expect(vault.byPointerId('pointer-a')).toEqual({
      ...row,
      valueFingerprint: FINGERPRINT_B,
      fingerprintKeyVersion: 3,
    });
  });
});

describe('SqliteSecretVaultRepository.purgeAll', () => {
  it('destroys every value and leaves the deref audit standing', () => {
    vault.upsert(entry(), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'human',
      reason: 'explicit-reveal',
      outcome: 'revealed',
    });

    expect(vault.purgeAll()).toBe(2);
    expect(vault.countEntries()).toBe(0);
    expect(vault.listAll()).toEqual([]);
    expect(vault.byPointerId('pointer-a')).toBeNull();
    // The record that a de-reference happened outlives the values.
    expect(raw.prepare('SELECT COUNT(*) AS n FROM secret_vault_deref').get()).toMatchObject({
      n: 1,
    });
    expect(vault.purgeAll()).toBe(0);
  });
});
