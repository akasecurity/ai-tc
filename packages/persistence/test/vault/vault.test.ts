import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { PointerToken } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { loadOrCreateFingerprintKey, rotateFingerprintKey } from '../../src/fingerprint.ts';
import { DB_FILENAME } from '../../src/paths.ts';
import { SqliteSecretVaultRepository } from '../../src/repositories/secret-vault.ts';
import { FileKeyProvider } from '../../src/vault/key-provider.ts';
import { CONSENT_ABSENT, SecretVault, UNAVAILABLE } from '../../src/vault/vault.ts';

// Narrowing helper: the lint config forbids non-null assertions, and these
// lookups are all "the row we just wrote must be there" assertions anyway.
function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`expected ${what}`);
  return value;
}

const SECRET = 'AKIAIOSFODNN7EXAMPLE';
const OTHER = 'AKIAI44QH8DHBEXAMPLE';

describe('SecretVault', () => {
  let dir: string;
  let migrated: ReturnType<typeof openLocalDatabase>;
  let db: DatabaseSync;
  let repo: SqliteSecretVaultRepository;
  let vault: SecretVault;
  let consented: boolean;

  const build = (): SecretVault =>
    new SecretVault({
      repo,
      keys: new FileKeyProvider(join(dir, 'keys')),
      fingerprintKey: loadOrCreateFingerprintKey(dir),
      isConsented: () => consented,
    });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-'));
    // Applies the migrations; the repository under test runs on a second
    // connection to the same file. BOTH handles must be closed before the temp
    // dir is removed — Windows refuses to delete a directory that still has an
    // open handle inside it (EPERM), where POSIX unlinks it happily.
    migrated = openLocalDatabase(dir);
    db = new DatabaseSync(join(dir, DB_FILENAME));
    repo = new SqliteSecretVaultRepository(db);
    consented = true;
    vault = build();
  });

  afterEach(() => {
    db.close();
    migrated.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const tokenize = async (raw: string, category = 'secret'): Promise<string> => {
    const result = await vault.tokenize(raw, {
      ruleId: 'aws-access-key-id',
      category: category as 'secret',
      maskedMatch: 'A******E',
    });
    if (typeof result !== 'string') throw new Error('expected a pointer');
    return result;
  };

  describe('round trip', () => {
    it('gives back the exact original bytes', async () => {
      for (const raw of [SECRET, 'ünïcøde ✓ 秘密', 'x'.repeat(4096), ' leading and trailing ']) {
        const token = await tokenize(raw);
        await expect(
          vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
        ).resolves.toBe(raw);
      }
    });

    it('emits a token the published grammar accepts', async () => {
      expect(PointerToken.safeParse(await tokenize(SECRET)).success).toBe(true);
    });

    it('never puts the raw value in the stored row', async () => {
      await tokenize(SECRET);
      const row = must(
        repo.byPointerId(must(repo.listAll()[0], 'a vault row').pointerId),
        'the row',
      );
      expect(JSON.stringify(row)).not.toContain(SECRET);
      expect(row.maskedMatch).not.toBe(SECRET);
    });
  });

  describe('determinism', () => {
    it('returns the same pointer for the same value and counts the reuse', async () => {
      expect(await tokenize(SECRET)).toBe(await tokenize(SECRET));
      expect(repo.countEntries()).toBe(1);
      expect(must(repo.listAll()[0], 'a vault row').occurrenceCount).toBe(2);
    });

    it('returns distinct pointers for distinct values', async () => {
      const a = await tokenize(SECRET);
      const b = await tokenize(OTHER);
      expect(a).not.toBe(b);
      await expect(
        vault.detokenize(a, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(SECRET);
      await expect(
        vault.detokenize(b, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(OTHER);
    });

    // One value must yield one row and one token even when a second rule
    // classifies it differently — otherwise the same secret would circulate
    // under two pointers.
    it('keeps the category it was minted with', async () => {
      const first = await tokenize(SECRET, 'secret');
      const second = await tokenize(SECRET, 'pii');
      expect(second).toBe(first);
      expect(first.startsWith('[[aka:secret:')).toBe(true);
      expect(repo.countEntries()).toBe(1);
      expect(must(repo.listAll()[0], 'a vault row').category).toBe('secret');
    });
  });

  describe('consent gate', () => {
    it('does not vault anything without consent', async () => {
      consented = false;
      await expect(
        vault.tokenize(SECRET, { ruleId: 'r', category: 'secret', maskedMatch: 'A***E' }),
      ).resolves.toBe(CONSENT_ABSENT);
      expect(repo.countEntries()).toBe(0);
    });

    // Revocation stops new vaulting; it does not strand values already stored.
    it('still resolves existing pointers after consent is revoked', async () => {
      const token = await tokenize(SECRET);
      consented = false;
      await expect(
        vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(SECRET);
    });
  });

  describe('unforgeable pointers', () => {
    it('refuses a fabricated pointer without auditing it', async () => {
      const forged = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
      await expect(
        vault.detokenize(forged, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(UNAVAILABLE);
      expect(derefRows()).toHaveLength(0);
    });

    it('refuses a token whose tag has been altered', async () => {
      const token = await tokenize(SECRET);
      const tampered = token.replace(
        /([A-Z2-7]{16})\]\]$/,
        (tag) => `${tag.startsWith('A') ? 'B' : 'A'}${tag.slice(1)}`,
      );
      await expect(
        vault.detokenize(tampered, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(UNAVAILABLE);
    });

    // The tag covers the category, so re-badging a pointer breaks it.
    it('refuses a pointer relabelled into another category', async () => {
      const token = await tokenize(SECRET);
      const relabelled = token.replace('[[aka:secret:', '[[aka:pii:');
      await expect(
        vault.detokenize(relabelled, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(UNAVAILABLE);
    });

    it('refuses a structurally invalid string outright', async () => {
      for (const junk of [
        '',
        'not a pointer',
        '[[aka:bogus:AE.AAAA.BBBB]]',
        '[[aka:tok:AE.A.B]]',
      ]) {
        await expect(
          vault.detokenize(junk, { target: 'human', reason: 'explicit-reveal' }),
        ).resolves.toBe(UNAVAILABLE);
      }
    });
  });

  describe('model de-reference', () => {
    it('refuses without a grant, and records the refusal', async () => {
      const token = await tokenize(SECRET);
      await expect(
        vault.detokenize(token, { target: 'model', reason: 'model-input' }),
      ).resolves.toBe(UNAVAILABLE);
      const rows = derefRows();
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ target: 'model', outcome: 'refused', reason: 'model-input' });
    });

    it('reveals with a grant, and records the crossing', async () => {
      const token = await tokenize(SECRET);
      await expect(
        vault.detokenize(token, { target: 'model', reason: 'model-input', grantId: 'g-1' }),
      ).resolves.toBe(SECRET);
      expect(derefRows()[0]).toMatchObject({
        target: 'model',
        outcome: 'revealed',
        grantId: 'g-1',
      });
    });
  });

  describe('audit trail', () => {
    it('never records the raw value', async () => {
      const token = await tokenize(SECRET);
      await vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' });
      expect(JSON.stringify(derefRows())).not.toContain(SECRET);
    });

    it('batches the human-volume reasons and never a model crossing', async () => {
      const token = await tokenize(SECRET);
      await vault.detokenize(token, { target: 'human', reason: 'view-render', pointerCount: 12 });
      await vault.detokenize(token, {
        target: 'model',
        reason: 'model-input',
        grantId: 'g-1',
        pointerCount: 12,
      });
      const [batched, crossing] = derefRows();
      expect(batched).toMatchObject({ reason: 'view-render', pointerCount: 12 });
      expect(crossing).toMatchObject({ reason: 'model-input', pointerCount: 1 });
    });
  });

  describe('describePointer', () => {
    it('describes a real pointer without revealing it', async () => {
      const token = await tokenize(SECRET);
      const descriptor = await vault.describePointer(token);
      expect(descriptor).toMatchObject({
        category: 'secret',
        maskedMatch: 'A******E',
        occurrences: 1,
      });
      expect(JSON.stringify(descriptor)).not.toContain(SECRET);
      expect(descriptor).not.toHaveProperty('valueFingerprint');
    });

    it('writes no audit row — nothing crossed', async () => {
      await vault.describePointer(await tokenize(SECRET));
      expect(derefRows()).toHaveLength(0);
    });

    // A fabricated pointer must not yield even a category and a masked preview.
    it('returns null for a pointer whose tag does not verify', async () => {
      const forged = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
      await expect(vault.describePointer(forged)).resolves.toBeNull();
    });
  });

  describe('vault key rotation', () => {
    // The property that makes rotation safe: a pointer already sitting in a
    // transcript or a committed file names the epoch it was minted under, and
    // that epoch is retained, so it keeps verifying.
    it('keeps outstanding pointers resolvable', async () => {
      const token = await tokenize(SECRET);
      const { version, reEncrypted } = await vault.rotateVaultKey();
      expect(version).toBe(2);
      expect(reEncrypted).toBe(1);
      await expect(
        vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(SECRET);
      expect(must(repo.listAll()[0], 'a vault row').keyVersion).toBe(2);
    });

    it('re-encrypts under the new epoch rather than leaving the old ciphertext', async () => {
      await tokenize(SECRET);
      const before = must(repo.listAll()[0], 'a vault row').ciphertext;
      await vault.rotateVaultKey();
      expect(must(repo.listAll()[0], 'a vault row').ciphertext).not.toBe(before);
    });

    it('still resolves a value tokenized after the rotation', async () => {
      await vault.rotateVaultKey();
      const token = await tokenize(SECRET);
      await expect(
        vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(SECRET);
    });
  });

  describe('fingerprint key refresh', () => {
    // Grants are invalidated by an exception-key rotation because their values
    // are gone. The vault still holds the values, so it re-keys instead —
    // preserving every pointer and the dedup that depends on them.
    it('re-keys fingerprints while preserving pointers and dedup', async () => {
      const token = await tokenize(SECRET);
      const before = must(repo.listAll()[0], 'a vault row');

      const next = rotateFingerprintKey(dir);
      expect(await vault.refreshFingerprints(next)).toBe(1);

      const after = must(repo.listAll()[0], 'a vault row');
      expect(after.pointerId).toBe(before.pointerId);
      expect(after.valueFingerprint).not.toBe(before.valueFingerprint);
      expect(after.fingerprintKeyVersion).toBe(next.version);

      await expect(
        vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(SECRET);

      // Re-tokenizing under the new key must find the refreshed row, not mint a
      // second one — otherwise the reuse count fragments.
      vault = new SecretVault({
        repo,
        keys: new FileKeyProvider(join(dir, 'keys')),
        fingerprintKey: next,
        isConsented: () => consented,
      });
      expect(await tokenize(SECRET)).toBe(token);
      expect(repo.countEntries()).toBe(1);
    });
  });

  describe('purge', () => {
    it('makes every pointer permanently unresolvable', async () => {
      const token = await tokenize(SECRET);
      expect(vault.purgeVault()).toBe(1);
      expect(repo.countEntries()).toBe(0);
      await expect(
        vault.detokenize(token, { target: 'human', reason: 'explicit-reveal' }),
      ).resolves.toBe(UNAVAILABLE);
    });

    // The record that values were destroyed has to outlive them.
    it('leaves an audit trail that survives the destruction', async () => {
      await tokenize(SECRET);
      vault.purgeVault();
      expect(derefRows().some((r) => r.reason === 'purge')).toBe(true);
    });

    it('records how many entries were actually destroyed', async () => {
      await tokenize(SECRET);
      await tokenize(OTHER);
      vault.purgeVault();
      const row = must(
        derefRows().find((r) => r.reason === 'purge'),
        'a purge audit row',
      );
      expect(row.pointerCount).toBe(2);
    });

    // The count has to come from inside the deleting transaction. A count taken
    // separately can be overtaken by a concurrent write before the delete runs,
    // and the audit row is the durable record that outlives the values — a number
    // that never matched reality is worse there than anywhere else.
    //
    // A repository whose out-of-transaction countEntries LIES stands in for that
    // race: purgeAll still counts truthfully inside its own transaction (it is
    // delegated to the real repository, so its internal count is the real one),
    // so anything reading the standalone count reports the lie instead.
    it('takes the count from the deleting transaction, not a separate count', async () => {
      await tokenize(SECRET);
      await tokenize(OTHER);

      const lying = new Proxy(repo, {
        get(target, prop) {
          if (prop === 'countEntries') return () => 99;
          const value: unknown = Reflect.get(target, prop, target);
          return typeof value === 'function'
            ? (value as (...args: unknown[]) => unknown).bind(target)
            : value;
        },
      });
      const vaultOverLyingRepo = new SecretVault({
        repo: lying,
        keys: new FileKeyProvider(join(dir, 'keys')),
        fingerprintKey: loadOrCreateFingerprintKey(dir),
        isConsented: () => consented,
      });

      expect(vaultOverLyingRepo.purgeVault()).toBe(2);
      const row = must(
        derefRows().find((r) => r.reason === 'purge'),
        'a purge audit row',
      );
      expect(row.pointerCount).toBe(2);
    });
  });

  function derefRows(): {
    pointerId: string;
    target: string;
    reason: string;
    outcome: string;
    grantId: string | null;
    pointerCount: number;
  }[] {
    return db
      .prepare(
        `SELECT pointer_id AS pointerId, target, reason, outcome,
                grant_id AS grantId, pointer_count AS pointerCount
         FROM secret_vault_deref ORDER BY rowid`,
      )
      .all() as never;
  }
});
