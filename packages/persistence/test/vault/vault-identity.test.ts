import { join } from 'node:path';

import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UserGrantPolicyProvider } from '../../src/exception-policy.ts';
import type { FingerprintKey } from '../../src/fingerprint.ts';
import {
  exactFingerprintValue,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  rotateFingerprintKey,
} from '../../src/fingerprint.ts';
import type { CreateExceptionInput } from '../../src/repositories/exceptions.ts';
import { FileKeyProvider } from '../../src/vault/key-provider.ts';
import { SecretVault } from '../../src/vault/vault.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// A vault row has TWO fingerprints: the exact-bytes one it dedupes on, and the
// identity one (invisible padding removed) that exceptions and grants match on.
// These cases sit where the two spaces meet, so a padded secret and its clean
// twin stay two restorable rows yet share one grant.

const RULE_ID = 'aws-access-key-id';
const CLEAN = 'AKIAIOSFODNN7EXAMPLE';
const PADDED = `${CLEAN.slice(0, 4)}\u200B${CLEAN.slice(4)}`;
const WITH_ZWJ = `${CLEAN.slice(0, 4)}\u200D${CLEAN.slice(4)}`;

function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`expected ${what}`);
  return value;
}

describe('vault identity fingerprint', () => {
  const store = useTempStore('aka-vault-identity-', { migrated: true });
  let db: LocalDatabase;
  let vault: SecretVault;
  let key: FingerprintKey;

  beforeEach(() => {
    db = store.open();
    key = loadOrCreateFingerprintKey(store.dataDir);
    vault = new SecretVault({
      repo: db.secretVault,
      keys: new FileKeyProvider(join(store.dataDir, 'keys')),
      isConsented: () => true,
    });
  });

  const tokenize = async (raw: string): Promise<string> => {
    const result = await vault.tokenize(
      raw,
      { ruleId: RULE_ID, category: 'secret', maskedMatch: 'A******E' },
      () => key,
    );
    if (typeof result !== 'string') throw new Error('expected a pointer');
    return result;
  };

  const grant = (valueFingerprint: string): Promise<unknown> =>
    db.exceptions.create({
      ruleId: RULE_ID,
      category: 'secret',
      valueFingerprint,
      keyVersion: key.version,
      maskedValue: 'A******E',
      capability: 'reveal_to_model',
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
      justification: 'test grant',
      conditions: null,
      createdBy: 'tester',
      createdVia: 'cli-approve',
    } satisfies CreateExceptionInput);

  const reveal = async (token: string): Promise<boolean> => {
    const identity = must(await vault.resolvePointerIdentity(token), 'an identity');
    const decision = await new UserGrantPolicyProvider(db.exceptions).decideReveal(identity);
    return decision.allow;
  };

  it('hands out the identity fingerprint, which a padded value shares with its clean twin', async () => {
    const padded = await tokenize(PADDED);
    const clean = await tokenize(CLEAN);
    expect(padded).not.toBe(clean);
    const paddedIdentity = must(await vault.resolvePointerIdentity(padded), 'padded identity');
    const cleanIdentity = must(await vault.resolvePointerIdentity(clean), 'clean identity');
    expect(paddedIdentity.valueFingerprint).toBe(fingerprintValue(key, CLEAN));
    expect(cleanIdentity.valueFingerprint).toBe(fingerprintValue(key, CLEAN));
    // The dedupe key stays exact, so the twins are two rows.
    expect(
      must(db.secretVault.byValueFingerprint(exactFingerprintValue(key, PADDED)), 'row'),
    ).toMatchObject({ valueIdentityFingerprint: fingerprintValue(key, CLEAN) });
    expect(db.secretVault.countEntries()).toBe(2);
  });

  it('a grant made from the ledger (identity space) reveals the padded vault row', async () => {
    const padded = await tokenize(PADDED);
    await grant(fingerprintValue(key, CLEAN));
    await expect(reveal(padded)).resolves.toBe(true);
  });

  it('a grant minted from the padded pointer is the identity every other surface computes', async () => {
    const padded = await tokenize(PADDED);
    const identity = must(await vault.resolvePointerIdentity(padded), 'identity');
    // What the CLI and dashboard copy into the exception, and what runtime
    // suppression looks up for the same padded text.
    expect(identity.valueFingerprint).toBe(fingerprintValue(key, PADDED));
    await grant(identity.valueFingerprint);
    await expect(reveal(padded)).resolves.toBe(true);
    await expect(reveal(await tokenize(CLEAN))).resolves.toBe(true);
  });

  it('shows the grant badge on a padded row for an exception in the identity space', async () => {
    await tokenize(PADDED);
    await tokenize(CLEAN);
    await grant(fingerprintValue(key, CLEAN));
    const items = db.secretVault.listInventory({}).items;
    expect(items).toHaveLength(2);
    for (const item of items) expect(item.revealGrantId).not.toBeNull();
  });

  it('restores each twin to its own exact text', async () => {
    const padded = await tokenize(PADDED);
    const clean = await tokenize(CLEAN);
    await expect(
      vault.detokenize(padded, { target: 'human', reason: 'explicit-reveal' }),
    ).resolves.toBe(PADDED);
    await expect(
      vault.detokenize(clean, { target: 'human', reason: 'explicit-reveal' }),
    ).resolves.toBe(CLEAN);
  });

  it('keeps a value with a zero width joiner distinct from the same text without it', async () => {
    const withJoiner = await tokenize(WITH_ZWJ);
    const clean = await tokenize(CLEAN);
    const joinerIdentity = must(await vault.resolvePointerIdentity(withJoiner), 'identity');
    expect(joinerIdentity.valueFingerprint).not.toBe(fingerprintValue(key, CLEAN));
    await grant(fingerprintValue(key, CLEAN));
    await expect(reveal(clean)).resolves.toBe(true);
    await expect(reveal(withJoiner)).resolves.toBe(false);
  });

  it('corrects a row whose identity still holds the pre-migration exact value when the value is seen again', async () => {
    const padded = await tokenize(PADDED);
    const row = must(db.secretVault.byValueFingerprint(exactFingerprintValue(key, PADDED)), 'row');
    store
      .openRaw()
      .prepare('UPDATE secret_vault SET value_identity_fingerprint = value_fingerprint')
      .run();
    const stale = must(db.secretVault.byPointerId(row.pointerId), 'stale row');
    expect(stale.valueIdentityFingerprint).toBe(exactFingerprintValue(key, PADDED));

    expect(await tokenize(PADDED)).toBe(padded);

    expect(must(db.secretVault.byPointerId(row.pointerId), 'row').valueIdentityFingerprint).toBe(
      fingerprintValue(key, PADDED),
    );
  });

  it('re-keys both fingerprints on rotation without the twins colliding', async () => {
    await tokenize(PADDED);
    await tokenize(CLEAN);
    const next = rotateFingerprintKey(store.dataDir);
    await expect(vault.refreshFingerprints(next)).resolves.toBe(2);
    const padded = must(
      db.secretVault.byValueFingerprint(exactFingerprintValue(next, PADDED)),
      'padded row',
    );
    const clean = must(
      db.secretVault.byValueFingerprint(exactFingerprintValue(next, CLEAN)),
      'clean row',
    );
    expect(padded.valueIdentityFingerprint).toBe(fingerprintValue(next, CLEAN));
    expect(clean.valueIdentityFingerprint).toBe(fingerprintValue(next, CLEAN));
    expect(padded.fingerprintKeyVersion).toBe(next.version);
  });
});
