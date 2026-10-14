import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

import { MAX_VARIABLE_NAME_LENGTH } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { FingerprintKey } from '../../src/fingerprint.ts';
import { loadOrCreateFingerprintKey } from '../../src/fingerprint.ts';
import { SqliteSecretVaultRepository } from '../../src/repositories/secret-vault.ts';
import { FileKeyProvider } from '../../src/vault/key-provider.ts';
import { SecretVault } from '../../src/vault/vault.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// Built at runtime so no credential-shaped literal sits in this file.
const VALUE = ['not', 'a', 'real', 'value', '42'].join('-');
const NAME = ['STRIPE', 'SECRET', 'KEY'].join('_');

describe('SecretVault — variable name', () => {
  const store = useTempStore('aka-vault-name-', { migrated: true });
  let db: DatabaseSync;
  let repo: SqliteSecretVaultRepository;
  let vault: SecretVault;
  let hmac: FingerprintKey;

  beforeEach(() => {
    store.open();
    db = store.openRaw();
    repo = new SqliteSecretVaultRepository(db);
    hmac = loadOrCreateFingerprintKey(store.dataDir);
    vault = new SecretVault({
      repo,
      keys: new FileKeyProvider(join(store.dataDir, 'keys')),
      isConsented: () => true,
    });
  });

  async function tokenize(variableName?: string): Promise<string> {
    const result = await vault.tokenize(
      VALUE,
      {
        ruleId: 'secrets-infra/env-key-value',
        category: 'secret',
        maskedMatch: 'n*******2',
        ...(variableName === undefined ? {} : { variableName }),
      },
      () => hmac,
    );
    if (typeof result !== 'string') throw new Error('expected a pointer');
    return result;
  }

  function storedName(): unknown {
    return (db.prepare('SELECT variable_name FROM secret_vault').get() as Record<string, unknown>)
      .variable_name;
  }

  it('records the variable name on the row it mints', async () => {
    await tokenize(NAME);
    expect(storedName()).toBe(NAME);
  });

  it('stores no name when none was detected', async () => {
    await tokenize();
    expect(storedName()).toBeNull();
  });

  it('takes the latest name a re-detection carries', async () => {
    await tokenize();
    await tokenize(NAME);
    expect(storedName()).toBe(NAME);
    await tokenize('OTHER_NAME');
    expect(storedName()).toBe('OTHER_NAME');
  });

  it('stores no name longer than the cap', async () => {
    await tokenize('K'.repeat(MAX_VARIABLE_NAME_LENGTH + 1));
    expect(storedName()).toBeNull();
    await tokenize('K'.repeat(MAX_VARIABLE_NAME_LENGTH));
    expect(storedName()).toBe('K'.repeat(MAX_VARIABLE_NAME_LENGTH));
  });

  it('keeps the stored name when a re-detection carries none', async () => {
    await tokenize(NAME);
    await tokenize();
    expect(storedName()).toBe(NAME);
  });

  it('shows the name in the inventory and the pointer descriptor, never the value', async () => {
    const pointer = await tokenize(NAME);
    const [entry] = repo.listInventory().items;
    expect(entry?.variableName).toBe(NAME);
    expect(JSON.stringify(entry)).not.toContain(VALUE);
    const descriptor = await vault.describePointer(pointer);
    expect(descriptor?.variableName).toBe(NAME);
  });

  it('leaves the name off an entry that has none', async () => {
    const pointer = await tokenize();
    const [entry] = repo.listInventory().items;
    expect(entry).not.toHaveProperty('variableName');
    expect(await vault.describePointer(pointer)).not.toHaveProperty('variableName');
  });
});
