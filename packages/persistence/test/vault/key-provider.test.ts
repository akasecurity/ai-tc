import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createKeyProvider,
  FileKeyProvider,
  KeychainKeyProvider,
  VAULT_KEY_FILENAME,
  VaultKeyEpochMissingError,
} from '../../src/vault/key-provider.ts';

const POSIX_MODES = process.platform !== 'win32';

describe('FileKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-key-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const keyFile = (): string => join(dir, VAULT_KEY_FILENAME);

  it('mints version 1 with 32 bytes of material on first use', async () => {
    const provider = new FileKeyProvider(dir);
    const key = await provider.loadOrCreate();

    expect(key.version).toBe(1);
    expect(key.material).toHaveLength(32);
  });

  it.skipIf(!POSIX_MODES)('writes the key file owner-only', async () => {
    await new FileKeyProvider(dir).loadOrCreate();

    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('returns the same material on a second load rather than re-minting', async () => {
    const first = await new FileKeyProvider(dir).loadOrCreate();
    const second = await new FileKeyProvider(dir).loadOrCreate();

    expect(second.version).toBe(first.version);
    expect(second.material.equals(first.material)).toBe(true);
  });

  // The property that separates this key from the fingerprint key: a pointer
  // minted under an old epoch is already out in transcripts and files, so its
  // material must survive every later rotation.
  it('retains the previous epoch after a rotation', async () => {
    const provider = new FileKeyProvider(dir);
    const v1 = await provider.loadOrCreate();
    const v2 = await provider.rotate();

    expect(v2.version).toBe(2);
    expect(v2.material.equals(v1.material)).toBe(false);

    const recovered = await provider.materialFor(1);
    expect(recovered.version).toBe(1);
    expect(recovered.material.equals(v1.material)).toBe(true);
  });

  it('retains every epoch across repeated rotations', async () => {
    const provider = new FileKeyProvider(dir);
    const v1 = await provider.loadOrCreate();
    const v2 = await provider.rotate();
    const v3 = await provider.rotate();

    expect(v3.version).toBe(3);
    expect((await provider.materialFor(1)).material.equals(v1.material)).toBe(true);
    expect((await provider.materialFor(2)).material.equals(v2.material)).toBe(true);
    expect((await provider.materialFor(3)).material.equals(v3.material)).toBe(true);
  });

  it('reports the current epoch after a rotation on a fresh load', async () => {
    await new FileKeyProvider(dir).loadOrCreate();
    const rotated = await new FileKeyProvider(dir).rotate();
    const reloaded = await new FileKeyProvider(dir).loadOrCreate();

    expect(reloaded.version).toBe(2);
    expect(reloaded.material.equals(rotated.material)).toBe(true);
  });

  it('throws on a corrupt key file and leaves it untouched', async () => {
    await new FileKeyProvider(dir).loadOrCreate();
    writeFileSync(keyFile(), '{ not json');
    const before = readFileSync(keyFile());

    await expect(new FileKeyProvider(dir).loadOrCreate()).rejects.toThrow();

    // Re-minting over a damaged keyring would orphan every ciphertext and every
    // outstanding pointer, so the file must survive the failed load byte for byte.
    expect(readFileSync(keyFile()).equals(before)).toBe(true);
  });

  it('throws on a key file whose material is the wrong length', async () => {
    writeFileSync(keyFile(), JSON.stringify({ current: 1, keys: { 1: 'c2hvcnQ=' } }));

    await expect(new FileKeyProvider(dir).loadOrCreate()).rejects.toThrow(/corrupt/);
  });

  it('throws VaultKeyEpochMissingError for an epoch that was never minted', async () => {
    const provider = new FileKeyProvider(dir);
    await provider.loadOrCreate();

    await expect(provider.materialFor(9)).rejects.toBeInstanceOf(VaultKeyEpochMissingError);
  });

  it('throws VaultKeyEpochMissingError when no keyring exists at all', async () => {
    await expect(new FileKeyProvider(dir).materialFor(1)).rejects.toBeInstanceOf(
      VaultKeyEpochMissingError,
    );
  });
});

describe('createKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-vault-key-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns a FileKeyProvider for file custody', () => {
    expect(createKeyProvider('file', dir)).toBeInstanceOf(FileKeyProvider);
  });

  // Custody is an open discriminant, so an unrecognized value must land on the
  // safe default rather than leaving the vault without a provider.
  it('falls back to a FileKeyProvider for an unknown custody value', () => {
    expect(createKeyProvider('hsm-cluster', dir)).toBeInstanceOf(FileKeyProvider);
  });

  it.skipIf(process.platform === 'darwin')(
    'rejects keychain custody on a platform without one',
    () => {
      expect(() => new KeychainKeyProvider(dir)).toThrow(/not available on this platform/);
    },
  );
});
