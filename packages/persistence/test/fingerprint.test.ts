import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from '../src/fingerprint.ts';
import { ensureDataDirSync } from '../src/paths.ts';
import type { TempStore } from './helpers/temp-store.ts';
import { withTempStore } from './helpers/temp-store.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-fingerprint-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const keyFile = (): string => join(dir, 'exception.key');

describe('loadOrCreateFingerprintKey', () => {
  it('creates version 1 with 32 bytes of material on first use, mode 0600', () => {
    expect(existsSync(keyFile())).toBe(false);
    const key = loadOrCreateFingerprintKey(dir);
    expect(key.version).toBe(1);
    expect(key.material).toHaveLength(32);
    expect(existsSync(keyFile())).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
    }
  });

  it('is stable across loads (same version, same material)', () => {
    const first = loadOrCreateFingerprintKey(dir);
    const second = loadOrCreateFingerprintKey(dir);
    expect(second.version).toBe(first.version);
    expect(second.material.equals(first.material)).toBe(true);
  });

  it('re-tightens a pre-existing loose key file to 0600 on load (not re-minted)', () => {
    if (process.platform === 'win32') return;
    const key = loadOrCreateFingerprintKey(dir);
    // Simulate a key written before the mode was enforced at write time.
    chmodSync(keyFile(), 0o644);
    const reloaded = loadOrCreateFingerprintKey(dir);
    // Same key — loading tightens the mode, it never mints a replacement.
    expect(reloaded.material.equals(key.material)).toBe(true);
    expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('throws on a corrupt key file rather than minting a replacement', () => {
    writeFileSync(keyFile(), 'not json at all');
    expect(() => loadOrCreateFingerprintKey(dir)).toThrow();
    // The corrupt file is left in place — nothing was silently re-created.
    expect(readFileSync(keyFile(), 'utf8')).toBe('not json at all');
  });

  it('throws on a parseable file with bad material (wrong length)', () => {
    writeFileSync(
      keyFile(),
      JSON.stringify({ version: 1, material: Buffer.from('short').toString('base64') }),
    );
    expect(() => loadOrCreateFingerprintKey(dir)).toThrow(/corrupt/);
  });
});

describe('readFingerprintKey', () => {
  it('returns null when the file is absent (and creates nothing)', () => {
    expect(readFingerprintKey(dir)).toBeNull();
    expect(existsSync(keyFile())).toBe(false);
  });

  it('throws on a corrupt file — absence and corruption stay distinguishable', () => {
    writeFileSync(keyFile(), '{"version":"one"}');
    expect(() => readFingerprintKey(dir)).toThrow(/corrupt/);
  });
});

describe('fingerprintValue', () => {
  it('is deterministic for the same key and value', () => {
    const key = loadOrCreateFingerprintKey(dir);
    const a = fingerprintValue(key, 'detected-value-alpha');
    expect(a).toBe(fingerprintValue(key, 'detected-value-alpha'));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('differs for distinct values under one key', () => {
    const key = loadOrCreateFingerprintKey(dir);
    expect(fingerprintValue(key, 'value-a')).not.toBe(fingerprintValue(key, 'value-b'));
  });

  it('differs for the same value under distinct keys (keyed, not a plain hash)', () => {
    const other = mkdtempSync(join(tmpdir(), 'aka-fingerprint-b-'));
    try {
      const keyA = loadOrCreateFingerprintKey(dir);
      const keyB = loadOrCreateFingerprintKey(other);
      expect(fingerprintValue(keyA, 'same-value')).not.toBe(fingerprintValue(keyB, 'same-value'));
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });
});

describe('rotateFingerprintKey', () => {
  it('bumps the version, replaces the material, and changes fingerprints', () => {
    const v1 = loadOrCreateFingerprintKey(dir);
    const v2 = rotateFingerprintKey(dir);
    expect(v2.version).toBe(v1.version + 1);
    expect(v2.material.equals(v1.material)).toBe(false);
    expect(fingerprintValue(v2, 'value')).not.toBe(fingerprintValue(v1, 'value'));
    // The rotated key is what subsequent loads see.
    const reloaded = loadOrCreateFingerprintKey(dir);
    expect(reloaded.version).toBe(v2.version);
    expect(reloaded.material.equals(v2.material)).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(keyFile()).mode & 0o777).toBe(0o600);
    }
  });

  it('starts at version 1 when no key exists and the store has none either', () => {
    const key = rotateFingerprintKey(dir);
    expect(key.version).toBe(1);
  });

  it('throws on a corrupt key file (the old version is unknowable)', () => {
    writeFileSync(keyFile(), 'garbage');
    expect(() => rotateFingerprintKey(dir)).toThrow();
  });
});

// A minted version must never collide with one the store already references.
// Deleting exception.key — what the corrupt-key recovery guidance says to do —
// takes the version with it, so an unguarded mint restarts at 1 while stored
// rows written under the DELETED material still say 1. Those rows then look
// current to every version check in the product, and a grant approved from one
// is inert the moment it is created. The store keeps the answer because the rows
// outlive the key file.
describe('a minted version never reuses one the store already references', () => {
  // Rows are written through the real repository so the columns the floor reads
  // are the ones the product actually writes.
  function seedLedger(store: TempStore, keyVersion: number): Promise<void> {
    return store.open().exceptions.recordBlocked({
      reference: `ref-v${String(keyVersion)}`,
      ruleId: 'aws-access-key-id',
      category: 'secret',
      valueFingerprint: keyVersion.toString(16).padStart(64, '0'),
      keyVersion,
      maskedValue: 'A*****Q',
      sessionId: null,
      repo: null,
    });
  }

  function seedGrant(store: TempStore, keyVersion: number): Promise<unknown> {
    return store.open().exceptions.create({
      ruleId: 'aws-access-key-id',
      category: 'secret',
      valueFingerprint: (keyVersion + 0xf00).toString(16).padStart(64, '0'),
      keyVersion,
      maskedValue: 'A*****Q',
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
      justification: 'seeded',
      conditions: null,
      createdBy: 'tester',
      createdVia: 'cli-add',
    });
  }

  it('mints past a blocked-ledger row after the key file is deleted', async () => {
    await withTempStore(async (store) => {
      // The shape the bug needs: a ledger row under v1, then the key deleted.
      const original = loadOrCreateFingerprintKey(store.dataDir);
      expect(original.version).toBe(1);
      await seedLedger(store, original.version);
      rmSync(join(store.dataDir, 'exception.key'));

      const reminted = loadOrCreateFingerprintKey(store.dataDir);
      // NOT 1: the row under the deleted material owns that version forever, so
      // reusing it would make the two indistinguishable.
      expect(reminted.version).toBe(2);
      expect(reminted.material.equals(original.material)).toBe(false);
    });
  });

  it('mints past a grant row too — both tables pin a version', async () => {
    await withTempStore(async (store) => {
      await seedGrant(store, 7);
      expect(loadOrCreateFingerprintKey(store.dataDir).version).toBe(8);
    });
  });

  it('takes the highest version across both tables', async () => {
    await withTempStore(async (store) => {
      await seedLedger(store, 2);
      await seedGrant(store, 5);
      expect(loadOrCreateFingerprintKey(store.dataDir).version).toBe(6);
    });
  });

  it('rotating after a delete clears the stored versions instead of restarting at 1', async () => {
    await withTempStore(async (store) => {
      await seedLedger(store, 1);
      // No key file at all: rotate used to fall back to (undefined ?? 0) + 1.
      expect(readFingerprintKey(store.dataDir)).toBeNull();
      expect(rotateFingerprintKey(store.dataDir).version).toBe(2);
    });
  });

  it('still mints version 1 on a store that references no key version', () => {
    withTempStore((store) => {
      // The floor must not inflate the common case — a first run mints v1.
      expect(loadOrCreateFingerprintKey(store.dataDir).version).toBe(1);
    });
  });

  it('rotates from the key file when it is ahead of the store', async () => {
    await withTempStore(async (store) => {
      const v1 = loadOrCreateFingerprintKey(store.dataDir);
      await seedLedger(store, v1.version);
      const v2 = rotateFingerprintKey(store.dataDir);
      const v3 = rotateFingerprintKey(store.dataDir);
      // Nothing was written under v2, so the store floor stays at 1 — the key
      // file is the higher of the two and rotation keeps stepping by one.
      expect(v2.version).toBe(2);
      expect(v3.version).toBe(3);
    });
  });

  it('degrades to the un-floored behaviour when the store cannot be read', () => {
    // An unreadable store must never stop a hook from minting the key it needs
    // — the floor is a hardening pass, not a precondition. Fail-open here is
    // deliberate, so pin it rather than let a future change make it fail-closed.
    ensureDataDirSync(dir);
    writeFileSync(join(dir, 'aka.db'), 'this is not a SQLite database at all\n');
    const key = loadOrCreateFingerprintKey(dir);
    expect(key.version).toBe(1);
    expect(key.material).toHaveLength(32);
  });

  it('reads the floor without creating a store', () => {
    // Resolving a key must never bring a database into existence as a side
    // effect — that would leave an empty store on a machine that only ever ran
    // a scan.
    expect(existsSync(join(dir, 'aka.db'))).toBe(false);
    expect(loadOrCreateFingerprintKey(dir).version).toBe(1);
    expect(existsSync(join(dir, 'aka.db'))).toBe(false);
  });
});
