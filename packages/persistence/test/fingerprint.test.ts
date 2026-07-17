import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  fingerprintValue,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  rotateFingerprintKey,
} from '../src/fingerprint.ts';

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

  it('starts at version 1 when no key exists', () => {
    const key = rotateFingerprintKey(dir);
    expect(key.version).toBe(1);
  });

  it('throws on a corrupt key file (the old version is unknowable)', () => {
    writeFileSync(keyFile(), 'garbage');
    expect(() => rotateFingerprintKey(dir)).toThrow();
  });
});
