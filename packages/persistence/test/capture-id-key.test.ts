import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { CAPTURE_ID_KEY_FILENAME, loadOrCreateCaptureIdKey } from '../src/capture-id-key.ts';
import { loadOrCreateFingerprintKey, rotateFingerprintKey } from '../src/fingerprint.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-capture-id-key-');

describe('loadOrCreateCaptureIdKey', () => {
  it('mints a 32-byte key once, owner-only, and returns it on every later load', () => {
    const key = loadOrCreateCaptureIdKey(store.dataDir);
    expect(key).toHaveLength(32);
    expect(loadOrCreateCaptureIdKey(store.dataDir).equals(key)).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(join(store.dataDir, CAPTURE_ID_KEY_FILENAME)).mode & 0o777).toBe(0o600);
    }
  });

  it('is untouched by rotating the exception key', () => {
    loadOrCreateFingerprintKey(store.dataDir);
    const key = loadOrCreateCaptureIdKey(store.dataDir);
    rotateFingerprintKey(store.dataDir);
    expect(loadOrCreateCaptureIdKey(store.dataDir).equals(key)).toBe(true);
  });

  it('throws on a corrupt file rather than minting a replacement', () => {
    const file = join(store.dataDir, CAPTURE_ID_KEY_FILENAME);
    writeFileSync(file, 'not a key\n');
    expect(() => loadOrCreateCaptureIdKey(store.dataDir)).toThrow(/corrupt/);
    expect(readFileSync(file, 'utf8')).toBe('not a key\n');
  });
});
