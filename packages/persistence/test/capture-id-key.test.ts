import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { CAPTURE_ID_KEY_FILENAME, loadOrCreateCaptureIdKey } from '../src/capture-id-key.ts';
import { loadOrCreateFingerprintKey, rotateFingerprintKey } from '../src/fingerprint.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-capture-id-key-'));
});

afterEach(() => {
  removeTree(dir);
});

describe('loadOrCreateCaptureIdKey', () => {
  it('mints a 32-byte key once, owner-only, and returns it on every later load', () => {
    const key = loadOrCreateCaptureIdKey(dir);
    expect(key).toHaveLength(32);
    expect(loadOrCreateCaptureIdKey(dir).equals(key)).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(join(dir, CAPTURE_ID_KEY_FILENAME)).mode & 0o777).toBe(0o600);
    }
  });

  it('is untouched by rotating the exception key', () => {
    loadOrCreateFingerprintKey(dir);
    const key = loadOrCreateCaptureIdKey(dir);
    rotateFingerprintKey(dir);
    expect(loadOrCreateCaptureIdKey(dir).equals(key)).toBe(true);
  });

  it('throws on a corrupt file rather than minting a replacement', () => {
    const file = join(dir, CAPTURE_ID_KEY_FILENAME);
    writeFileSync(file, 'not a key\n');
    expect(() => loadOrCreateCaptureIdKey(dir)).toThrow(/corrupt/);
    expect(readFileSync(file, 'utf8')).toBe('not a key\n');
  });
});
