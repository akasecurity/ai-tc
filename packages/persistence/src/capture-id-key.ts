import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { createOwnerOnlyFileSync, ensureDataDirSync, tightenFile } from './paths.ts';

export const CAPTURE_ID_KEY_FILENAME = 'capture-id.key';
const KEY_BYTES = 32;

function readKey(file: string): Buffer | null {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err instanceof Error ? err : new Error(String(err));
  }
  const key = Buffer.from(raw.trim(), 'base64');
  if (key.length !== KEY_BYTES) throw new Error('capture id key file is corrupt');
  return key;
}

/**
 * The key a rewritten capture's wire id is keyed under. Machine-local, never
 * rotated, and created once: concurrent first callers converge on one key. A
 * corrupt file throws rather than minting a replacement.
 */
export function loadOrCreateCaptureIdKey(dataDir: string): Buffer {
  const file = join(dataDir, CAPTURE_ID_KEY_FILENAME);
  const existing = readKey(file);
  if (existing) {
    tightenFile(file);
    return existing;
  }
  ensureDataDirSync(dataDir);
  const key = randomBytes(KEY_BYTES);
  if (createOwnerOnlyFileSync(file, `${key.toString('base64')}\n`)) return key;
  const winner = readKey(file);
  if (winner === null) throw new Error(`capture id key file (${file}) could not be created`);
  return winner;
}
