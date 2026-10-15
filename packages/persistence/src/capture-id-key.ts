import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { Occupant } from './paths.ts';
import {
  classifyOccupant,
  createOwnerOnlyFileSync,
  ensureDataDirSync,
  KeyUnclaimableError,
  tightenFile,
} from './paths.ts';

export const CAPTURE_ID_KEY_FILENAME = 'capture-id.key';
const KEY_BYTES = 32;

const OCCUPANT_REASON: Record<Occupant['kind'], string> = {
  symlink: 'a symlink is there; remove it so a key can be created',
  gone: 'the file was removed while it was being created',
  unknown: 'the path is occupied but cannot be inspected; check the permissions on its directory',
};

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
  if (winner === null) {
    const occupant = classifyOccupant(file);
    throw new KeyUnclaimableError(
      `capture id key: cannot create ${file} — ${OCCUPANT_REASON[occupant.kind]}`,
      occupant.cause,
    );
  }
  tightenFile(file);
  return winner;
}
