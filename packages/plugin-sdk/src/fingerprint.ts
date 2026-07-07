// The exception fingerprint key: 32 random bytes stored at <dataDir>/exception.key.
//
// Security intent: detection-exception grants are matched by a fingerprint of the
// exact detected value, and much of what the engine flags is low-entropy (emails,
// card numbers) — a plain hash would be dictionary-attackable offline. So the
// fingerprint is an HMAC under this machine-local key: DETERMINISTIC, so the
// point lookup works, and KEYED, so a copy of the store (a backup, a drained
// event batch, a stolen DB image) leaks nothing about the underlying values.
// The key protects copies of the DB, not the machine itself — an attacker with
// full data-dir access has both file and key by construction. The key material
// must never be logged, surfaced, or shipped anywhere.
import { createHmac, randomBytes } from 'node:crypto';
import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_FILE_MODE, ensureDataDirSync } from './data-dir.ts';

export interface FingerprintKey {
  version: number;
  material: Buffer;
}

const KEY_FILENAME = 'exception.key';
const KEY_MATERIAL_BYTES = 32;

function keyFilePath(dataDir: string): string {
  return join(dataDir, KEY_FILENAME);
}

// Strict parse of the on-disk shape `{ version, material: base64 }`. Throws on
// anything malformed — a corrupt key file must NOT silently mint a new key
// (that would orphan every existing grant); callers fail secure instead (no
// exceptions applied, enforcement proceeds).
function parseKeyFile(raw: string): FingerprintKey {
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('exception key file is corrupt: not a JSON object');
  }
  const { version, material } = parsed as { version?: unknown; material?: unknown };
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
    throw new Error('exception key file is corrupt: bad version');
  }
  if (typeof material !== 'string') {
    throw new Error('exception key file is corrupt: bad material');
  }
  const bytes = Buffer.from(material, 'base64');
  if (bytes.length !== KEY_MATERIAL_BYTES) {
    throw new Error('exception key file is corrupt: bad material length');
  }
  return { version, material: bytes };
}

// Atomic write (tmp + rename) with owner-only mode; chmod after the rename too,
// so a key file that pre-existed with looser permissions is tightened.
function writeKeyFile(dataDir: string, key: FingerprintKey): FingerprintKey {
  ensureDataDirSync(dataDir);
  const file = keyFilePath(dataDir);
  const tmp = `${file}.tmp`;
  const body = JSON.stringify({ version: key.version, material: key.material.toString('base64') });
  writeFileSync(tmp, `${body}\n`, { mode: DATA_FILE_MODE });
  renameSync(tmp, file);
  try {
    chmodSync(file, DATA_FILE_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
  return key;
}

/**
 * Read the fingerprint key if the file exists. Returns null when it is ABSENT;
 * throws when it exists but is corrupt or unreadable — absence and corruption
 * must stay distinguishable, because only absence may ever mint a key.
 */
export function readFingerprintKey(dataDir: string): FingerprintKey | null {
  let raw: string;
  try {
    raw = readFileSync(keyFilePath(dataDir), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err instanceof Error ? err : new Error(String(err));
  }
  return parseKeyFile(raw);
}

/**
 * Load the fingerprint key, minting version 1 on first use. ONLY absence
 * creates a key: a corrupt/unparseable file throws so callers fail secure —
 * silently re-minting would orphan every grant written under the real key.
 * Loading an existing file re-tightens its mode to 0600 (best-effort), covering
 * files created before the mode was enforced at write time.
 */
export function loadOrCreateFingerprintKey(dataDir: string): FingerprintKey {
  const existing = readFingerprintKey(dataDir);
  if (existing) {
    try {
      chmodSync(keyFilePath(dataDir), DATA_FILE_MODE);
    } catch {
      // best-effort: platform without POSIX modes, or not owned by us
    }
    return existing;
  }
  return writeKeyFile(dataDir, { version: 1, material: randomBytes(KEY_MATERIAL_BYTES) });
}

/**
 * Rotate the key: fresh 32 bytes, version bumped past the old one (1 when no
 * key exists yet). Rotation is INVALIDATION — fingerprints cannot be re-keyed
 * without the raw values, which are never stored, so grants written under the
 * old version simply stop matching (they remain, inert, for audit). A corrupt
 * existing file still throws: the old version is unknowable, and silently
 * reusing a version could collide new grants with orphaned ones.
 */
export function rotateFingerprintKey(dataDir: string): FingerprintKey {
  const existing = readFingerprintKey(dataDir);
  return writeKeyFile(dataDir, {
    version: (existing?.version ?? 0) + 1,
    material: randomBytes(KEY_MATERIAL_BYTES),
  });
}

/** The keyed fingerprint of one detected value: HMAC-SHA256 hex under the key. */
export function fingerprintValue(key: FingerprintKey, raw: string): string {
  return createHmac('sha256', key.material).update(raw, 'utf8').digest('hex');
}
