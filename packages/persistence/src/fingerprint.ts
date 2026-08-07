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
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { FingerprintKeyState } from '@akasecurity/schema';
import { isMatchableUnder } from '@akasecurity/schema';

import { getRow } from './internal/rows.ts';
import {
  classifyOccupant,
  createOwnerOnlyFileSync,
  DB_FILENAME,
  ensureDataDirSync,
  KeyUnclaimableError,
  type Occupant,
  tightenFile,
  writeOwnerOnlyFileSync,
} from './paths.ts';

export interface FingerprintKey {
  version: number;
  material: Buffer;
}

export const EXCEPTION_KEY_FILENAME = 'exception.key';
const KEY_MATERIAL_BYTES = 32;

function keyFilePath(dataDir: string): string {
  return join(dataDir, EXCEPTION_KEY_FILENAME);
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

// Every table that records WHICH key material produced a stored fingerprint,
// with the column holding that epoch. The version integer is the only handle any
// of them has on the key — see storedKeyVersionFloor.
//
// secret_vault carries TWO version columns and only one of them belongs here:
// `fingerprint_key_version` is the exception.key epoch its value_fingerprint was
// derived under, while `key_version` is the vault-key epoch its ciphertext is
// sealed under — a different key on a different rotation. Reading the latter
// would tie two independent rotations together and skip versions on every mint.
const KEY_VERSION_COLUMNS: Record<string, string> = {
  exceptions: 'key_version',
  blocked_detections: 'key_version',
  secret_vault: 'fingerprint_key_version',
};

// SQLITE_ERROR — the generic code a missing table reports. node:sqlite gives
// every SQLite failure the same `code` ('ERR_SQLITE_ERROR'), so only `errcode`
// separates "this store has no such table" from "this store is damaged or
// locked": SQLITE_NOTADB and SQLITE_BUSY both arrive here too, and treating
// those as an absent table is what would silently under-report the floor.
const SQLITE_ERROR = 1;

// Long enough to ride out the moment a writer holds an exclusive lock, short
// enough that the mint path — which the plugin runs while a hook is waiting —
// fails fast instead of stalling. The whole read is best-effort hardening; the
// default 2s, taken twice, is a quarter-minute of a user's session.
const FLOOR_BUSY_TIMEOUT_MS = 250;

/** Raised when the store exists but cannot answer which key versions it holds. */
class FloorUnreadableError extends Error {
  readonly code = 'floor-unreadable';
  constructor(cause: unknown) {
    super(
      `cannot read the stored fingerprint key versions: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
    this.name = 'FloorUnreadableError';
  }
}

/**
 * The highest key version any stored row already references — 0 when the store
 * holds none, or does not exist yet.
 *
 * A minted version must never collide with one already in the store. Deleting
 * `exception.key` — which the corrupt-key recovery guidance tells users to do —
 * loses the version, so an unguarded mint restarts at 1 while rows written under
 * the DELETED material still say 1. Those rows then look current: a grant
 * approved from one is fingerprinted under material that no longer exists and is
 * inert the moment it is created, which is exactly what the approve-side version
 * check exists to prevent. Reading the floor from the store closes that, because
 * the rows outlive the key file.
 *
 * Vault rows count for the same reason and are the likeliest to be the only ones
 * present: vaulting happens on ordinary detections, while the two grant tables
 * stay empty until someone blocks or approves something. Colliding there also
 * breaks one-value-one-pointer — the re-minted material stops matching every
 * stored fingerprint, so a known secret mints a second row and a second pointer.
 *
 * THROWS rather than guessing when the store cannot answer. Returning 0 on a
 * locked or damaged store would be the one direction that is unsafe: too LOW a
 * floor is exactly the collision above, so a swallowed failure quietly reopens
 * the hole this exists to close. Callers already fail secure on a throw — the
 * plugin degrades to writing no ledger row, which costs an approvable row and
 * never an enforcement decision.
 *
 * Opened only when the store already exists, so resolving a key never creates
 * one, read-only, and with a short busy timeout so a contended store fails fast.
 */
function storedKeyVersionFloor(dataDir: string): number {
  const file = join(dataDir, DB_FILENAME);
  if (!existsSync(file)) return 0;
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(file, { readOnly: true });
    db.exec(`PRAGMA busy_timeout = ${String(FLOOR_BUSY_TIMEOUT_MS)}`);
    let floor = 0;
    for (const [table, column] of Object.entries(KEY_VERSION_COLUMNS)) {
      try {
        // MAX() over an empty table is NULL, which arrives as a null column.
        const row = getRow<{ v: number | null }>(
          db.prepare(`SELECT MAX(${column}) AS v FROM ${table}`),
        );
        floor = Math.max(floor, row?.v ?? 0);
      } catch (err) {
        // A genuinely absent table contributes nothing and is not a failure:
        // this opens its own handle and runs no migrations, so it can meet a
        // store written before the table was added. Anything else — damaged,
        // locked, unreadable — means the floor is unknown, not zero.
        if ((err as { errcode?: number }).errcode !== SQLITE_ERROR) {
          throw new FloorUnreadableError(err);
        }
      }
    }
    return floor;
  } catch (err) {
    throw err instanceof FloorUnreadableError ? err : new FloorUnreadableError(err);
  } finally {
    db?.close();
  }
}

function serializeKey(key: FingerprintKey): string {
  return JSON.stringify({ version: key.version, material: key.material.toString('base64') });
}

// Owner-only atomic REPLACE (tmp + rename), so a key file that pre-existed with
// looser permissions ends 0600 rather than carrying its mode through the
// rename. Replacing is what ROTATION is for; a first mint must not use this —
// see createKeyFileExclusive.
function writeKeyFile(dataDir: string, key: FingerprintKey): FingerprintKey {
  ensureDataDirSync(dataDir);
  writeOwnerOnlyFileSync(keyFilePath(dataDir), `${serializeKey(key)}\n`);
  return key;
}

/**
 * First mint: the key is CREATED, never replaced.
 *
 * Reading the key and writing it are two syscalls, so on a fresh store every
 * process that gets through the absence check before anyone's write lands mints
 * material of its own — the plugin's hooks, the CLI and the dashboard all reach
 * this path and all run as separate processes. Publishing with a replace lets
 * the LAST writer win, which is the one outcome this module exists to prevent:
 * a fingerprint is an HMAC under this key and the raw value is never stored, so
 * every grant a losing process writes is unmatchable the moment it is created,
 * while still reporting as approved. That is the same orphaning a corrupt key
 * throws to avoid, reached by accident instead of by re-minting.
 *
 * `createOwnerOnlyFileSync` publishes by link, so exactly one caller wins and a
 * concurrent reader never sees a partially written key. The loser re-reads and
 * ADOPTS the winner's key — including its VERSION, since rows written under a
 * version the key file does not carry are exactly the inert grants above.
 *
 * When the path is taken but no key can be read back, this throws rather than
 * falling back to a replacing write, because that fallback is the clobber this
 * exists to remove. Reaching that throw means the re-read returned null, and
 * readFingerprintKey only returns null on ENOENT — so the path is occupied by
 * something that does not resolve to a readable file. THREE states produce that,
 * reported apart because their remedies differ: a DANGLING symlink at the key
 * path (which the caller has to remove), a key unlinked between the failed
 * publish and the re-read, and a path that cannot be inspected at all. A corrupt
 * winner throws from the parse, for the reason it always does.
 *
 * A symlink whose target is a READABLE key never reaches this function at all:
 * the load path reads through it and ADOPTS it, because readFileSync follows
 * links. So the refusal below is narrower than it reads — symlinks are refused
 * only where they are also unresolvable. That is not an escalation (the data dir
 * is 0700, and anyone who can plant a link in it can read the key directly), but
 * the operator is then using a key that is not at the path they think it is.
 */
function createKeyFile(dataDir: string, key: FingerprintKey): FingerprintKey {
  ensureDataDirSync(dataDir);
  const file = keyFilePath(dataDir);
  if (createOwnerOnlyFileSync(file, `${serializeKey(key)}\n`)) return key;

  const winner = readFingerprintKey(dataDir);
  if (winner) {
    // Re-tighten for the same reason the load path does: the winner may be an
    // older build, or a restore, that published without the mode.
    tightenFile(file);
    return winner;
  }
  const occupant = classifyOccupant(file);
  throw new KeyUnclaimableError(occupantMessage(file, occupant.kind), occupant.cause);
}

function occupantMessage(file: string, kind: Occupant['kind']): string {
  switch (kind) {
    case 'symlink':
      return `exception key file is a symlink (${file}); remove it so a key can be created`;
    case 'gone':
      return 'exception key file was removed while it was being created';
    case 'unknown':
      return `exception key file (${file}) is occupied but cannot be inspected; check the permissions on its directory`;
  }
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
 * Load the fingerprint key, minting one on first use. ONLY absence creates a
 * key: a corrupt/unparseable file throws so callers fail secure — silently
 * re-minting would orphan every grant written under the real key. Loading an
 * existing file re-tightens its mode to 0600 (best-effort), covering files
 * created before the mode was enforced at write time.
 *
 * A mint takes version 1 on a fresh store, and otherwise the first version the
 * store has not already seen — so material minted after the key file was deleted
 * is never mistaken for the material the stored rows were written under. A store
 * that cannot report its versions throws instead of minting: a colliding key is
 * worse than no key, because it produces grants that silently never match.
 *
 * The mint is creation-exclusive, so concurrent callers on a fresh store
 * converge on ONE key instead of each publishing their own over the last —
 * including the version, which is adopted from the winner rather than kept from
 * whatever this call computed before it lost.
 */
export function loadOrCreateFingerprintKey(dataDir: string): FingerprintKey {
  const existing = readFingerprintKey(dataDir);
  if (existing) {
    // Re-tighten to 0600 on load, covering a key written before the mode was
    // enforced at write time. Best-effort — never mints a replacement.
    tightenFile(keyFilePath(dataDir));
    return existing;
  }
  return createKeyFile(dataDir, {
    version: storedKeyVersionFloor(dataDir) + 1,
    material: randomBytes(KEY_MATERIAL_BYTES),
  });
}

/**
 * Rotate the key: fresh 32 bytes, version bumped past both the old key file and
 * anything the store already references. Rotation is INVALIDATION — fingerprints
 * cannot be re-keyed without the raw values, which are never stored, so grants
 * written under the old version simply stop matching (they remain, inert, for
 * audit). A corrupt existing file still throws: the old version is unknowable,
 * and silently reusing a version could collide new grants with orphaned ones.
 *
 * The store floor matters when the key file is ABSENT — rotating after a delete
 * would otherwise restart at 1 and collide with rows written under the deleted
 * material.
 */
export function rotateFingerprintKey(dataDir: string): FingerprintKey {
  const existing = readFingerprintKey(dataDir);
  return writeKeyFile(dataDir, {
    version: Math.max(existing?.version ?? 0, storedKeyVersionFloor(dataDir)) + 1,
    material: randomBytes(KEY_MATERIAL_BYTES),
  });
}

/** The keyed fingerprint of one detected value: HMAC-SHA256 hex under the key. */
export function fingerprintValue(key: FingerprintKey, raw: string): string {
  return createHmac('sha256', key.material).update(raw, 'utf8').digest('hex');
}

/**
 * Whether a stored fingerprint — a grant, or a blocked-ledger row — was written
 * under the key in use now, and so can still be matched.
 *
 * The rule itself is `isMatchableUnder` in @akasecurity/schema, the one package
 * the approve surfaces AND the dashboard can all import; this is the adapter for
 * callers that hold a loaded key rather than a UI-facing state. A second copy of
 * the rule is how the server and the UI come to disagree about which rows are
 * usable, so there is deliberately only one.
 *
 * An absent key fails on its own terms: the material is gone, so no stored
 * fingerprint can be reproduced.
 */
export function isCurrentKeyVersion(key: FingerprintKey | null, keyVersion: number): boolean {
  return isMatchableUnder(keyVersion, keyStateOf(key));
}

/** A loaded key (or its absence) as the shared, UI-facing state. */
export function keyStateOf(key: FingerprintKey | null): FingerprintKeyState {
  return key === null ? { status: 'absent' } : { status: 'present', version: key.version };
}
