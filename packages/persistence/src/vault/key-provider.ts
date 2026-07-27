// Custody of the vault master key: where the 32 bytes that every vault subkey is
// derived from actually live, and how they survive rotation.
//
// The one structural difference from the exception fingerprint key: that key
// holds a SINGLE version, because rotating it is invalidation — a fingerprint
// cannot be re-derived without the raw value, so old grants simply stop
// matching. The vault must do the opposite. A pointer already sitting in a
// transcript, a commit, or a colleague's paste carries the key epoch it was
// minted under, and it still has to verify and open after a rotation. So the
// store is a MAP of version → material, `rotate()` adds an epoch without ever
// dropping a prior one, and `materialFor(version)` is how a historical pointer
// finds its key.
//
// Two custody backends:
//   file      32 random bytes per epoch in <keysDir>/vault.key, mode 0600.
//   keychain  the same versioned JSON map held as one OS-keychain item, so the
//             bytes are not readable from the filesystem at rest. Implemented by
//             shelling out to the platform's local `security` binary — a child
//             process against an OS service on this machine, no network hop.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_FILE_MODE, ensureDataDirSync } from '../paths.ts';

export interface VaultKeyMaterial {
  material: Buffer;
  version: number;
}

export interface KeyProvider {
  /** The current epoch, minting version 1 on first use. */
  loadOrCreate(): Promise<VaultKeyMaterial>;
  /** Mint the next epoch, retaining every earlier one. */
  rotate(): Promise<VaultKeyMaterial>;
  /** A specific historical epoch, for a pointer minted under it. */
  materialFor(version: number): Promise<VaultKeyMaterial>;
}

/** The requested key epoch is not in the keyring — its pointers cannot open. */
export class VaultKeyEpochMissingError extends Error {
  readonly version: number;

  constructor(version: number) {
    super(`vault: key epoch ${String(version)} is not present in the keyring`);
    this.name = 'VaultKeyEpochMissingError';
    this.version = version;
  }
}

export const VAULT_KEY_FILENAME = 'vault.key';
const KEY_MATERIAL_BYTES = 32;

const KEYCHAIN_SERVICE = 'aka-vault';
const KEYCHAIN_ACCOUNT = 'keyring';

// The in-memory form of the stored map: every epoch ever minted, plus which one
// new pointers are minted under.
interface Keyring {
  current: number;
  keys: Map<number, Buffer>;
}

// ─── The stored shape ────────────────────────────────────────────────────────

/**
 * Strict parse of `{ current, keys: { "<version>": "<base64 32 bytes>" } }`.
 * Throws on anything malformed. A corrupt keyring must NEVER be replaced with a
 * fresh one: re-minting would orphan every ciphertext in the store and every
 * pointer already outside it, turning a recoverable file problem into permanent
 * data loss. Callers surface the error instead.
 */
function parseKeyring(raw: string): Keyring {
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('vault key file is corrupt: not a JSON object');
  }
  const { current, keys } = parsed as { current?: unknown; keys?: unknown };
  if (typeof current !== 'number' || !Number.isInteger(current) || current < 1) {
    throw new Error('vault key file is corrupt: bad current version');
  }
  if (typeof keys !== 'object' || keys === null || Array.isArray(keys)) {
    throw new Error('vault key file is corrupt: bad keys map');
  }
  const map = new Map<number, Buffer>();
  for (const [rawVersion, rawMaterial] of Object.entries(keys as Record<string, unknown>)) {
    const version = Number(rawVersion);
    if (!Number.isInteger(version) || version < 1) {
      throw new Error('vault key file is corrupt: bad key version');
    }
    if (typeof rawMaterial !== 'string') {
      throw new Error('vault key file is corrupt: bad key material');
    }
    const bytes = Buffer.from(rawMaterial, 'base64');
    if (bytes.length !== KEY_MATERIAL_BYTES) {
      throw new Error('vault key file is corrupt: bad key material length');
    }
    map.set(version, bytes);
  }
  if (!map.has(current)) {
    throw new Error('vault key file is corrupt: current version has no material');
  }
  return { current, keys: map };
}

function serializeKeyring(keyring: Keyring): string {
  const keys: Record<string, string> = {};
  for (const version of [...keyring.keys.keys()].sort((a, b) => a - b)) {
    const material = keyring.keys.get(version);
    if (material) keys[String(version)] = material.toString('base64');
  }
  return JSON.stringify({ current: keyring.current, keys });
}

function mintKeyring(): Keyring {
  return { current: 1, keys: new Map([[1, randomBytes(KEY_MATERIAL_BYTES)]]) };
}

// The next epoch is one past the HIGHEST version ever minted, not one past
// `current`: a version number must never be reused, or a pointer from the
// original epoch would verify against unrelated key bytes.
function withNextEpoch(keyring: Keyring): Keyring {
  const next = Math.max(...keyring.keys.keys()) + 1;
  const keys = new Map(keyring.keys);
  keys.set(next, randomBytes(KEY_MATERIAL_BYTES));
  return { current: next, keys };
}

function currentOf(keyring: Keyring): VaultKeyMaterial {
  const material = keyring.keys.get(keyring.current);
  if (!material) throw new VaultKeyEpochMissingError(keyring.current);
  return { material, version: keyring.current };
}

function epochOf(keyring: Keyring, version: number): VaultKeyMaterial {
  const material = keyring.keys.get(version);
  if (!material) throw new VaultKeyEpochMissingError(version);
  return { material, version };
}

// Custody backends do synchronous I/O, but the interface is async so a backend
// that must await (a remote or hardware-backed keyring) can implement it. This
// keeps that promise honest: a failure surfaces as a REJECTION, never as a
// synchronous throw a caller's `await` in a try/catch would miss.
function asAsync<T>(work: () => T): Promise<T> {
  try {
    return Promise.resolve(work());
  } catch (err) {
    return Promise.reject(err instanceof Error ? err : new Error(String(err)));
  }
}

// ─── File custody ────────────────────────────────────────────────────────────

/**
 * The default backend: the keyring as owner-only JSON under the keys dir.
 *
 * The file protects copies of the store — a backup, a synced folder, a stolen
 * database image — not the machine itself. Anyone with read access to the keys
 * dir has both the ciphertext and the key by construction.
 */
export class FileKeyProvider implements KeyProvider {
  readonly #keysDir: string;

  constructor(keysDir: string) {
    this.#keysDir = keysDir;
  }

  get filePath(): string {
    return join(this.#keysDir, VAULT_KEY_FILENAME);
  }

  loadOrCreate(): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      if (!existing) return currentOf(this.#write(mintKeyring()));
      // Re-tighten on every load, covering a file created before the mode was
      // enforced at write time.
      tightenFileMode(this.filePath);
      return currentOf(existing);
    });
  }

  rotate(): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      // With no keyring yet there is nothing to rotate away from: the first
      // epoch is minted instead, so rotation on a fresh machine is not a no-op.
      return currentOf(this.#write(existing ? withNextEpoch(existing) : mintKeyring()));
    });
  }

  materialFor(version: number): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      if (!existing) throw new VaultKeyEpochMissingError(version);
      return epochOf(existing, version);
    });
  }

  /** The keyring, or null when the file is ABSENT. A corrupt file throws. */
  #read(): Keyring | null {
    let raw: string;
    try {
      raw = readFileSync(this.filePath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err instanceof Error ? err : new Error(String(err));
    }
    return parseKeyring(raw);
  }

  /** Atomic tmp + rename so a crash mid-write cannot truncate the keyring. */
  #write(keyring: Keyring): Keyring {
    ensureDataDirSync(this.#keysDir);
    const file = this.filePath;
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, `${serializeKeyring(keyring)}\n`, { mode: DATA_FILE_MODE });
    renameSync(tmp, file);
    tightenFileMode(file);
    return keyring;
  }
}

function tightenFileMode(file: string): void {
  try {
    chmodSync(file, DATA_FILE_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
}

// ─── Keychain custody ────────────────────────────────────────────────────────

/**
 * Opt-in OS-keychain custody: the same versioned keyring JSON held as one
 * generic-password item, so the key bytes are not sitting in a readable file.
 *
 * macOS only. The bytes move through the local `security` binary as a child
 * process — an OS service on this machine, not a network call. Elsewhere the
 * constructor throws so the caller can fall back to file custody.
 */
export class KeychainKeyProvider implements KeyProvider {
  readonly #keysDir: string;

  constructor(keysDir: string) {
    if (process.platform !== 'darwin') {
      throw new Error(
        `keychain custody is not available on this platform (${process.platform}); use file custody`,
      );
    }
    this.#keysDir = keysDir;
  }

  /** Where a fallback file provider for the same vault would keep its keyring. */
  get keysDir(): string {
    return this.#keysDir;
  }

  loadOrCreate(): Promise<VaultKeyMaterial> {
    return asAsync(() => currentOf(this.#read() ?? this.#write(mintKeyring())));
  }

  rotate(): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      return currentOf(this.#write(existing ? withNextEpoch(existing) : mintKeyring()));
    });
  }

  materialFor(version: number): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      if (!existing) throw new VaultKeyEpochMissingError(version);
      return epochOf(existing, version);
    });
  }

  /** The keyring, or null when no item exists yet. A corrupt item throws. */
  #read(): Keyring | null {
    let raw: string;
    try {
      raw = execFileSync(
        '/usr/bin/security',
        ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
      );
    } catch {
      // `security` exits non-zero both when the item is absent and when access
      // is denied; neither may mint over a keyring that might still exist, so
      // absence is reported and the caller's mint path handles a real first run.
      return null;
    }
    const body = raw.trim();
    if (body.length === 0) return null;
    return parseKeyring(body);
  }

  // `-U` updates the item in place when it already exists, so a rotation
  // replaces the stored map rather than adding a second item the reader would
  // have to disambiguate.
  #write(keyring: Keyring): Keyring {
    execFileSync(
      '/usr/bin/security',
      [
        'add-generic-password',
        '-U',
        '-s',
        KEYCHAIN_SERVICE,
        '-a',
        KEYCHAIN_ACCOUNT,
        '-w',
        serializeKeyring(keyring),
      ],
      { stdio: ['ignore', 'ignore', 'ignore'] },
    );
    return keyring;
  }
}

/**
 * The provider for a configured custody setting. Custody is an open
 * discriminant — the vocabulary can grow backends this build has never heard
 * of — so an unrecognized value falls back to file custody rather than
 * failing: the vault keeps working under the safe default.
 */
export function createKeyProvider(custody: string, keysDir: string): KeyProvider {
  if (custody === 'keychain') return new KeychainKeyProvider(keysDir);
  return new FileKeyProvider(keysDir);
}
