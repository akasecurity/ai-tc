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
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
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

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

// ─── Rotation lock ───────────────────────────────────────────────────────────

const ROTATION_LOCK_STALE_MS = 60_000;

// Names the holder, so release can tell "still mine" from "reclaimed by someone
// else while I was working" and decline to remove a lock it no longer owns.
const LOCK_OWNER_FILE = 'owner';

const ROTATION_IN_PROGRESS = 'vault: a key rotation is already in progress';

interface RotationLease {
  lock: string;
  owner: string;
}

// Create the lock directory and stamp it with this holder's token. False means
// someone else already holds it. A failed stamp gives the directory back rather
// than leaving behind a lock nobody can prove ownership of — and so release.
function claimRotationLock(lock: string, owner: string): boolean {
  try {
    mkdirSync(lock);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw asError(err);
  }
  try {
    writeFileSync(join(lock, LOCK_OWNER_FILE), `${owner}\n`, { mode: DATA_FILE_MODE });
    return true;
  } catch (err) {
    rmSync(lock, { recursive: true, force: true });
    throw asError(err);
  }
}

/**
 * Advisory lock guarding rotation: `mkdirSync` is atomic, so whichever process
 * creates the lock directory owns the rotation, and a concurrent caller fails
 * loudly instead of both minting a different next epoch. Rotation is a rare,
 * user-initiated operation — surfacing contention as an error is correct.
 * A lock left by a crashed process is reclaimed once it is older than the
 * stale window.
 */
function acquireRotationLock(keysDir: string): RotationLease {
  const lock = join(keysDir, `${VAULT_KEY_FILENAME}.lock`);
  const owner = randomBytes(16).toString('hex');
  if (claimRotationLock(lock, owner)) return { lock, owner };

  let held: ReturnType<typeof statSync>;
  try {
    held = statSync(lock);
  } catch {
    // The lock vanished between the failed create and the stat: the other
    // rotation just finished. The contention was still real; the caller retries.
    throw new Error(ROTATION_IN_PROGRESS);
  }
  if (Date.now() - held.mtimeMs < ROTATION_LOCK_STALE_MS) throw new Error(ROTATION_IN_PROGRESS);

  // Reclaim by MOVING the stale directory aside, never by deleting it in place.
  // Delete-then-recreate is check-then-act: two processes that both judge one
  // lock stale both delete and both create, and both believe they hold it. That
  // needs no slow rotation to reach — a stale lock stays stale until somebody
  // takes it, so any two attempts after a crash collide. A rename can only
  // succeed for one of them.
  //
  // Identity is re-checked first, so a lock a third process legitimately took
  // over since the staleness read is left alone instead of displaced. Identity
  // is (inode, mtime) and NOT the inode alone: a filesystem is free to hand a
  // freshly created directory the inode number it just reclaimed from a deleted
  // one, so an inode match does not prove it is the same directory. A
  // replacement lock is stamped at creation time and cannot also carry the old
  // one's backdated mtime, which is what makes the pair conclusive.
  const aside = `${lock}.stale.${owner}`;
  try {
    const now = statSync(lock);
    if (now.ino !== held.ino || now.mtimeMs !== held.mtimeMs) {
      throw new Error(ROTATION_IN_PROGRESS);
    }
    renameSync(lock, aside);
  } catch (err) {
    if (err instanceof Error && err.message === ROTATION_IN_PROGRESS) throw err;
    throw new Error(ROTATION_IN_PROGRESS, { cause: err });
  }
  rmSync(aside, { recursive: true, force: true });
  if (!claimRotationLock(lock, owner)) throw new Error(ROTATION_IN_PROGRESS);
  return { lock, owner };
}

// Release only what this holder still owns. A lock reclaimed as stale while its
// holder was still alive belongs to the reclaimer, and deleting it on the way
// out would unlock the reclaimer and let a third caller walk in beside it.
function releaseRotationLock(lease: RotationLease): void {
  try {
    if (readFileSync(join(lease.lock, LOCK_OWNER_FILE), 'utf8').trim() !== lease.owner) return;
  } catch {
    return;
  }
  rmSync(lease.lock, { recursive: true, force: true });
}

function withRotationLock<T>(keysDir: string, work: () => T): T {
  ensureDataDirSync(keysDir);
  const lease = acquireRotationLock(keysDir);
  try {
    return work();
  } finally {
    releaseRotationLock(lease);
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
      if (!existing) return currentOf(this.#createExclusive());
      // Re-tighten on every load, covering a file created before the mode was
      // enforced at write time.
      tightenFileMode(this.filePath);
      return currentOf(existing);
    });
  }

  rotate(): Promise<VaultKeyMaterial> {
    return asAsync(() =>
      withRotationLock(this.#keysDir, () => {
        const existing = this.#read();
        // With no keyring yet there is nothing to rotate away from: the first
        // epoch is minted instead, so rotation on a fresh machine is not a no-op.
        if (!existing) return currentOf(this.#createExclusive());
        return currentOf(this.#write(withNextEpoch(existing)));
      }),
    );
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

  /**
   * First mint: the keyring is created at its FINAL path with a
   * creation-exclusive write, so two processes racing a fresh machine cannot
   * each mint a different epoch 1 — with tmp + rename the loser's replace
   * would orphan everything the winner had already sealed. On EEXIST the
   * loser re-reads and adopts the winner's keyring; it minted nothing.
   * Atomic replace is unnecessary here: nothing can be mid-read of a file
   * that did not exist, and a torn exclusive write parses as corrupt on the
   * next read and fails secure rather than being re-minted over.
   */
  #createExclusive(): Keyring {
    ensureDataDirSync(this.#keysDir);
    const keyring = mintKeyring();
    try {
      writeFileSync(this.filePath, `${serializeKeyring(keyring)}\n`, {
        flag: 'wx',
        mode: DATA_FILE_MODE,
      });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw asError(err);
      const winner = this.#read();
      if (!winner) {
        throw new Error('vault: key file vanished during first mint', { cause: err });
      }
      return winner;
    }
    tightenFileMode(this.filePath);
    return keyring;
  }

  /**
   * Atomic tmp + rename so a crash mid-write cannot truncate the keyring.
   * Used only for rotation, under the rotation lock — first creation goes
   * through the creation-exclusive path instead.
   */
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

/** Invokes the platform `security` binary with the given argv, returning stdout. */
export type SecurityExec = (args: string[]) => string;

const runSecurity: SecurityExec = (args) =>
  execFileSync('/usr/bin/security', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });

// `security find-generic-password` exit status for "no matching item exists"
// (errSecItemNotFound). Every other non-zero exit — a locked keychain, a
// denied ACL — is a failure, not absence.
const SECURITY_ITEM_NOT_FOUND = 44;

/**
 * Opt-in OS-keychain custody: the same versioned keyring JSON held as one
 * generic-password item, so the key bytes are not sitting in a readable file.
 *
 * macOS only. The bytes move through the local `security` binary as a child
 * process — an OS service on this machine, not a network hop. Elsewhere the
 * constructor throws so the caller can fall back to file custody.
 *
 * On writes the keyring JSON rides in the child's argv (`-w <json>`), which is
 * observable by same-UID processes for the duration of the exec. That is an
 * accepted exposure under the local threat model: a same-UID process can
 * already read the keychain item itself.
 */
export class KeychainKeyProvider implements KeyProvider {
  readonly #keysDir: string;
  readonly #exec: SecurityExec;

  constructor(keysDir: string, exec: SecurityExec = runSecurity) {
    // The platform guard applies only to the real binary; an injected exec
    // carries its own platform expectations.
    if (exec === runSecurity && process.platform !== 'darwin') {
      throw new Error(
        `keychain custody is not available on this platform (${process.platform}); use file custody`,
      );
    }
    this.#keysDir = keysDir;
    this.#exec = exec;
  }

  /** Where a fallback file provider for the same vault would keep its keyring. */
  get keysDir(): string {
    return this.#keysDir;
  }

  loadOrCreate(): Promise<VaultKeyMaterial> {
    return asAsync(() => {
      const existing = this.#read();
      if (existing) return currentOf(existing);
      return currentOf(this.#create(mintKeyring()));
    });
  }

  rotate(): Promise<VaultKeyMaterial> {
    return asAsync(() =>
      withRotationLock(this.#keysDir, () => {
        const existing = this.#read();
        // With no keyring yet there is nothing to rotate away from: the first
        // epoch is minted instead, so rotation on a fresh machine is not a no-op.
        if (!existing) return currentOf(this.#create(mintKeyring()));
        return currentOf(this.#replace(withNextEpoch(existing)));
      }),
    );
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
      raw = this.#exec([
        'find-generic-password',
        '-s',
        KEYCHAIN_SERVICE,
        '-a',
        KEYCHAIN_ACCOUNT,
        '-w',
      ]);
    } catch (err) {
      // Only "no such item" may read as absence. A locked keychain or a
      // denied ACL also exits non-zero, and reading those as absence would
      // route into the mint path and orphan every existing ciphertext.
      if ((err as { status?: unknown }).status === SECURITY_ITEM_NOT_FOUND) return null;
      throw new Error(
        `vault: keychain read failed (${err instanceof Error ? err.message : String(err)}); refusing to treat the failure as an absent keyring`,
        { cause: err },
      );
    }
    const body = raw.trim();
    if (body.length === 0) return null;
    return parseKeyring(body);
  }

  /**
   * First mint: a plain `add-generic-password` (no `-U`) fails when an item
   * already exists, so a concurrent first mint cannot overwrite the winner's
   * keyring — the loser re-reads and adopts it instead.
   */
  #create(keyring: Keyring): Keyring {
    const args = [
      'add-generic-password',
      '-s',
      KEYCHAIN_SERVICE,
      '-a',
      KEYCHAIN_ACCOUNT,
      '-w',
      serializeKeyring(keyring),
    ];
    try {
      this.#exec(args);
    } catch (err) {
      const winner = this.#read();
      if (winner) return winner;
      throw asError(err);
    }
    return keyring;
  }

  // `-U` updates the item in place, deliberately replacing the stored map with
  // one that contains it — used only for rotation, under the rotation lock.
  #replace(keyring: Keyring): Keyring {
    this.#exec([
      'add-generic-password',
      '-U',
      '-s',
      KEYCHAIN_SERVICE,
      '-a',
      KEYCHAIN_ACCOUNT,
      '-w',
      serializeKeyring(keyring),
    ]);
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
