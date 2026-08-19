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

import {
  classifyOccupant,
  createOwnerOnlyFileSync,
  DATA_FILE_MODE,
  ensureDataDirSync,
  KeyUnclaimableError,
  type Occupant,
} from '../paths.ts';

// The keyring's wording for the three states classifyOccupant tells apart.
const VAULT_OCCUPANT_REASON: Record<Occupant['kind'], string> = {
  symlink: 'the path is a symlink; remove it so a keyring can be created',
  gone: 'the path was occupied but holds no keyring (removed while it was being created)',
  unknown: 'the path is occupied but cannot be inspected; check the permissions on its directory',
};

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
   * First mint: the keyring is CREATED, never replaced, so two processes racing
   * a fresh machine cannot each mint a different epoch 1 — with tmp + rename
   * the loser's replace would orphan everything the winner had already sealed.
   * The loser re-reads and adopts the winner's keyring; it minted nothing.
   *
   * `createOwnerOnlyFileSync` publishes by link rather than by an exclusive open
   * at the final path, so the keyring never exists at zero length: a reader —
   * including the loser, re-reading in order to adopt — sees the file absent or
   * whole, and never mistakes a live keyring for a corrupt one. A corrupt file
   * still throws from the parse and is never re-minted over.
   */
  #createExclusive(): Keyring {
    ensureDataDirSync(this.#keysDir);
    const keyring = mintKeyring();
    if (createOwnerOnlyFileSync(this.filePath, `${serializeKeyring(keyring)}\n`)) return keyring;

    const winner = this.#read();
    if (!winner) {
      // Same type, and for the same reason, as the fingerprint key's first mint:
      // a codeless error is read as "the file is corrupt, delete it", and the
      // blast radius here is larger — a discarded epoch does not orphan a grant,
      // it leaves ciphertext that nothing can ever open.
      const occupant = classifyOccupant(this.filePath);
      throw new KeyUnclaimableError(
        `vault: cannot create a key file at ${this.filePath} — ${VAULT_OCCUPANT_REASON[occupant.kind]}`,
        occupant.cause,
      );
    }
    tightenFileMode(this.filePath);
    return winner;
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

/**
 * Invokes the platform `security` binary with the given argv, returning stdout.
 * `stdin` feeds the child's standard input, which is how the write paths keep
 * key material off the command line — see {@link writeCommand}.
 */
export type SecurityExec = (args: string[], stdin?: string) => string;

/**
 * Ceiling on a single `security` call.
 *
 * A LOCKED keychain does not fail: `security` blocks on an unlock dialog —
 * measured, with no exit status and no stderr — and nothing on this thread can
 * interrupt it. The callers are a hook with its own harness deadline, a CLI
 * command and a dashboard action, so an unbounded wait is a wedged session
 * rather than a slow one, and on a hook it is a scan that never happens. The
 * bound is what turns "blocks for ever" into a loud, catchable failure.
 *
 * Well clear of an honest call, which is milliseconds against a local binary,
 * and inside the plugin harness's own 10s budget so the hook still gets to
 * fail rather than being killed mid-read.
 *
 * It bounds WRITES as well, which is not free: a write killed part-way can
 * leave a half-written item. That is the better end of the trade — a locked
 * keychain blocks writes exactly as it blocks reads, so an unbounded write
 * hangs just as hard — and the damage is contained, because a keyring that
 * will not parse is refused rather than minted over. Lowering this bound
 * raises the odds of that partial write; it is not a free dial to turn.
 */
const SECURITY_TIMEOUT_MS = 5_000;

const runSecurity: SecurityExec = (args, stdin) =>
  execFileSync('/usr/bin/security', args, {
    encoding: 'utf8',
    input: stdin,
    timeout: SECURITY_TIMEOUT_MS,
    // stderr is discarded rather than captured, and that is deliberate: a
    // captured stream rides out on an execFileSync error's `.stderr`, and the
    // write paths here carry the keyring. Exit status is the only thing any
    // branch below reads.
    stdio: [stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'ignore'],
  });

// `security find-generic-password` exit status for "no matching item exists"
// (errSecItemNotFound). Every other non-zero exit — a locked keychain, a
// denied ACL — is a failure, not absence.
const SECURITY_ITEM_NOT_FOUND = 44;

/**
 * Why a stored item would not parse, without quoting it.
 *
 * `parseKeyring`'s own refusals name a field and carry no value, so they pass
 * through. A `JSON.parse` SyntaxError is replaced rather than forwarded, for
 * two reasons — and NOT because it currently leaks. Measured on this Node, its
 * structural messages carry a position and no snippet ("Unterminated string in
 * JSON at position 67"), and the one form that does quote input quotes the
 * START, which for a keyring is always `{"current":…`. So:
 *
 * - a bare SyntaxError names neither the vault nor the backend, and reads as a
 *   fault in whatever called it rather than as a damaged keychain item;
 * - the quoting form is V8's choice, not this code's, and the input it would be
 *   handed is key material. Depending on where a future runtime decides to cut
 *   that window is not a bet worth taking for a message nobody needs.
 */
function corruptReason(err: unknown): string {
  if (err instanceof SyntaxError) return 'malformed JSON';
  return err instanceof Error ? err.message : 'unknown';
}

/**
 * Raw-free description of a `security` failure: exit metadata only.
 *
 * An `execFileSync` error's `.message` echoes the argv it was given, and its
 * `.stdout`/`.stderr` carry whatever the child produced. On the read path
 * stdout IS the keyring, so none of it may cross into a thrown message — nor
 * ride out as `cause`, which would re-attach the whole error object and
 * re-expose exactly what this strips.
 */
function securityFailureMeta(err: unknown): string {
  const e = err as { status?: number | null; signal?: string | null; code?: string };
  const parts: string[] = [];
  if (typeof e.status === 'number') parts.push(`exit ${String(e.status)}`);
  if (typeof e.signal === 'string' && e.signal) parts.push(`signal ${e.signal}`);
  if (typeof e.code === 'string' && e.code) parts.push(e.code);
  return parts.length > 0 ? parts.join(', ') : 'unknown error';
}

/**
 * Builds an `add-generic-password` line for `security -i`, which reads
 * COMMANDS on stdin.
 *
 * `add-generic-password` has no stdin option of its own: `-w`, `-p` and `-X`
 * all take their value on the command line, and a bare `-w` prompts on a
 * terminal. Interactive mode is therefore what keeps the keyring out of argv,
 * where a failed exec's `.message` would echo it.
 *
 * The keyring is hex-encoded and passed with `-X`, so the only payload token is
 * `[0-9a-f]` — no quoting question can arise from it however the interactive
 * tokenizer behaves. The keychain path is the one variable token and is
 * single-quoted; a path carrying a character the tokenizer would act on is
 * refused rather than escaped, since a mangled line writes the keyring to a
 * keychain other than the one named. The refused set is listed at the check
 * itself, because which characters those are is measured, not obvious.
 */
function writeCommand(keyring: Keyring, update: boolean, keychain?: string): string {
  const hex = Buffer.from(serializeKeyring(keyring), 'utf8').toString('hex');
  const parts = [
    'add-generic-password',
    ...(update ? ['-U'] : []),
    '-s',
    KEYCHAIN_SERVICE,
    '-a',
    KEYCHAIN_ACCOUNT,
    '-X',
    hex,
  ];
  if (keychain !== undefined) {
    // A BACKSLASH belongs in this set and reads as though it should not: the
    // interactive tokenizer treats it as an escape even inside single quotes,
    // so it is consumed rather than carried. Measured — a keychain at
    // `back\slash-….keychain` is reported by `security` as
    // `backslash-….keychain`, and the write misses the keychain it named.
    // That is the failure this refusal exists to prevent, not a variant of it.
    // NUL is here for the ordinary reason: it terminates the token.
    if (/['\\\n\r\0]/.test(keychain)) {
      throw new Error(
        'vault: keychain path contains a quote, backslash, line break or NUL, which security -i cannot carry intact',
      );
    }
    parts.push(`'${keychain}'`);
  }
  return `${parts.join(' ')}\n`;
}

/**
 * Opt-in OS-keychain custody: the same versioned keyring JSON held as one
 * generic-password item, so the key bytes are not sitting in a readable file.
 *
 * macOS only. The bytes move through the local `security` binary as a child
 * process — an OS service on this machine, not a network hop. Elsewhere the
 * constructor throws so the caller can fall back to file custody.
 *
 * **No secret is on the command line, on any path.** Writes cross on STDIN:
 * `#create` and `#replace` both run `security -i`, which reads commands on
 * stdin, and {@link writeCommand} hex-encodes the keyring into `-X` so nothing
 * about the payload can be re-tokenized. Putting it back in argv would put it
 * in an `execFileSync` error's `.message`, which echoes the argv it was given
 * — an error outlives the process and travels into logs and bug reports, which
 * a same-UID observer of a running exec does not.
 *
 * The read path's `-w` is not a counter-example, and it is worth naming because
 * the flag appears on both sides: on `find-generic-password` it is an OUTPUT
 * flag asking for the value on stdout, not a value being passed in.
 *
 * `test/vault/key-provider.test.ts`'s `keeps the keyring off argv on both write
 * paths` is what holds this.
 */
export class KeychainKeyProvider implements KeyProvider {
  readonly #keysDir: string;
  readonly #exec: SecurityExec;
  readonly #keychain: string | undefined;
  /**
   * The trailing keychain argument, or nothing. Every subcommand used here
   * takes it last (`add-generic-password [keychain]`,
   * `find-generic-password [keychain...]`), and omitting it means the default
   * search list. Fixed at construction, so it is built once rather than per
   * call on the capture path.
   */
  readonly #target: readonly string[];

  /**
   * `keychain` names the keychain to operate on, as `security`'s trailing
   * argument. Production passes nothing and gets the user's default keychain,
   * which is the whole point of the backend. A test driving the REAL binary
   * passes a throwaway one, because the alternative is writing vault key
   * material into the developer's own login keychain and leaving it there.
   */
  constructor(keysDir: string, exec: SecurityExec = runSecurity, keychain?: string) {
    // The platform guard applies only to the real binary; an injected exec
    // carries its own platform expectations.
    if (exec === runSecurity && process.platform !== 'darwin') {
      throw new Error(
        `keychain custody is not available on this platform (${process.platform}); use file custody`,
      );
    }
    this.#keysDir = keysDir;
    this.#exec = exec;
    this.#keychain = keychain;
    this.#target = keychain === undefined ? [] : [keychain];
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
        ...this.#target,
      ]);
    } catch (err) {
      // Only "no such item" may read as absence. A locked keychain or a
      // denied ACL also exits non-zero, and reading those as absence would
      // route into the mint path and orphan every existing ciphertext.
      if ((err as { status?: unknown }).status === SECURITY_ITEM_NOT_FOUND) return null;
      // Exit metadata only, and no `cause`: on this path the child's stdout is
      // the keyring itself, so the caught error is not something to carry along.
      // eslint-disable-next-line preserve-caught-error -- caught error's stdout is the keyring; see securityFailureMeta
      throw new Error(
        `vault: keychain read failed (${securityFailureMeta(err)}); refusing to treat the failure as an absent keyring`,
      );
    }
    const body = raw.trim();
    if (body.length === 0) return null;
    try {
      return parseKeyring(body);
    } catch (err) {
      // Refuses rather than returning null: a keyring that will not parse is
      // not an absent one, and minting over it orphans every ciphertext sealed
      // under whatever it held.
      // eslint-disable-next-line preserve-caught-error -- a JSON.parse error quotes the keyring; see corruptReason
      throw new Error(`vault: keychain item is not a usable keyring (${corruptReason(err)})`);
    }
  }

  /**
   * First mint: a plain `add-generic-password` (no `-U`) fails when an item
   * already exists, so a concurrent first mint cannot overwrite the winner's
   * keyring — the loser re-reads and adopts it instead.
   */
  #create(keyring: Keyring): Keyring {
    // Built OUTSIDE the try: its refusal is a caller/config fault, and the
    // catch below reads any throw as a lost mint race and re-reports it as a
    // write failure, which would bury the reason.
    const line = writeCommand(keyring, false, this.#keychain);
    try {
      this.#exec(['-i'], line);
    } catch (err) {
      const winner = this.#read();
      if (winner) return winner;
      // eslint-disable-next-line preserve-caught-error -- caught error may echo the write payload; see securityFailureMeta
      throw new Error(`vault: keychain write failed (${securityFailureMeta(err)})`);
    }
    return keyring;
  }

  // `-U` updates the item in place, deliberately replacing the stored map with
  // one that contains it — used only for rotation, under the rotation lock.
  #replace(keyring: Keyring): Keyring {
    const line = writeCommand(keyring, true, this.#keychain);
    try {
      this.#exec(['-i'], line);
    } catch (err) {
      // Exit metadata only: a rotation failure must not carry the payload it
      // was writing out to whatever logs it.
      // eslint-disable-next-line preserve-caught-error -- caught error may echo the write payload; see securityFailureMeta
      throw new Error(`vault: keychain write failed (${securityFailureMeta(err)})`);
    }
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
