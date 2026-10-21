// Custody of the sighting key: the versioned HMAC key map an attached machine
// is given by its deployment. Held under the same custody as the vault key
// (`vaultKeyCustody`) but as its own file or keychain item, never inside the
// vault keyring. A fetched map replaces the stored one wholesale, and records
// which endpoint issued it.
import { createHash } from 'node:crypto';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import { isAttached, SIGHTING_ALIASES_MAX, StoredSightingKeys } from '@akasecurity/schema';

import { defaultDataDir, keysDir } from '../local-layout.ts';
import { ensureDataDirSync, writeOwnerOnlyFileSync } from '../paths.ts';
import { readWorkspaceSettings } from '../settings.ts';
import type { KeychainItem, SecurityExec } from './key-provider.ts';
import {
  deleteKeychainItem,
  keychainWriteLine,
  readKeychainItem,
  runKeychainWrite,
  runSecurity,
} from './key-provider.ts';

export const SIGHTING_KEY_FILENAME = 'sighting.key';

const SIGHTING_ITEM: KeychainItem = {
  service: 'aka-sighting-key',
  account: 'keys',
  label: 'sighting key',
};

export interface SightingKey {
  keyVersion: number;
  key: Uint8Array;
}

export interface SightingKeys {
  current: SightingKey;
  /**
   * Versions still used during a rotation overlap, newest first and at most
   * SIGHTING_ALIASES_MAX; may be empty.
   */
  previous: SightingKey[];
}

/** The longest a previous version is used for, counted from when this machine first held it. */
export const SIGHTING_KEY_OVERLAP_MAX_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * When this machine first held `keyVersion` as a previous version: its
 * `previousFirstSeenAtMs` entry, or the map's fetch time for a map stored
 * without one.
 */
export function previousVersionFirstSeenAtMs(
  stored: Pick<StoredSightingKeys, 'fetchedAtMs' | 'previousFirstSeenAtMs'>,
  keyVersion: number,
): number {
  return stored.previousFirstSeenAtMs?.[String(keyVersion)] ?? stored.fetchedAtMs;
}

/**
 * The instant a previous version stops being used: its `acceptedUntil`, but no
 * later than SIGHTING_KEY_OVERLAP_MAX_MS after this machine first held it. NaN
 * when it has no `acceptedUntil` or one that does not parse.
 */
export function previousVersionUsableUntil(
  stored: Pick<StoredSightingKeys, 'fetchedAtMs' | 'previousFirstSeenAtMs'>,
  version: { keyVersion: number; acceptedUntil?: string | undefined },
): number {
  if (version.acceptedUntil === undefined) return Number.NaN;
  return Math.min(
    Date.parse(version.acceptedUntil),
    previousVersionFirstSeenAtMs(stored, version.keyVersion) + SIGHTING_KEY_OVERLAP_MAX_MS,
  );
}

export interface SightingKeyStore {
  /** The stored map, or undefined when none is stored. Unreadable or corrupt custody throws. */
  read(): StoredSightingKeys | undefined;
  /** Atomically replace the stored map with `keys`. */
  replace(keys: StoredSightingKeys): void;
  /** Remove the stored map. Removing an absent map is not an error. */
  remove(): void;
}

/** The fingerprint a stored map records for the endpoint that issued it: sha256 hex. */
export function sightingKeyEndpointFingerprint(endpoint: string): string {
  return createHash('sha256').update(endpoint).digest('hex');
}

/** Parse a stored payload. The refusal names neither the field values nor the payload. */
function parseStored(raw: string): StoredSightingKeys {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new Error('sighting key: stored map is not valid JSON');
  }
  const result = StoredSightingKeys.safeParse(json);
  if (!result.success) throw new Error('sighting key: stored map is not a usable key map');
  return result.data;
}

function validatedForWrite(keys: StoredSightingKeys): StoredSightingKeys {
  const result = StoredSightingKeys.safeParse(keys);
  if (!result.success) {
    throw new Error('sighting key: refusing to store a map that is not a usable key map');
  }
  return result.data;
}

const serialize = (keys: StoredSightingKeys): string => `${JSON.stringify(keys)}\n`;

class FileSightingKeyStore implements SightingKeyStore {
  readonly #keysDir: string;

  constructor(keysDirectory: string) {
    this.#keysDir = keysDirectory;
  }

  get #path(): string {
    return join(this.#keysDir, SIGHTING_KEY_FILENAME);
  }

  read(): StoredSightingKeys | undefined {
    let raw: string;
    try {
      raw = readFileSync(this.#path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw err instanceof Error ? err : new Error(String(err));
    }
    return parseStored(raw);
  }

  replace(keys: StoredSightingKeys): void {
    const validated = validatedForWrite(keys);
    ensureDataDirSync(this.#keysDir);
    writeOwnerOnlyFileSync(this.#path, serialize(validated));
  }

  remove(): void {
    rmSync(this.#path, { force: true });
  }
}

class KeychainSightingKeyStore implements SightingKeyStore {
  readonly #exec: SecurityExec;

  constructor(exec: SecurityExec) {
    if (exec === runSecurity && process.platform !== 'darwin') {
      throw new Error(
        `keychain custody is not available on this platform (${process.platform}); use file custody`,
      );
    }
    this.#exec = exec;
  }

  read(): StoredSightingKeys | undefined {
    const raw = readKeychainItem(this.#exec, SIGHTING_ITEM, []);
    if (raw === null) return undefined;
    const body = raw.trim();
    return body.length === 0 ? undefined : parseStored(body);
  }

  replace(keys: StoredSightingKeys): void {
    const validated = validatedForWrite(keys);
    runKeychainWrite(
      this.#exec,
      SIGHTING_ITEM,
      keychainWriteLine(SIGHTING_ITEM, serialize(validated), true),
    );
  }

  remove(): void {
    deleteKeychainItem(this.#exec, SIGHTING_ITEM, []);
  }
}

/**
 * The store for a configured custody setting: the keychain item for
 * `keychain`, otherwise `<keysDir>/sighting.key`. `exec` replaces the
 * platform `security` binary.
 */
export function createSightingKeyStore(
  custody: string,
  keysDirectory: string,
  exec: SecurityExec = runSecurity,
): SightingKeyStore {
  if (custody === 'keychain') return new KeychainSightingKeyStore(exec);
  return new FileSightingKeyStore(keysDirectory);
}

/**
 * The stored map in the form a consumer uses: versions and raw key bytes, with
 * only the previous versions still accepted at `nowMs`.
 */
export function sightingKeysOf(stored: StoredSightingKeys, nowMs: number): SightingKeys {
  const bytes = (key: string): Uint8Array => new Uint8Array(Buffer.from(key, 'base64url'));
  return {
    current: { keyVersion: stored.keyVersion, key: bytes(stored.key) },
    previous: (stored.previous ?? [])
      .filter((p) => nowMs < previousVersionUsableUntil(stored, p))
      .sort((a, b) => b.keyVersion - a.keyVersion)
      .slice(0, SIGHTING_ALIASES_MAX)
      .map((p) => ({ keyVersion: p.keyVersion, key: bytes(p.key) })),
  };
}

/**
 * The sighting keys this machine holds for the deployment it is attached to.
 * Undefined when the machine is not attached, holds no map, holds a map issued
 * by another endpoint, or its custody cannot be read. Custody follows
 * `vaultKeyCustody`.
 */
export function readSightingKeys(
  base: string = defaultDataDir(),
  deps: { exec?: SecurityExec; now?: () => number } = {},
): SightingKeys | undefined {
  try {
    const settings = readWorkspaceSettings(base);
    const endpoint = isAttached(settings) ? settings.controlPlane?.endpoint : undefined;
    if (endpoint === undefined) return undefined;
    const stored = createSightingKeyStore(
      settings.vaultKeyCustody,
      keysDir(base),
      deps.exec,
    ).read();
    if (stored === undefined) return undefined;
    if (stored.endpointFingerprint !== sightingKeyEndpointFingerprint(endpoint)) return undefined;
    return sightingKeysOf(stored, (deps.now ?? Date.now)());
  } catch {
    return undefined;
  }
}

/**
 * Remove the stored sighting key on detach: the file always, and the keychain
 * item when custody is `keychain`. Best-effort; never throws.
 */
export function clearSightingKeys(
  base: string = defaultDataDir(),
  deps: { exec?: SecurityExec } = {},
): void {
  try {
    createSightingKeyStore('file', keysDir(base)).remove();
  } catch {
    // A leftover file is not worth failing a completed detach over.
  }
  try {
    if (readWorkspaceSettings(base).vaultKeyCustody === 'keychain') {
      createSightingKeyStore('keychain', keysDir(base), deps.exec).remove();
    }
  } catch {
    // Same: the detach has already happened.
  }
}
