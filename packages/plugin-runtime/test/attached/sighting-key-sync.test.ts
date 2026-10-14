import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  clearSightingKeys,
  createSightingKeyStore,
  dataDir as dataDirOf,
  keysDir as keysDirOf,
  readSightingKeys,
  removeControlPlaneCredential,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as Remote from '@akasecurity/remote';
import type {
  AttachedCredentialAny,
  ControlPlaneConnection,
  SightingKeyResponse,
  StoredSightingKeys,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { endpointFingerprint } from '../../src/attached/history-sync.ts';
import {
  runSightingKeySync,
  SIGHTING_KEY_MAX_AGE_MS,
} from '../../src/attached/sighting-key-sync.ts';

const getSightingKey = vi.fn();

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ getSightingKey }),
}));

const NOW = 1_766_000_000_000;

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.example-org.internal',
  attachedAt: '2026-10-01T10:00:00.000Z',
};

const credential = (
  mode: 'machine' | 'scoped',
  endpoint = CONNECTION.endpoint,
): AttachedCredentialAny => {
  const common = {
    endpoint,
    apiKey: ['plugin', 'test', 'cred'].join('-'),
  };
  return mode === 'machine'
    ? { specVersion: 1, ...common }
    : { specVersion: 2, mode: 'scoped', ...common };
};

const material = (fill: number): string => Buffer.alloc(32, fill).toString('base64url');

const FETCHED: SightingKeyResponse = {
  keyVersion: 4,
  algorithm: 'hmac-sha256',
  key: material(4),
  previous: [{ keyVersion: 3, key: material(3) }],
};

const STORED = (fetchedAtMs: number): StoredSightingKeys => ({
  keyVersion: 2,
  algorithm: 'hmac-sha256',
  key: material(2),
  previous: [{ keyVersion: 1, key: material(1) }],
  fetchedAtMs,
  endpointFingerprint: endpointFingerprint(CONNECTION.endpoint),
});

let base: string;

const store = () => createSightingKeyStore('file', keysDirOf(base));

function attach(mode: 'machine' | 'scoped' = 'machine', connection = CONNECTION): void {
  applyOnboarding({ runMode: 'attached', controlPlane: connection }, base, null);
  writeControlPlaneCredential(settingsDirOf(base), credential(mode, connection.endpoint));
}

const OTHER: ControlPlaneConnection = {
  endpoint: 'https://aka.other-org.internal',
  attachedAt: '2026-10-02T10:00:00.000Z',
};

const run = (now = NOW) =>
  runSightingKeySync({ base, settingsDir: settingsDirOf(base), now: () => now });

beforeEach(() => {
  getSightingKey.mockReset();
  getSightingKey.mockResolvedValue(FETCHED);
  base = mkdtempSync(join(tmpdir(), 'aka-sighting-sync-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('runSightingKeySync', () => {
  it('fetches and stores the map when no key is stored', async () => {
    attach();

    await expect(run()).resolves.toBe('fetched');

    expect(getSightingKey).toHaveBeenCalledTimes(1);
    expect(store().read()).toEqual({
      ...FETCHED,
      fetchedAtMs: NOW,
      endpointFingerprint: endpointFingerprint(CONNECTION.endpoint),
    });
  });

  it('refetches a stored key older than a day, replacing it wholesale', async () => {
    attach();
    store().replace(STORED(NOW - SIGHTING_KEY_MAX_AGE_MS));

    await expect(run()).resolves.toBe('fetched');

    expect(getSightingKey).toHaveBeenCalledTimes(1);
    expect(store().read()).toEqual({
      ...FETCHED,
      fetchedAtMs: NOW,
      endpointFingerprint: endpointFingerprint(CONNECTION.endpoint),
    });
  });

  it('does not fetch while the stored key is younger than a day', async () => {
    attach();
    store().replace(STORED(NOW - SIGHTING_KEY_MAX_AGE_MS + 1));

    await expect(run()).resolves.toBe('fresh');

    expect(getSightingKey).not.toHaveBeenCalled();
    expect(store().read()).toEqual(STORED(NOW - SIGHTING_KEY_MAX_AGE_MS + 1));
  });

  it('counts a stored key as a day old at exactly twenty-four hours', async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    attach();
    store().replace(STORED(NOW - DAY_MS + 1));

    await expect(run()).resolves.toBe('fresh');
    expect(getSightingKey).not.toHaveBeenCalled();

    store().replace(STORED(NOW - DAY_MS));

    await expect(run()).resolves.toBe('fetched');
    expect(getSightingKey).toHaveBeenCalledTimes(1);
  });

  describe('a previous version past its overlap window', () => {
    const youngWith = (previous: StoredSightingKeys['previous']): StoredSightingKeys => ({
      ...STORED(NOW - 60_000),
      keyVersion: 5,
      key: material(5),
      previous,
    });
    const at = (ms: number) => new Date(ms).toISOString();

    it('refetches a young map once the soonest acceptedUntil has passed', async () => {
      attach();
      store().replace(
        youngWith([
          { keyVersion: 4, key: material(4), acceptedUntil: at(NOW + 3_600_000) },
          { keyVersion: 3, key: material(3), acceptedUntil: at(NOW) },
        ]),
      );

      await expect(run()).resolves.toBe('fetched');
      expect(getSightingKey).toHaveBeenCalledTimes(1);
      expect(store().read()?.keyVersion).toBe(FETCHED.keyVersion);
    });

    it('keeps a young map while every acceptedUntil is still ahead', async () => {
      attach();
      const stored = youngWith([{ keyVersion: 1, key: material(1), acceptedUntil: at(NOW + 1) }]);
      store().replace(stored);

      await expect(run()).resolves.toBe('fresh');
      expect(getSightingKey).not.toHaveBeenCalled();
      expect(store().read()).toEqual(stored);
    });

    it('keeps a young map whose previous versions carry no acceptedUntil', async () => {
      attach();
      store().replace(youngWith([{ keyVersion: 1, key: material(1) }]));

      await expect(run()).resolves.toBe('fresh');
      expect(getSightingKey).not.toHaveBeenCalled();
    });

    it('stores the window each fetched previous version carries', async () => {
      attach();
      const fetched = {
        ...FETCHED,
        previous: [{ keyVersion: 3, key: material(3), acceptedUntil: at(NOW + 86_400_000) }],
      };
      getSightingKey.mockResolvedValue(fetched);

      await expect(run()).resolves.toBe('fetched');
      expect(store().read()?.previous).toEqual(fetched.previous);
    });
  });

  it('refetches a key stamped in the future rather than trusting it indefinitely', async () => {
    attach();
    store().replace(STORED(NOW + 60_000));

    await expect(run()).resolves.toBe('fetched');
    expect(getSightingKey).toHaveBeenCalledTimes(1);
  });

  it('fetches on a scoped attachment too', async () => {
    attach('scoped');

    await expect(run()).resolves.toBe('fetched');
    expect(getSightingKey).toHaveBeenCalledTimes(1);
  });

  it('never fetches on a standalone machine', async () => {
    await expect(run()).resolves.toBeNull();
    expect(getSightingKey).not.toHaveBeenCalled();
    expect(store().read()).toBeUndefined();
  });

  it('never fetches in standalone run mode, even beside a descriptor and a credential', async () => {
    attach();
    applyOnboarding({ runMode: 'standalone' }, base, null);

    await expect(run()).resolves.toBeNull();
    expect(getSightingKey).not.toHaveBeenCalled();
  });

  it('never fetches when only the settings half of an attachment is present', async () => {
    applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base, null);

    await expect(run()).resolves.toBeNull();
    expect(getSightingKey).not.toHaveBeenCalled();
  });

  it('keeps the stored key and does not throw when the fetch fails', async () => {
    attach();
    store().replace(STORED(NOW - 2 * SIGHTING_KEY_MAX_AGE_MS));
    getSightingKey.mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(run()).resolves.toBe('failed');
    expect(store().read()).toEqual(STORED(NOW - 2 * SIGHTING_KEY_MAX_AGE_MS));
  });

  it('keeps the stored key when the answer is not a usable key map', async () => {
    attach();
    store().replace(STORED(NOW - 2 * SIGHTING_KEY_MAX_AGE_MS));
    getSightingKey.mockResolvedValue({ ...FETCHED, key: 'short' });

    await expect(run()).resolves.toBe('failed');
    expect(store().read()).toEqual(STORED(NOW - 2 * SIGHTING_KEY_MAX_AGE_MS));
  });

  it('does not throw when the custody cannot be written', async () => {
    attach();
    // A directory where the key file should be makes the replace fail.
    mkdirSync(join(keysDirOf(base), 'sighting.key'), { recursive: true });

    await expect(run()).resolves.toBe('failed');
  });

  it('refetches a fresh key that another endpoint issued', async () => {
    attach();
    store().replace({
      ...STORED(NOW - 1),
      endpointFingerprint: endpointFingerprint(OTHER.endpoint),
    });

    await expect(run()).resolves.toBe('fetched');
    expect(getSightingKey).toHaveBeenCalledTimes(1);
  });

  it('detached from one deployment and attached to another within the day, serves only the new key', async () => {
    attach();
    await run();
    expect(readSightingKeys(base)?.current.keyVersion).toBe(FETCHED.keyVersion);

    // A detach that left the stored map in place, then an attach elsewhere.
    applyOnboarding({ runMode: 'standalone', controlPlane: undefined }, base, null);
    removeControlPlaneCredential(settingsDirOf(base));
    expect(readSightingKeys(base)).toBeUndefined();
    attach('machine', OTHER);
    expect(readSightingKeys(base)).toBeUndefined();

    const fromOther: SightingKeyResponse = {
      keyVersion: 9,
      algorithm: 'hmac-sha256',
      key: material(9),
    };
    getSightingKey.mockResolvedValue(fromOther);
    await expect(run(NOW + 60_000)).resolves.toBe('fetched');

    expect(getSightingKey).toHaveBeenCalledTimes(2);
    expect(readSightingKeys(base)?.current.keyVersion).toBe(9);
    expect(store().read()?.endpointFingerprint).toBe(endpointFingerprint(OTHER.endpoint));
  });

  it('writes a map readSightingKeys accepts for the attached endpoint', async () => {
    attach();
    await run();
    clearSightingKeys(base);
    expect(readSightingKeys(base)).toBeUndefined();
    await run();
    expect(readSightingKeys(base)?.current.keyVersion).toBe(FETCHED.keyVersion);
  });
});
