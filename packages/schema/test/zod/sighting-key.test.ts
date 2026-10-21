import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  SIGHTING_KEY_BYTES,
  SightingKeyResponse,
  StoredSightingKeys,
} from '../../src/zod/control-plane.ts';

const material = (fill: number, bytes = SIGHTING_KEY_BYTES): string =>
  Buffer.alloc(bytes, fill).toString('base64url');

const body = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  keyVersion: 2,
  algorithm: 'hmac-sha256',
  key: material(7),
  previous: [{ keyVersion: 1, key: material(3) }],
  ...overrides,
});

describe('SightingKeyResponse', () => {
  it('parses a current key with one previous version', () => {
    const parsed = SightingKeyResponse.parse(body());
    expect(parsed.keyVersion).toBe(2);
    expect(Buffer.from(parsed.key, 'base64url')).toHaveLength(32);
    expect(parsed.previous).toEqual([{ keyVersion: 1, key: material(3) }]);
  });

  it('accepts an absent or empty previous list', () => {
    const withoutPrevious = body();
    delete withoutPrevious.previous;
    expect(SightingKeyResponse.parse(withoutPrevious).previous).toBeUndefined();
    expect(SightingKeyResponse.parse(body({ previous: [] })).previous).toEqual([]);
  });

  it('accepts every 32-byte value, whatever its final character', () => {
    for (const fill of [0, 1, 2, 3, 0x0f, 0x3f, 0xff]) {
      expect(SightingKeyResponse.safeParse(body({ key: material(fill) })).success).toBe(true);
    }
  });

  it.each([
    ['31 bytes', material(7, 31)],
    ['33 bytes', material(7, 33)],
    ['64 bytes', material(7, 64)],
    ['empty', ''],
  ])('refuses key material of the wrong length (%s)', (_label, key) => {
    expect(SightingKeyResponse.safeParse(body({ key })).success).toBe(false);
  });

  it('refuses a value that is not base64url', () => {
    const standard = Buffer.alloc(32, 0xfb).toString('base64');
    expect(standard).toMatch(/[+/]/);
    expect(SightingKeyResponse.safeParse(body({ key: standard })).success).toBe(false);
    expect(SightingKeyResponse.safeParse(body({ key: `${material(7)}=` })).success).toBe(false);
    expect(
      SightingKeyResponse.safeParse(body({ key: `${material(7).slice(0, 42)}!` })).success,
    ).toBe(false);
  });

  it('refuses a 43-character value that does not decode to exactly 32 bytes', () => {
    // The final character of a canonical 32-byte encoding carries 4 data bits;
    // one with any of the low 2 bits set is not the encoding of 32 bytes.
    const nonCanonical = `${material(0).slice(0, 42)}B`;
    expect(SightingKeyResponse.safeParse(body({ key: nonCanonical })).success).toBe(false);
  });

  it.each([0, -1, 1.5])('refuses key version %s', (keyVersion) => {
    expect(SightingKeyResponse.safeParse(body({ keyVersion })).success).toBe(false);
    expect(
      SightingKeyResponse.safeParse(body({ previous: [{ keyVersion, key: material(3) }] })).success,
    ).toBe(false);
  });

  it('refuses a bad key among the previous versions', () => {
    const previous = [{ keyVersion: 1, key: material(3, 16) }];
    expect(SightingKeyResponse.safeParse(body({ previous })).success).toBe(false);
  });

  it('refuses an algorithm it does not implement', () => {
    expect(SightingKeyResponse.safeParse(body({ algorithm: 'hmac-sha512' })).success).toBe(false);
  });

  it('refuses a previous version that repeats the current one or another previous one', () => {
    expect(
      SightingKeyResponse.safeParse(body({ previous: [{ keyVersion: 2, key: material(3) }] }))
        .success,
    ).toBe(false);
    expect(
      SightingKeyResponse.safeParse(
        body({
          previous: [
            { keyVersion: 1, key: material(3) },
            { keyVersion: 1, key: material(4) },
          ],
        }),
      ).success,
    ).toBe(false);
  });

  it('strips unknown keys, like every response parser, instead of failing on a newer deployment', () => {
    const parsed = SightingKeyResponse.parse(
      body({
        rotatesAt: '2026-11-01T00:00:00.000Z',
        previous: [{ keyVersion: 1, key: material(3), note: 'x' }],
      }),
    );
    expect(parsed).not.toHaveProperty('rotatesAt');
    expect(parsed.previous?.[0]).not.toHaveProperty('note');
  });

  it('does not quote the key material back in a refusal', () => {
    const key = material(9, 31);
    const result = SightingKeyResponse.safeParse(body({ key }));
    expect(result.success).toBe(false);
    expect(JSON.stringify(result.error?.issues)).not.toContain(key);
  });

  it('registers no component id, like the other response parsers', () => {
    expect(z.globalRegistry.get(SightingKeyResponse)).toBeUndefined();
    expect(z.globalRegistry.get(StoredSightingKeys)).toBeUndefined();
  });
});

describe('StoredSightingKeys', () => {
  const FINGERPRINT = 'a'.repeat(64);
  const stored = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    ...body(),
    fetchedAtMs: 1_766_000_000_000,
    endpointFingerprint: FINGERPRINT,
    ...overrides,
  });

  it('is the response plus the fetch instant and the issuing endpoint', () => {
    const parsed = StoredSightingKeys.parse(stored());
    expect(parsed.fetchedAtMs).toBe(1_766_000_000_000);
    expect(parsed.endpointFingerprint).toBe(FINGERPRINT);
    expect(parsed.keyVersion).toBe(2);
  });

  it('requires the fetch instant', () => {
    const withoutInstant = stored();
    delete withoutInstant.fetchedAtMs;
    expect(StoredSightingKeys.safeParse(withoutInstant).success).toBe(false);
    expect(StoredSightingKeys.safeParse(stored({ fetchedAtMs: -1 })).success).toBe(false);
  });

  it('requires a sha256 hex endpoint fingerprint', () => {
    const withoutFingerprint = stored();
    delete withoutFingerprint.endpointFingerprint;
    expect(StoredSightingKeys.safeParse(withoutFingerprint).success).toBe(false);
    expect(
      StoredSightingKeys.safeParse(stored({ endpointFingerprint: 'a'.repeat(63) })).success,
    ).toBe(false);
    expect(
      StoredSightingKeys.safeParse(stored({ endpointFingerprint: 'https://aka.example.test' }))
        .success,
    ).toBe(false);
  });
});

describe('previous versions and their overlap window', () => {
  const until = '2026-10-21T09:00:00.000Z';

  it('keeps the instant each previous version stops being accepted', () => {
    const parsed = SightingKeyResponse.parse(
      body({ previous: [{ keyVersion: 1, key: material(3), acceptedUntil: until }] }),
    );
    expect(parsed.previous).toEqual([{ keyVersion: 1, key: material(3), acceptedUntil: until }]);
  });

  it('accepts a previous version without one, from a deployment that does not send it', () => {
    expect(SightingKeyResponse.parse(body()).previous?.[0]).not.toHaveProperty('acceptedUntil');
  });

  it('keeps an instant with a numeric UTC offset', () => {
    for (const acceptedUntil of ['2026-10-21T09:00:00+00:00', '2026-10-21T09:00:00+05:30']) {
      const parsed = SightingKeyResponse.parse(
        body({ previous: [{ keyVersion: 1, key: material(3), acceptedUntil }] }),
      );
      expect(parsed.previous?.[0]?.acceptedUntil).toBe(acceptedUntil);
    }
  });

  it('drops an instant that is not an ISO datetime and keeps the rest of the map', () => {
    for (const acceptedUntil of ['tomorrow', '2026-10-21', 1_766_000_000_000]) {
      const parsed = SightingKeyResponse.parse(
        body({ previous: [{ keyVersion: 1, key: material(3), acceptedUntil }] }),
      );
      expect(parsed.keyVersion).toBe(2);
      expect(parsed.previous?.[0]?.keyVersion).toBe(1);
      expect(parsed.previous?.[0]?.acceptedUntil).toBeUndefined();
    }
  });

  it('stores when the machine first held each previous version, keyed by its number', () => {
    const map = {
      ...body({ previous: [{ keyVersion: 1, key: material(3), acceptedUntil: until }] }),
      fetchedAtMs: 1,
      endpointFingerprint: 'a'.repeat(64),
    };
    expect(StoredSightingKeys.parse({ ...map, previousFirstSeenAtMs: { '1': 5 } })).toMatchObject({
      previousFirstSeenAtMs: { '1': 5 },
    });
    expect(StoredSightingKeys.safeParse({ ...map, previousFirstSeenAtMs: { v1: 5 } }).success).toBe(
      false,
    );
    expect(
      StoredSightingKeys.safeParse({ ...map, previousFirstSeenAtMs: { '1': -1 } }).success,
    ).toBe(false);
  });

  it('takes no first-seen instant from the deployment', () => {
    const parsed = SightingKeyResponse.parse({ ...body(), previousFirstSeenAtMs: { '1': 5 } });
    expect(parsed).not.toHaveProperty('previousFirstSeenAtMs');
  });

  it('stores the instant with the map', () => {
    const stored = StoredSightingKeys.parse({
      ...body({ previous: [{ keyVersion: 1, key: material(3), acceptedUntil: until }] }),
      fetchedAtMs: 1,
      endpointFingerprint: 'a'.repeat(64),
    });
    expect(stored.previous?.[0]?.acceptedUntil).toBe(until);
  });
});
