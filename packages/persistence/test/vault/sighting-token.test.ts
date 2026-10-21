import { createHmac } from 'node:crypto';

import { SIGHTING_TOKEN_ANCHORED } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { SightingKey } from '../../src/vault/sighting-keys.ts';
import { SIGHTING_DOMAIN, sightingToken, sightingTokens } from '../../src/vault/sighting-token.ts';

const keyOf = (keyVersion: number, seed: number): SightingKey => ({
  keyVersion,
  key: Uint8Array.from({ length: 32 }, (_, i) => (i * 31 + seed) % 256),
});

const value = ['tok', 'en', 'value', String(9 * 9), 'z'.repeat(9)].join('_');

function expectedToken(key: SightingKey, raw: string): string {
  const mac = createHmac('sha256', Buffer.from(key.key))
    .update(Buffer.concat([Buffer.from('aka:sighting:v1', 'utf8'), Buffer.from(raw, 'utf8')]))
    .digest();
  return `[[aka:fp:v${String(key.keyVersion)}.${mac.toString('base64url')}]]`;
}

describe('sightingToken', () => {
  it('is the HMAC of the domain and the value under the key, versioned', () => {
    const key = keyOf(3, 5);
    expect(SIGHTING_DOMAIN).toBe('aka:sighting:v1');
    expect(sightingToken(key, value)).toBe(expectedToken(key, value));
    expect(sightingToken(key, value)).toMatch(SIGHTING_TOKEN_ANCHORED);
  });

  it('strips invisible padding before hashing, and nothing else', () => {
    const key = keyOf(1, 9);
    const padded = `${value.slice(0, 4)}\u200B${value.slice(4)}\uFEFF`;
    expect(sightingToken(key, padded)).toBe(sightingToken(key, value));
    expect(sightingToken(key, ` ${value}`)).not.toBe(sightingToken(key, value));
  });

  it('differs under a different key, and under a different version', () => {
    expect(sightingToken(keyOf(1, 1), value)).not.toBe(sightingToken(keyOf(1, 2), value));
    const a = sightingToken(keyOf(1, 1), value);
    const b = sightingToken(keyOf(2, 1), value);
    expect(a.slice(a.indexOf('.'))).toBe(b.slice(b.indexOf('.')));
    expect(a).not.toBe(b);
  });

  it('carries at most SIGHTING_ALIASES_MAX aliases, whatever the keys hold', () => {
    const previous = [6, 5, 4, 3, 2].map((version) => keyOf(version, version));
    const { aliases } = sightingTokens({ current: keyOf(7, 9), previous }, value);
    expect(aliases).toEqual([6, 5, 4, 3].map((v) => expectedToken(keyOf(v, v), value)));
  });

  it('never contains the value', () => {
    expect(sightingToken(keyOf(1, 4), value)).not.toContain(value);
  });
});

describe('sightingTokens', () => {
  it('is the current-version token, with no aliases when no previous version is held', () => {
    const current = keyOf(5, 1);
    const tokens = sightingTokens({ current, previous: [] }, value);
    expect(tokens).toEqual({ token: expectedToken(current, value) });
    expect(tokens).not.toHaveProperty('aliases');
  });

  it('adds the token under each previous version, in the order the keys hold them', () => {
    const current = keyOf(5, 1);
    const newer = keyOf(4, 3);
    const older = keyOf(3, 2);
    expect(sightingTokens({ current, previous: [newer, older] }, value)).toEqual({
      token: expectedToken(current, value),
      aliases: [expectedToken(newer, value), expectedToken(older, value)],
    });
  });

  it('never contains the value', () => {
    const tokens = sightingTokens({ current: keyOf(2, 1), previous: [keyOf(1, 2)] }, value);
    expect(JSON.stringify(tokens)).not.toContain(value);
  });
});
