import { describe, expect, it } from 'vitest';

import {
  CaptureSighting,
  EventMetadata,
  SIGHTING_TOKEN_ANCHORED,
  sightingTokenScanner,
} from '../../src/zod/event.ts';
import { POINTER_TOKEN_ANCHORED, pointerTokenScanner } from '../../src/zod/vault.ts';

const FP = 'aZ09_-'.repeat(7) + 'Q';
const tokenOf = (version: string, fingerprint: string): string =>
  ['[[aka:fp:v', version, '.', fingerprint, ']]'].join('');
const pointer = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;

describe('sighting token grammar', () => {
  it('accepts a versioned 43-character base64url fingerprint', () => {
    expect(SIGHTING_TOKEN_ANCHORED.test(tokenOf('1', FP))).toBe(true);
    expect(SIGHTING_TOKEN_ANCHORED.test(tokenOf('120', FP))).toBe(true);
  });

  it('refuses a version of zero, a short fingerprint, or a padded one', () => {
    expect(SIGHTING_TOKEN_ANCHORED.test(tokenOf('0', FP))).toBe(false);
    expect(SIGHTING_TOKEN_ANCHORED.test(tokenOf('1', FP.slice(1)))).toBe(false);
    expect(SIGHTING_TOKEN_ANCHORED.test(tokenOf('1', `${FP.slice(1)}=`))).toBe(false);
  });

  it('never collides with the vault pointer grammar', () => {
    expect(POINTER_TOKEN_ANCHORED.test(tokenOf('1', FP))).toBe(false);
    expect(SIGHTING_TOKEN_ANCHORED.test(pointer)).toBe(false);
    const text = `${tokenOf('2', FP)} ${pointer}`;
    expect([...text.matchAll(pointerTokenScanner())].map((m) => m[0])).toEqual([pointer]);
    expect([...text.matchAll(sightingTokenScanner())].map((m) => m[0])).toEqual([tokenOf('2', FP)]);
  });
});

describe('capture sightings on the wire', () => {
  it('carries a token with its rule and category, optionally', () => {
    const sighting = { token: tokenOf('3', FP), ruleId: 'secrets/github-pat', category: 'secret' };
    expect(CaptureSighting.parse(sighting)).toEqual(sighting);
    expect(EventMetadata.parse({ sightings: [sighting] })).toEqual({ sightings: [sighting] });
    expect(EventMetadata.parse({})).toEqual({});
  });

  it('refuses an entry whose token is not a sighting token', () => {
    expect(
      CaptureSighting.safeParse({ token: pointer, ruleId: 'r', category: 'secret' }).success,
    ).toBe(false);
    expect(
      CaptureSighting.safeParse({ token: tokenOf('1', FP), ruleId: '', category: 'secret' })
        .success,
    ).toBe(false);
  });
});
