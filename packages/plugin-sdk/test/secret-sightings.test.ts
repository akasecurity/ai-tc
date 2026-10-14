import type { MatchResult } from '@akasecurity/detections';
import { sightingToken } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import { secretSightingsOf } from '../src/secret-sightings.ts';

const KEY = { keyVersion: 2, key: new Uint8Array(32).fill(7) };
const PREVIOUS = { keyVersion: 1, key: new Uint8Array(32).fill(3) };
const KEYS = { current: KEY, previous: [] };
// Assembled at runtime so no key-shaped literal sits in this file.
const VALUE = ['AK', 'IA'].join('') + ['Q7RT', '2MXP', '9KZB', '4HWN'].join('');

function match(overrides: Partial<MatchResult>): MatchResult {
  return {
    ruleId: 'secrets/aws-access-key-id',
    category: 'secret',
    span: { start: 10, end: 30 },
    rawMatch: VALUE,
    ...overrides,
  } as MatchResult;
}

describe('secretSightingsOf', () => {
  it('gives each secret one token, shared by its sighting and its span', () => {
    const found = secretSightingsOf(
      KEYS,
      [match({ variableName: 'AWS_ACCESS_KEY_ID' }), match({ category: 'pii', rawMatch: 'x' })],
      '/repo/deploy.ts',
      'github.com/acme/widgets',
    );

    const token = sightingToken(KEY, VALUE);
    expect(found.sightings).toEqual([
      {
        token,
        ruleId: 'secrets/aws-access-key-id',
        variableName: 'AWS_ACCESS_KEY_ID',
        file: '/repo/deploy.ts',
        scopeKey: 'github.com/acme/widgets',
      },
    ]);
    expect(found.spans).toEqual([
      { start: 10, end: 30, ruleId: 'secrets/aws-access-key-id', token },
    ]);
  });

  it('carries the previous-version token of a value as an alias on its sighting and its span', () => {
    const found = secretSightingsOf(
      { current: KEY, previous: [PREVIOUS] },
      [match({})],
      '/repo/a.ts',
    );

    const aliases = [sightingToken(PREVIOUS, VALUE)];
    expect(found.sightings[0]).toMatchObject({ token: sightingToken(KEY, VALUE), aliases });
    expect(found.spans[0]).toMatchObject({ token: sightingToken(KEY, VALUE), aliases });
  });
});
