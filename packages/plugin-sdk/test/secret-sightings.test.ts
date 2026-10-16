import type { MatchResult } from '@akasecurity/detections';
import { sightingToken } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import { secretSightingsOf } from '../src/secret-sightings.ts';

const KEY = { keyVersion: 2, key: new Uint8Array(32).fill(7) };
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
      KEY,
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
});
