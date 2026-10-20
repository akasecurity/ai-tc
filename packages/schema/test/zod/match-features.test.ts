import { describe, expect, it } from 'vitest';

import { KNOWN_PREFIXES, MatchFeatures } from '../../src/zod/match-features.ts';

const valid = {
  ruleId: 'secrets/generic-key',
  category: 'secret',
  validators: ['entropy'],
  corroborated: false,
  shape: { length: 40, classes: ['digit', 'lower'], knownPrefix: null, entropyBucket: 'high' },
  placeholder: false,
  pathClass: 'source',
  name: 'secret_like',
  nearby: ['test_like'],
};

describe('MatchFeatures', () => {
  it('accepts a feature set built only from its vocabulary', () => {
    expect(MatchFeatures.safeParse(valid).success).toBe(true);
    expect(
      MatchFeatures.safeParse({
        ...valid,
        shape: { ...valid.shape, knownPrefix: KNOWN_PREFIXES[0] },
      }).success,
    ).toBe(true);
  });

  it('rejects free text where only a fixed value may go', () => {
    const parse = (v: unknown) => MatchFeatures.safeParse(v).success;
    expect(parse({ ...valid, shape: { ...valid.shape, knownPrefix: 'abc123' } })).toBe(false);
    expect(parse({ ...valid, pathClass: 'src/billing' })).toBe(false);
    expect(parse({ ...valid, name: 'STRIPE_SECRET_KEY' })).toBe(false);
    expect(parse({ ...valid, nearby: ['password'] })).toBe(false);
  });

  it('rejects an unknown field, so nothing extra can ride along', () => {
    expect(MatchFeatures.safeParse({ ...valid, rawMatch: 'x' }).success).toBe(false);
    expect(
      MatchFeatures.safeParse({ ...valid, shape: { ...valid.shape, value: 'x' } }).success,
    ).toBe(false);
  });
});
