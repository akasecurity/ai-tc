import { describe, expect, it } from 'vitest';

import { Namespace, PackId, SemVer } from '../../src/zod/registry.ts';

describe('pack-coordinate primitives', () => {
  it('Namespace accepts kebab-case handles and rejects others', () => {
    expect(Namespace.safeParse('aka').success).toBe(true);
    expect(Namespace.safeParse('Aka_Labs').success).toBe(false);
    expect(Namespace.safeParse('1labs').success).toBe(false);
  });

  it('PackId accepts kebab-case identifiers and rejects others', () => {
    expect(PackId.safeParse('core-pii').success).toBe(true);
    expect(PackId.safeParse('Core PII').success).toBe(false);
  });

  it('SemVer accepts major.minor.patch (+prerelease) and rejects loose strings', () => {
    expect(SemVer.safeParse('1.0.0').success).toBe(true);
    expect(SemVer.safeParse('2.3.4-rc.1').success).toBe(true);
    expect(SemVer.safeParse('1.0').success).toBe(false);
    expect(SemVer.safeParse('latest').success).toBe(false);
  });
});
