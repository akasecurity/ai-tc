import { describe, expect, it } from 'vitest';

import { computeFindingKey } from '../src/finding-key.ts';

// LOCKSTEP KNOWN-ANSWER VECTOR — the same literal input and digest are pinned
// so that any independently replicated computeFindingKey MUST produce
// byte-identical output. If two implementations diverge, a finding_key minted
// by one side never reconciles with the other; this pinned digest turns silent
// drift into a test failure. Never update this vector without updating every
// replica in lockstep.
const FINDING_KEY_LOCKSTEP_VECTOR = {
  input: {
    ruleId: 'secrets/aws-access-key-id',
    filePath: '/repo/src/config.ts',
    valueFingerprint: 'A******Z',
  },
  digest: 'c40ff85511682e39f27e4a206af8366b80d535a064e6bca8c986200813c23d1a',
} as const;

describe('computeFindingKey', () => {
  it('matches the cross-package lockstep known-answer vector', () => {
    expect(computeFindingKey(FINDING_KEY_LOCKSTEP_VECTOR.input)).toBe(
      FINDING_KEY_LOCKSTEP_VECTOR.digest,
    );
  });

  it('is deterministic for the same (ruleId, filePath, valueFingerprint)', () => {
    const input = { ruleId: 'aws-key', filePath: '/repo/src/a.ts', valueFingerprint: 'fp-1' };
    expect(computeFindingKey(input)).toBe(computeFindingKey({ ...input }));
  });

  it('is a sha256 hex digest', () => {
    const key = computeFindingKey({
      ruleId: 'aws-key',
      filePath: '/repo/src/a.ts',
      valueFingerprint: 'fp-1',
    });
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('differs when the ruleId differs', () => {
    const base = { filePath: '/repo/src/a.ts', valueFingerprint: 'fp-1' };
    expect(computeFindingKey({ ruleId: 'aws-key', ...base })).not.toBe(
      computeFindingKey({ ruleId: 'gcp-key', ...base }),
    );
  });

  it('differs when the file path differs', () => {
    const base = { ruleId: 'aws-key', valueFingerprint: 'fp-1' };
    expect(computeFindingKey({ ...base, filePath: '/repo/src/a.ts' })).not.toBe(
      computeFindingKey({ ...base, filePath: '/repo/src/b.ts' }),
    );
  });

  it('differs when the value fingerprint differs — two distinct secrets in one file stay distinct', () => {
    const base = { ruleId: 'aws-key', filePath: '/repo/src/a.ts' };
    expect(computeFindingKey({ ...base, valueFingerprint: 'fp-1' })).not.toBe(
      computeFindingKey({ ...base, valueFingerprint: 'fp-2' }),
    );
  });

  it('normalizes backslash path separators so a key stays stable across separator styles', () => {
    const a = computeFindingKey({
      ruleId: 'aws-key',
      filePath: 'repo/src/a.ts',
      valueFingerprint: 'fp-1',
    });
    const b = computeFindingKey({
      ruleId: 'aws-key',
      filePath: 'repo\\src\\a.ts',
      valueFingerprint: 'fp-1',
    });
    expect(a).toBe(b);
  });
});
