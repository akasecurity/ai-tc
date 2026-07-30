import { describe, expect, it } from 'vitest';

import type { BlockedDetection } from '../../src/zod/exception.ts';
import {
  DetectionException,
  ExceptionBundleEntry,
  ExceptionDescriptor,
  ExceptionScope,
  toBlockedDetectionDescriptor,
  toExceptionDescriptor,
} from '../../src/zod/exception.ts';
import { PolicyBundle } from '../../src/zod/policy.ts';

// A fully-populated active grant. The fingerprint is a keyed HMAC-SHA256 hex
// digest of the approved value — the raw value never appears in any shape.
const validException = {
  id: '00000000-0000-0000-0000-000000000001',
  ruleId: 'aws-access-key-id',
  category: 'secret' as const,
  valueFingerprint: 'a'.repeat(64),
  keyVersion: 1,
  maskedValue: 'AKIA****************',
  scope: 'temporary' as const,
  expiresAt: '2026-01-01T00:00:00.000Z',
  maxUses: null,
  useCount: 0,
  lastUsedAt: null,
  justification: 'Sandbox key used in integration-test fixtures',
  conditions: null,
  createdBy: '00000000-0000-0000-0000-000000000002',
  createdVia: 'cli-approve' as const,
  createdAt: '2025-12-31T00:00:00.000Z',
  updatedAt: '2025-12-31T00:00:00.000Z',
  revokedAt: null,
  revokedBy: null,
  revokeReason: null,
};

describe('DetectionException', () => {
  it('parses a valid exception', () => {
    const result = DetectionException.safeParse(validException);
    expect(result.success).toBe(true);
  });

  it('rejects an unknown scope', () => {
    expect(ExceptionScope.safeParse('forever').success).toBe(false);
    expect(DetectionException.safeParse({ ...validException, scope: 'forever' }).success).toBe(
      false,
    );
  });

  it('accepts all 3 scope values', () => {
    for (const scope of ['once', 'temporary', 'permanent']) {
      expect(ExceptionScope.safeParse(scope).success).toBe(true);
    }
  });

  it('accepts setup-triage as a createdVia provenance', () => {
    expect(
      DetectionException.safeParse({ ...validException, createdVia: 'setup-triage' }).success,
    ).toBe(true);
  });

  it('rejects an empty justification (every grant carries its reason)', () => {
    expect(DetectionException.safeParse({ ...validException, justification: '' }).success).toBe(
      false,
    );
  });

  it('parses with a conditions bag (all keys optional)', () => {
    const result = DetectionException.safeParse({
      ...validException,
      conditions: { repo: 'github.com/acme/api' },
    });
    expect(result.success).toBe(true);
  });

  it('rejects an unknown condition key (fail-closed: never silently widen a grant)', () => {
    const result = DetectionException.safeParse({
      ...validException,
      conditions: { repo: 'github.com/acme/api', branch: 'main' },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a malformed fingerprint (wrong length, non-hex, or raw-looking)', () => {
    for (const bad of ['a'.repeat(63), 'A'.repeat(64), 'zz'.repeat(32), 'AKIA-not-a-digest']) {
      expect(
        DetectionException.safeParse({ ...validException, valueFingerprint: bad }).success,
      ).toBe(false);
    }
  });
});

describe('ExceptionBundleEntry', () => {
  it('picks the evaluation subset only (no justification, no audit fields)', () => {
    const result = ExceptionBundleEntry.safeParse(validException);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(Object.keys(result.data).sort()).toEqual([
        'capability',
        'conditions',
        'expiresAt',
        'id',
        'keyVersion',
        'maxUses',
        'ruleId',
        'useCount',
        'valueFingerprint',
      ]);
    }
  });
});

describe('ExceptionDescriptor / toExceptionDescriptor', () => {
  it('omits exactly the keyed fingerprint and keeps everything else', () => {
    // Keys are compared against the PARSED row, not the raw fixture, so a
    // field the schema fills by default (e.g. capability) counts as "kept".
    const row = DetectionException.parse(validException);
    const descriptor = toExceptionDescriptor(row);
    expect(Object.keys(descriptor).sort()).toEqual(
      Object.keys(row)
        .filter((key) => key !== 'valueFingerprint')
        .sort(),
    );
    expect(descriptor.maskedValue).toBe(validException.maskedValue);
    expect(descriptor.keyVersion).toBe(validException.keyVersion);
  });

  it('does not mutate the row it projects', () => {
    const row = DetectionException.parse(validException);
    toExceptionDescriptor(row);
    expect(row.valueFingerprint).toBe(validException.valueFingerprint);
  });

  it('parses a full row by stripping the fingerprint (unknown keys drop)', () => {
    const parsed = ExceptionDescriptor.parse(validException);
    expect(Object.keys(parsed)).not.toContain('valueFingerprint');
  });
});

describe('toBlockedDetectionDescriptor', () => {
  const ledgerRow: BlockedDetection = {
    reference: 'blk-1234',
    ruleId: 'aws-access-key-id',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 1,
    maskedValue: 'AKIA****************',
    sessionId: null,
    repo: 'github.com/acme/api',
    blockedAt: '2026-01-01T00:00:00.000Z',
  };

  it('omits exactly the keyed fingerprint and keeps everything else', () => {
    const descriptor = toBlockedDetectionDescriptor(ledgerRow);
    expect(Object.keys(descriptor).sort()).toEqual(
      Object.keys(ledgerRow)
        .filter((key) => key !== 'valueFingerprint')
        .sort(),
    );
    expect(descriptor.reference).toBe(ledgerRow.reference);
    expect(ledgerRow.valueFingerprint).toBe('a'.repeat(64));
  });
});

describe('PolicyBundle.exceptions', () => {
  const baseBundle = {
    version: '1',
    policies: [],
    customKeywords: [],
    fetchedAt: '2025-12-31T00:00:00.000Z',
  };

  it('parses without exceptions (older backends / on-disk caches omit it)', () => {
    const result = PolicyBundle.safeParse(baseBundle);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.exceptions).toBeUndefined();
    }
  });

  it('parses with exceptions present', () => {
    const entry = ExceptionBundleEntry.parse(validException);
    const result = PolicyBundle.safeParse({ ...baseBundle, exceptions: [entry] });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.exceptions).toHaveLength(1);
    }
  });
});
