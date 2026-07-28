import type { DetectionException } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { exceptionState, isBlockedRowApprovable } from '../../src/exceptions/meta.ts';

const NOW = Date.parse('2026-07-03T12:00:00.000Z');

function exception(overrides: Partial<DetectionException>): DetectionException {
  return {
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 1,
    maskedValue: 'A****Z',
    scope: 'permanent',
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    lastUsedAt: null,
    justification: 'test fixture',
    conditions: null,
    createdBy: 'tester',
    createdVia: 'web-add',
    createdAt: '2026-07-01T00:00:00.000Z',
    updatedAt: '2026-07-01T00:00:00.000Z',
    revokedAt: null,
    revokedBy: null,
    revokeReason: null,
    ...overrides,
  };
}

describe('exceptionState', () => {
  it('is active while unrevoked, unexpired, and under budget', () => {
    expect(exceptionState(exception({}), NOW)).toBe('active');
    expect(
      exceptionState(exception({ expiresAt: '2026-07-03T13:00:00.000Z', scope: 'temporary' }), NOW),
    ).toBe('active');
    expect(exceptionState(exception({ maxUses: 2, useCount: 1 }), NOW)).toBe('active');
  });

  it('revoked wins over everything (terminal, audit-retained)', () => {
    expect(
      exceptionState(
        exception({
          revokedAt: '2026-07-02T00:00:00.000Z',
          revokedBy: 'tester',
          maxUses: 1,
          useCount: 1,
        }),
        NOW,
      ),
    ).toBe('revoked');
  });

  it('consumed when the use budget is spent', () => {
    expect(exceptionState(exception({ maxUses: 1, useCount: 1 }), NOW)).toBe('consumed');
  });

  it('expired when past expiresAt', () => {
    expect(
      exceptionState(exception({ expiresAt: '2026-07-03T11:59:59.000Z', scope: 'temporary' }), NOW),
    ).toBe('expired');
  });
});

describe('isBlockedRowApprovable', () => {
  it('is approvable only under the key version in use now', () => {
    expect(isBlockedRowApprovable({ keyVersion: 3 }, 3)).toBe(true);
  });

  it('is not approvable after a rotation moved the key on', () => {
    // The ledger is retained longer than a rotation takes, so the strip keeps
    // listing rows fingerprinted under the old key. A grant built from one
    // could never match, so the row is shown but not offered.
    expect(isBlockedRowApprovable({ keyVersion: 1 }, 2)).toBe(false);
  });

  it('is not approvable under an OLDER current version either', () => {
    // Not a `<` comparison: any version other than the current one means the
    // material differs, whichever way the number moved.
    expect(isBlockedRowApprovable({ keyVersion: 4 }, 2)).toBe(false);
  });

  it('is not approvable when there is no key file at all', () => {
    // The material is gone, so no stored fingerprint can be reproduced —
    // absence is refused on its own terms rather than treated as version 0.
    expect(isBlockedRowApprovable({ keyVersion: 1 }, null)).toBe(false);
    expect(isBlockedRowApprovable({ keyVersion: 0 }, null)).toBe(false);
  });
});
