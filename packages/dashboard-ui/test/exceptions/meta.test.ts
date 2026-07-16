import type { DetectionException } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { exceptionState } from '../../src/exceptions/meta.ts';

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
