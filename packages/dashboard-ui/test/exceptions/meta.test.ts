import type { DetectionException, FingerprintKeyState } from '@akasecurity/schema';
import { isMatchableUnder } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  blockedRowBlockReason,
  exceptionState,
  isBlockedRowApprovable,
} from '../../src/exceptions/meta.ts';

const NOW = Date.parse('2026-07-03T12:00:00.000Z');

function exception(overrides: Partial<DetectionException>): DetectionException {
  return {
    id: '7d9f7a4e-1111-4222-8333-444455556666',
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: 'a'.repeat(64),
    keyVersion: 1,
    maskedValue: 'A****Z',
    capability: 'suppress',
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
  const present = (version: number): FingerprintKeyState => ({ status: 'present', version });

  it('is approvable only under the key version in use now', () => {
    expect(isBlockedRowApprovable({ keyVersion: 3 }, present(3))).toBe(true);
  });

  it('is not approvable after a rotation moved the key on', () => {
    // The ledger is retained longer than a rotation takes, so the strip keeps
    // listing rows fingerprinted under the old key. A grant built from one
    // could never match, so the row is shown but not offered.
    expect(isBlockedRowApprovable({ keyVersion: 1 }, present(2))).toBe(false);
  });

  it('is not approvable under an OLDER current version either', () => {
    // Not a `<` comparison: any version other than the current one means the
    // material differs, whichever way the number moved.
    expect(isBlockedRowApprovable({ keyVersion: 4 }, present(2))).toBe(false);
  });

  it('is not approvable when the key is absent or unreadable', () => {
    // Absent: the material is gone, so no stored fingerprint can be reproduced.
    // Unreadable: it may be intact, but nothing can be matched until it can be
    // read. Neither is treated as version 0.
    expect(isBlockedRowApprovable({ keyVersion: 1 }, { status: 'absent' })).toBe(false);
    expect(isBlockedRowApprovable({ keyVersion: 0 }, { status: 'absent' })).toBe(false);
    expect(isBlockedRowApprovable({ keyVersion: 1 }, { status: 'unreadable' })).toBe(false);
  });

  it('agrees with the shared rule it delegates to', () => {
    // The point of routing through @akasecurity/schema is that the strip and the
    // two approve surfaces cannot drift. Pin the delegation itself, so a future
    // local reimplementation here fails rather than silently disagrees.
    const cases: [number, FingerprintKeyState][] = [
      [1, present(1)],
      [1, present(2)],
      [2, present(1)],
      [1, { status: 'absent' }],
      [1, { status: 'unreadable' }],
    ];
    for (const [keyVersion, key] of cases) {
      expect(isBlockedRowApprovable({ keyVersion }, key)).toBe(isMatchableUnder(keyVersion, key));
    }
  });
});

describe('blockedRowBlockReason', () => {
  it('is null when the row is approvable — nothing to explain', () => {
    expect(blockedRowBlockReason({ keyVersion: 2 }, { status: 'present', version: 2 })).toBeNull();
  });

  it('names the rotation, with both versions, when the key moved on', () => {
    const reason = blockedRowBlockReason({ keyVersion: 1 }, { status: 'present', version: 3 });
    expect(reason).toMatch(/v1/);
    expect(reason).toMatch(/v3/);
    expect(reason).toMatch(/trigger the detection again/i);
  });

  it('tells an UNREADABLE key apart from a missing one — and never says delete it', () => {
    // The whole reason the state is a discriminated union rather than
    // `number | null`: for a chmod-broken key nothing changed, re-triggering
    // fixes nothing, and deleting the key to "fix" it would destroy every grant
    // on the machine.
    const reason = blockedRowBlockReason({ keyVersion: 1 }, { status: 'unreadable' });
    expect(reason).toMatch(/cannot be read/i);
    expect(reason).toMatch(/permissions/i);
    expect(reason).toMatch(/do not delete/i);
    expect(reason).not.toMatch(/trigger the detection again/i);
    expect(reason).not.toBe(blockedRowBlockReason({ keyVersion: 1 }, { status: 'absent' }));
  });

  it('tells a missing key to re-trigger, which does fix it', () => {
    const reason = blockedRowBlockReason({ keyVersion: 1 }, { status: 'absent' });
    expect(reason).toMatch(/missing/i);
    expect(reason).toMatch(/trigger the detection again/i);
  });
});
