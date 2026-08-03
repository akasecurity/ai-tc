import type {
  DetectionException,
  ExceptionDescriptor,
  FingerprintKeyState,
} from '@akasecurity/schema';
import {
  isMatchableUnder,
  LEDGER_WINDOW_HOURS as SCHEMA_LEDGER_WINDOW_HOURS,
  rotationBlockedLedgerNote as schemaRotationBlockedLedgerNote,
  toExceptionDescriptor,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  blockedRowBlockReason,
  exceptionState,
  isBlockedRowApprovable,
  LEDGER_WINDOW_HOURS,
  rotationBlockedLedgerNote,
} from '../../src/exceptions/meta.ts';

const NOW = Date.parse('2026-07-03T12:00:00.000Z');

// Built as a full store row and projected, exactly as a server boundary does —
// the helpers here take the fingerprint-free descriptor, which excludes the
// field rather than merely omitting it.
function exception(overrides: Partial<DetectionException>): ExceptionDescriptor {
  return toExceptionDescriptor({
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
  });
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

describe('rotationBlockedLedgerNote', () => {
  // This is disclosure copy on a one-way action, so the assertions are about
  // what the sentence must still SAY, not how it is worded. The dialog lists
  // the permanent grants rotation orphans; without this it said nothing about
  // the blocked ledger, which is retained for a day and so routinely outlives a
  // rotation. Those rows are handled correctly afterwards — the strip marks
  // them unapprovable via blockedRowBlockReason above — but that is the user
  // finding out after the fact, which is what this line exists to prevent.
  //
  // Guarded as a pure function rather than through the rendered dialog, unlike
  // the badge copy in views.test.tsx next door. That file's views are plain
  // markup; RotateKeyDialog is built on the Radix dialog primitive, which calls
  // hooks that renderToStaticMarkup cannot serve here, so a render assertion on
  // it would not run at all. Keeping the sentence in meta.ts is what makes it
  // reachable — the dialog holds no copy of its own to drift from.
  const CASES = [0, 1, 2, 17];

  // The sentence itself lives in @akasecurity/schema, beside the
  // isMatchableUnder predicate its count is taken with, because TWO surfaces
  // disclose this one-way action's cost — this dialog and
  // `aka exception rotate-key` — and cli cannot import this package's view
  // tree. What meta.ts exports has to stay that same function rather than a
  // copy that happens to read alike today: identity is what a reintroduced
  // local definition fails on, where an equal-output assertion would pass right
  // up until someone edited one of the two. The window constant travels with
  // it, since a forked note would fork the number it names.
  it('re-exports the shared copy rather than restating it', () => {
    expect(rotationBlockedLedgerNote).toBe(schemaRotationBlockedLedgerNote);
    expect(LEDGER_WINDOW_HOURS).toBe(SCHEMA_LEDGER_WINDOW_HOURS);
  });

  it.each(CASES)('names the blocked ledger and the way back, at %i approvable', (count) => {
    const note = rotationBlockedLedgerNote(count);
    expect(note).toMatch(/blocked/i);
    expect(note).toMatch(/approvable/i);
    // The rows are not deleted — saying so would be a different (and wrong)
    // claim about a ledger the user can still see.
    expect(note).toMatch(/stay listed/i);
    expect(note).toMatch(/trigger the detection again/i);
  });

  it('says the caveat applies even with nothing approvable', () => {
    // The ledger refills within minutes of a rotation, so a note shown only
    // when the count is non-zero would read as a caveat that only sometimes
    // applies. It must state the invalidation without a number.
    const note = rotationBlockedLedgerNote(0);
    expect(note).toMatch(/invalidated too/i);
    expect(note).not.toMatch(/\d/);
  });

  it('shows the count, and agrees with itself on singular and plural', () => {
    // Noun and verb asserted separately: the window phrase sits between them,
    // so pinning the adjacency would fail on a wording change that is still
    // grammatical — which is not what this case is for.
    const one = rotationBlockedLedgerNote(1);
    expect(one).toContain('1 recently blocked detection');
    expect(one).toContain('is still approvable');
    expect(one).not.toMatch(/detections/);

    const many = rotationBlockedLedgerNote(4);
    expect(many).toContain('4 recently blocked detections');
    expect(many).toContain('are still approvable');
  });

  it('names its window, so the number can be reconciled with the strip', () => {
    // The count spans the ledger's whole retention window while the strip shows
    // the selected chip — 30 minutes by default. Unqualified, "recently" leaves
    // the reader with a figure several times what is on screen and no way to
    // account for it, which is close to the failure this line exists to prevent.
    for (const count of [1, 2, 17]) {
      expect(rotationBlockedLedgerNote(count)).toContain(
        `from the last ${String(LEDGER_WINDOW_HOURS)} hours`,
      );
    }
  });

  it('claims no number it was not given, beyond that window', () => {
    // The count is threaded from a store read; a hard-coded digit in the
    // sentence would survive every count and be wrong for all but one. The
    // window is the ONLY other number allowed, and it must appear after the
    // count — pinned as an exact list rather than a loosened pattern, so a
    // stray figure still fails.
    for (const count of CASES) {
      const digits = rotationBlockedLedgerNote(count).match(/\d+/g) ?? [];
      expect(digits).toEqual(count === 0 ? [] : [String(count), String(LEDGER_WINDOW_HOURS)]);
    }
  });
});
