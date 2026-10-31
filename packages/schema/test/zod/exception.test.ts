import { describe, expect, it } from 'vitest';

import type { BlockedDetection, BlockedDetectionDescriptor } from '../../src/zod/exception.ts';
import {
  DetectionException,
  ExceptionBundleEntry,
  ExceptionDescriptor,
  ExceptionScope,
  toBlockedDetectionDescriptor,
  toExceptionDescriptor,
  VAULT_REFRESH_FAILED_NOTE,
  vaultRefreshShortfallNote,
} from '../../src/zod/exception.ts';
import { PolicyBundle } from '../../src/zod/policy.ts';
import { DismissMethod } from '../../src/zod/recommendation-action.ts';

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

  it('reads a grant written before the label fields as unlabelled and user-confirmed', () => {
    const parsed = DetectionException.parse(validException);
    expect(parsed.method).toBeNull();
    expect(parsed.confirmedBy).toBe('user');
  });

  it.each(DismissMethod.options)('accepts %s as the label of a grant', (method) => {
    expect(DetectionException.parse({ ...validException, method }).method).toBe(method);
  });

  it('rejects a machine verdict as the label of a grant', () => {
    for (const method of ['exception', 'redetected', 'fixed-at-source', 'enforced-in-flight']) {
      expect(DetectionException.safeParse({ ...validException, method }).success).toBe(false);
    }
  });

  it('accepts an admin confirmation and nothing outside user or admin', () => {
    expect(DetectionException.parse({ ...validException, confirmedBy: 'admin' }).confirmedBy).toBe(
      'admin',
    );
    expect(DetectionException.safeParse({ ...validException, confirmedBy: 'model' }).success).toBe(
      false,
    );
  });

  it('keeps the free-text justification required beside the label', () => {
    expect(
      DetectionException.safeParse({
        ...validException,
        method: 'test-or-example',
        justification: '',
      }).success,
    ).toBe(false);
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

  it('refuses an unprojected row at the type level, not just a literal', () => {
    // The point of the optional-never exclusion. A plain omit would accept
    // this: every property the descriptor asks for is present on a full row,
    // so a surface typed against it would keep compiling with the projection
    // call in front of it deleted — which is exactly how the fingerprint gets
    // back into the browser with nothing red. Pinned on a `declare`d row, not
    // an object literal, because excess-property checking already rejects
    // literals and would make this pass for the wrong reason.
    const row = DetectionException.parse(validException);
    // @ts-expect-error -- a full grant row is not an ExceptionDescriptor
    const unprojected: ExceptionDescriptor = row;
    // The runtime value is still the row; only the assignment is refused.
    expect(unprojected.id).toBe(validException.id);

    const ledgerRow: BlockedDetection = {
      reference: 'blk-9999',
      ruleId: 'aws-access-key-id',
      category: 'secret',
      valueFingerprint: 'b'.repeat(64),
      keyVersion: 1,
      maskedValue: 'AKIA****************',
      sessionId: null,
      repo: null,
      blockedAt: '2026-01-01T00:00:00.000Z',
    };
    // @ts-expect-error -- a full ledger row is not a BlockedDetectionDescriptor
    const unprojectedLedger: BlockedDetectionDescriptor = ledgerRow;
    expect(unprojectedLedger.reference).toBe('blk-9999');
  });

  it('accepts the projected value it produces', () => {
    // The other half: the exclusion must not be so strict that the helper's
    // own output fails to satisfy it, which would push callers to cast.
    const descriptor: ExceptionDescriptor = toExceptionDescriptor(
      DetectionException.parse(validException),
    );
    expect(descriptor.id).toBe(validException.id);
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

// The AFTER-the-fact half of the rotate disclosure. The vault is the one store a
// rotation re-keys rather than invalidates, so a complete pass has nothing to
// say — which is exactly why an incomplete one must say something, and why the
// note is shaped around a denominator rather than a success count.
describe('vaultRefreshShortfallNote', () => {
  it('says nothing for a pass that reached every row', () => {
    expect(vaultRefreshShortfallNote(3, 0)).toBeNull();
  });

  // The case the bare count could not tell from the one above. Both report zero
  // refreshes; only one of them has lost anything.
  it('distinguishes an empty vault from a vault where every row failed', () => {
    expect(vaultRefreshShortfallNote(0, 0)).toBeNull();
    expect(vaultRefreshShortfallNote(0, 2)).not.toBeNull();
  });

  it('states the shortfall against the rows the pass actually walked', () => {
    const note = vaultRefreshShortfallNote(7, 3);
    expect(note).toContain('3 of 10');
    // Both numbers and nothing else: a third figure in a line about a count the
    // reader is being asked to trust is a figure they cannot reconcile.
    expect(note?.match(/\d+/g)).toEqual(['3', '10']);
  });

  it('keeps the noun in step with the number of rows walked', () => {
    expect(vaultRefreshShortfallNote(0, 1)).toContain('1 of 1 stored value could');
    expect(vaultRefreshShortfallNote(1, 1)).toContain('1 of 2 stored values could');
  });

  // Why it matters, in the note itself: a reader who takes "could not be
  // re-keyed" for "the values are gone" deletes a vault that is intact.
  it('names the consequence and rules out the wrong one', () => {
    const note = vaultRefreshShortfallNote(0, 1) ?? '';
    expect(note).toContain('second pointer');
    expect(note).toContain('Nothing stored is lost');
  });

  // The remedy has exactly one lever — another rotation — and that lever is
  // itself destructive, because rotateFingerprintKey always mints a HIGHER
  // version. A note that said "re-run the rotation" without this would have the
  // reader destroy the grants they re-approved after the first rotation.
  it('states what the only remedy costs, not just that there is one', () => {
    const note = vaultRefreshShortfallNote(0, 1) ?? '';
    expect(note).toContain('Only another rotation re-keys them');
    expect(note).toContain('invalidates every exception grant a second time');
  });

  // A skipped row covers two unlike causes the pass cannot tell apart: a key
  // directory that cannot be read right now, which a later rotation does fix,
  // and a damaged entry, which nothing fixes — so the note must not promise the
  // retry works, and must name the answer for the half that never will.
  it('does not promise a retry will work, and names pruning for the half that will not', () => {
    const note = vaultRefreshShortfallNote(0, 1) ?? '';
    expect(note).toContain('find out why the rows will not open');
    expect(note).toContain('never open again');
    expect(note).toContain('pruned');
    // The claim that was there before, and was true for only one of the two
    // causes. Its absence is the fix, so it is asserted rather than assumed.
    expect(note).not.toContain('Re-run the rotation once the vault is readable');
  });

  // The same two numbers describe the standing condition as describe one pass,
  // so the route's store-derived notice reads through this helper rather than a
  // second sentence of its own — which is why the wording cannot say "the
  // previous key": after two rotations a row left behind is two epochs back.
  it('reads for a standing count as well as for one pass', () => {
    expect(vaultRefreshShortfallNote(10 - 3, 3)).toBe(vaultRefreshShortfallNote(7, 3));
    expect(vaultRefreshShortfallNote(7, 3)).toContain('an older fingerprint key');
    expect(vaultRefreshShortfallNote(7, 3)).not.toContain('the previous fingerprint key');
  });

  it('treats a negative skip as nothing to disclose rather than a shortfall', () => {
    expect(vaultRefreshShortfallNote(1, -1)).toBeNull();
  });

  // The standing count reaches this helper as `(total - stale, stale)`. A caller
  // that reads those two halves separately can have a purge land between them
  // and subtract its way to a negative fresh count, and the sentence would then
  // state a fraction no state of the vault ever held. The digits are asserted
  // rather than the absence of a minus sign: the note is full of hyphens
  // ("re-keyed", "off-key"), so only the numbers can carry this.
  it('floors the fresh half at zero, so a torn pair cannot state a denominator below the shortfall', () => {
    expect(vaultRefreshShortfallNote(-1, 1)?.match(/\d+/g)).toEqual(['1', '1']);
    expect(vaultRefreshShortfallNote(-3, 5)?.match(/\d+/g)).toEqual(['5', '5']);
    // And the clamp changes nothing for a pair that is already consistent.
    expect(vaultRefreshShortfallNote(7, 3)?.match(/\d+/g)).toEqual(['3', '10']);
  });
});

describe('VAULT_REFRESH_FAILED_NOTE', () => {
  // The whole-pass variant exists because a throw can land before the first row,
  // so there is no denominator to state. Any digit in it would be invented.
  // One wording for one fact, across both notes. Two whole-pass failures running
  // leave a row two epochs back, so "the previous one" would overstate how
  // fresh the stored values are — in the one note whose job is the conservative
  // account. The reader's question is the same either way: is anything still
  // under a key I have replaced?
  it('says the values are under an older key, not the previous one', () => {
    expect(VAULT_REFRESH_FAILED_NOTE).toContain('still carries an older one');
    expect(VAULT_REFRESH_FAILED_NOTE).not.toContain('the previous one');
    expect(vaultRefreshShortfallNote(0, 1)).toContain('an older fingerprint key');
  });

  it('claims no count, because a pass that threw does not have one', () => {
    expect(VAULT_REFRESH_FAILED_NOTE).not.toMatch(/\d/);
  });

  it('still names the loss and rules out the wrong conclusion', () => {
    expect(VAULT_REFRESH_FAILED_NOTE).toContain('second pointer');
    expect(VAULT_REFRESH_FAILED_NOTE).toContain('still resolve');
  });

  // Same remedy, same cost, same refusal to promise it works. A whole-pass
  // fault is likelier to be the store or the key custody than any one row, so
  // this variant points at the read and leaves pruning to the per-row note —
  // the only one that can be about a specific unrecoverable entry.
  it('carries the remedy cost without prescribing a blind retry', () => {
    expect(VAULT_REFRESH_FAILED_NOTE).toContain('invalidates every exception grant a second time');
    expect(VAULT_REFRESH_FAILED_NOTE).toContain('check why the vault could not be read');
    expect(VAULT_REFRESH_FAILED_NOTE).not.toContain('until a rotation re-keys them');
  });
});
