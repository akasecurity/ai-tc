import { policyFloorReason } from '@akasecurity/dashboard-ui';
import { PolicyFloorError } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import {
  asPolicyFloorRefusal,
  DETECTION_POLICY_INVALID,
  DETECTION_POLICY_MISSING,
  DETECTION_POLICY_WRITE_ERROR,
  policyFloorRefusal,
} from '../../app/lib/detection-refusals.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// What a user reads when the Detections page cannot save their choice.
//
// Covered here rather than only through the action because these are the words
// that carry the whole point of the change: an organizational constraint
// reported as breakage reads as a bug in the product rather than as a decision
// by the user's own organization, and the two have opposite remedies.

describe('policyFloorRefusal', () => {
  it('says the change was not saved', () => {
    // The one fact the constraint itself does not carry. Without it the reader
    // is left guessing whether a partial change landed.
    expect(policyFloorRefusal({ floor: 'warn', refusal: 'floor' })).toMatch(/not saved/i);
  });

  it('reuses the sentence the picker already showed', () => {
    // One rule, one wording. The picker greys the option out with this before
    // the click; two wordings is how the two moments start describing different
    // products.
    expect(policyFloorRefusal({ floor: 'redact', refusal: 'floor' })).toContain(
      policyFloorReason({ floor: 'redact', locked: false }),
    );
    expect(policyFloorRefusal({ floor: 'redact', refusal: 'lock' })).toContain(
      policyFloorReason({ floor: 'redact', locked: true }),
    );
  });

  it('distinguishes a floor from a lock', () => {
    // Under a floor there is still a decision to take; under a lock there is
    // none. A reader who cannot tell them apart goes looking for a stronger
    // option that will also be refused.
    expect(policyFloorRefusal({ floor: 'warn', refusal: 'floor' })).not.toBe(
      policyFloorRefusal({ floor: 'warn', refusal: 'lock' }),
    );
  });

  it('does not read as a fault the user should retry', () => {
    // Retrying cannot help, and the user has done nothing wrong — so this must
    // not borrow the vocabulary of the write-failure message.
    for (const refusal of ['floor', 'lock'] as const) {
      const message = policyFloorRefusal({ floor: 'block', refusal });
      expect(message).not.toMatch(/error|failed|try again/i);
      expect(message).not.toBe(DETECTION_POLICY_WRITE_ERROR);
    }
  });

  it('echoes nothing but the archetype it was handed', () => {
    // A structural property rather than a filter — it is handed two enum
    // values and nothing else — pinned because a future version that passed the
    // store's own error message through would break it silently, and that
    // message names the pack the user was working on.
    const secretish = 'Zk7QvR2mNbXt4LpW9sHyEc3JdFgA6uTi';
    expectNoEchoOf(policyFloorRefusal({ floor: 'warn', refusal: 'floor' }), secretish);
  });
});

describe('the four refusals are distinguishable', () => {
  it('no two produce the same message', () => {
    // They mean different things and have different remedies: pick something
    // stronger, ask your administrator, reload, or the store is broken.
    const messages = new Set([
      policyFloorRefusal({ floor: 'warn', refusal: 'floor' }),
      policyFloorRefusal({ floor: 'warn', refusal: 'lock' }),
      DETECTION_POLICY_INVALID,
      DETECTION_POLICY_MISSING,
      DETECTION_POLICY_WRITE_ERROR,
    ]);
    expect(messages.size).toBe(5);
  });

  it('the two faults tell the user what to do about them', () => {
    expect(DETECTION_POLICY_INVALID).toMatch(/reload/i);
    expect(DETECTION_POLICY_MISSING).toMatch(/reload/i);
    expect(DETECTION_POLICY_WRITE_ERROR).toMatch(/try again/i);
  });
});

/**
 * A SECOND copy of the store's error class — same name, same fields, unrelated
 * prototype — standing in for what a page and the store it calls look like once
 * a bundler has given each its own copy of the module. Declared here rather
 * than faked as an object literal because the copy an `instanceof` misses in
 * production is a real Error subclass, and a literal would not prove the reader
 * is looking at the fields instead of the ancestry.
 */
class ForeignPolicyFloorError extends Error {
  readonly floor: string;
  readonly refusal: string;

  constructor(floor: string, refusal: string) {
    super('refusing to re-assign');
    this.name = 'PolicyFloorError';
    this.floor = floor;
    this.refusal = refusal;
  }
}

describe('asPolicyFloorRefusal', () => {
  it("reads the store's own refusal", () => {
    const error = new PolicyFloorError('aka/pack', 'monitor', 'block', 'floor');
    expect(asPolicyFloorRefusal(error)).toEqual({ floor: 'block', refusal: 'floor' });
  });

  it('reads a copy of it that `instanceof` would miss', () => {
    // The whole reason the check is structural. If this ever regressed to a
    // prototype test, the organization's decision would come out as the
    // store-is-broken message and send someone to fix a permission on ~/.aka
    // they do not have.
    const copy = new ForeignPolicyFloorError('warn', 'lock');
    expect(copy instanceof PolicyFloorError).toBe(false);
    const read = asPolicyFloorRefusal(copy);
    expect(read).toEqual({ floor: 'warn', refusal: 'lock' });
    // And the sentence it produces is the one the organization's own error
    // would have produced — the point is the message, not the parse.
    expect(read === null ? '' : policyFloorRefusal(read)).toBe(
      policyFloorRefusal({ floor: 'warn', refusal: 'lock' }),
    );
  });

  it('turns away everything that is not one', () => {
    // A structural read is only safe if it is also strict: the name alone must
    // not be enough, or a shape carrying it without a usable floor would be
    // formatted into a sentence with `undefined` in it. Each of these has to
    // fall through to the write-error message instead.
    const notRefusals: unknown[] = [
      null,
      undefined,
      'PolicyFloorError',
      new Error('SQLITE_BUSY: database is locked'),
      { name: 'PolicyFloorError' },
      { name: 'PolicyFloorError', floor: 'block' },
      { name: 'PolicyFloorError', refusal: 'floor' },
      { name: 'PolicyFloorError', floor: 'not-an-archetype', refusal: 'floor' },
      { name: 'PolicyFloorError', floor: 'block', refusal: 'maybe' },
      { name: 'ManagedFieldError', floor: 'block', refusal: 'floor' },
    ];
    for (const candidate of notRefusals) {
      expect(asPolicyFloorRefusal(candidate), JSON.stringify(candidate ?? null)).toBeNull();
    }
  });
});
