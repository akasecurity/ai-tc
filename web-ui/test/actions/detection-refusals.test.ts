import { DETECTION_STAYS_ON_REASON, policyFloorReason } from '@akasecurity/dashboard-ui';
import { PolicyFloorError } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

import {
  asPolicyFloorRefusal,
  DETECTION_ID_INVALID,
  DETECTION_MISSING,
  DETECTION_POLICY_INVALID,
  DETECTION_STAYS_ON_REFUSAL,
  DETECTION_WRITE_ERROR,
  isControlPlaneRefusal,
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
      expect(message).not.toBe(DETECTION_WRITE_ERROR);
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

describe('DETECTION_STAYS_ON_REFUSAL', () => {
  it('says the change was not saved', () => {
    // The one fact the constraint itself does not carry. Without it the reader
    // is left guessing whether the detection is now off.
    expect(DETECTION_STAYS_ON_REFUSAL).toMatch(/not saved/i);
  });

  it('reuses the sentence the toggle already showed', () => {
    // One rule, one wording — the toggle withholds the choice with this before
    // the click, exactly as the picker does with the floor's own sentence.
    expect(DETECTION_STAYS_ON_REFUSAL).toContain(DETECTION_STAYS_ON_REASON);
  });

  it('says the detection can still be raised', () => {
    // The remedy this refusal leaves open, and the whole reason it is not the
    // lock's sentence: enforcement may still be strengthened here.
    expect(DETECTION_STAYS_ON_REFUSAL).toMatch(/stronger/i);
  });

  it('does not read as a fault the user should retry', () => {
    // Retrying cannot help, and the user has done nothing wrong.
    expect(DETECTION_STAYS_ON_REFUSAL).not.toMatch(/error|failed|try again/i);
    expect(DETECTION_STAYS_ON_REFUSAL).not.toBe(DETECTION_WRITE_ERROR);
  });
});

describe('every refusal is distinguishable', () => {
  it('no two produce the same message', () => {
    // They mean different things and have different remedies: pick something
    // stronger, raise it instead of switching it off, ask your administrator,
    // reload, or the store is broken.
    const messages = new Set([
      policyFloorRefusal({ floor: 'warn', refusal: 'floor' }),
      policyFloorRefusal({ floor: 'warn', refusal: 'lock' }),
      DETECTION_STAYS_ON_REFUSAL,
      DETECTION_POLICY_INVALID,
      DETECTION_ID_INVALID,
      DETECTION_MISSING,
      DETECTION_WRITE_ERROR,
    ]);
    expect(messages.size).toBe(7);
  });

  it('the faults tell the user what to do about them', () => {
    expect(DETECTION_POLICY_INVALID).toMatch(/reload/i);
    expect(DETECTION_ID_INVALID).toMatch(/reload/i);
    expect(DETECTION_MISSING).toMatch(/reload/i);
    expect(DETECTION_WRITE_ERROR).toMatch(/try again/i);
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

describe('isControlPlaneRefusal', () => {
  it("reads the store's own refusal, and a copy `instanceof` would miss", () => {
    // The enable path asks only this question: was this the organization's
    // decision? It quotes no archetype, so it validates none — and it must
    // still see the refusal through a second copy of the class, for the same
    // reason the assignment path does.
    expect(
      isControlPlaneRefusal(new PolicyFloorError('aka/pack', 'monitor', 'block', 'floor')),
    ).toBe(true);
    const copy = new ForeignPolicyFloorError('warn', 'lock');
    expect(copy instanceof PolicyFloorError).toBe(false);
    expect(isControlPlaneRefusal(copy)).toBe(true);
  });

  it('turns away a genuine store fault', () => {
    // The other half of the same read. A write that failed for a real reason
    // must keep the message that tells the user to retry, or every fault would
    // come out as somebody else's decision.
    for (const candidate of [
      null,
      undefined,
      'PolicyFloorError',
      new Error('SQLITE_BUSY: database is locked'),
      { name: 'ManagedFieldError' },
    ] as unknown[]) {
      expect(isControlPlaneRefusal(candidate), JSON.stringify(candidate ?? null)).toBe(false);
    }
  });

  it('accepts a refusal carrying no archetype at all', () => {
    // Deliberately weaker than asPolicyFloorRefusal, and this is the case that
    // says so: the enable refusal's sentence quotes nothing from the error, so
    // demanding a floor it never reads would report the organization's decision
    // as a broken store.
    expect(isControlPlaneRefusal({ name: 'PolicyFloorError' })).toBe(true);
  });
});

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
