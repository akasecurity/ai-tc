import { policyFloorReason } from '@akasecurity/dashboard-ui';
import { describe, expect, it } from 'vitest';

import {
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
