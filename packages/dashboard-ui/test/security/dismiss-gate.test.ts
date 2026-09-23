import { DISMISS_CONFIRMATION, DismissMethod } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  canConfirmDismiss,
  DISMISS_METHODS,
  dismissConsequences,
} from '../../src/security/dismiss-gate.ts';

// The Dismiss dialog's decisions. None of this is the control — the Server
// Action re-checks the confirmation and the method before it writes, and that
// is where the property is proven. What these cover is that the dialog agrees
// with it, because a dialog that arms a button the server then refuses is a
// dead end the reader cannot get out of.

describe('canConfirmDismiss', () => {
  const armed = { confirmation: DISMISS_CONFIRMATION, method: 'acknowledged' as const };

  it('arms only on the exact word, a chosen method, and no write in flight', () => {
    expect(canConfirmDismiss({ ...armed, isMutating: false })).toBe(true);
  });

  it('stays disabled until a method is chosen', () => {
    // The segmented control starts unset, and a toggle group reports '' when its
    // active item is pressed again — so `null` is reachable after a choice, not
    // only before one.
    expect(canConfirmDismiss({ ...armed, method: null, isMutating: false })).toBe(false);
  });

  it('stays disabled while a write is in flight', () => {
    expect(canConfirmDismiss({ ...armed, isMutating: true })).toBe(false);
  });

  it.each([
    ['empty', ''],
    ['capitalized', 'Dismiss'],
    ['upper case', 'DISMISS'],
    ['padded', ` ${DISMISS_CONFIRMATION} `],
    ['a prefix', DISMISS_CONFIRMATION.slice(0, -1)],
    ['a superstring', `${DISMISS_CONFIRMATION}!`],
    ['a different word', 'yes'],
  ])('refuses a confirmation that is %s', (_name, confirmation) => {
    // Compared exactly, matching the action and the two sibling irreversible
    // surfaces on this dashboard. Every forgiving comparison makes a deliberate
    // act a little less deliberate, and a dialog more permissive than the server
    // arms a button that is then refused.
    expect(canConfirmDismiss({ ...armed, confirmation, isMutating: false })).toBe(false);
  });
});

describe('DISMISS_METHODS', () => {
  it('offers exactly the dispositions the schema lets a person record', () => {
    // Derived from the schema rather than restated: an offer the action refuses
    // is a dead end, and one the action accepts but the dialog never shows is a
    // disposition nobody can choose.
    expect(DISMISS_METHODS.map((m) => m.value).sort()).toEqual([...DismissMethod.options].sort());
  });

  it('labels each one in plain words, without naming the enum member', () => {
    for (const m of DISMISS_METHODS) {
      expect(m.label).not.toBe(m.value);
      expect(m.label).not.toBe('');
      expect(m.description).not.toBe('');
    }
  });
});

describe('dismissConsequences', () => {
  const lines = dismissConsequences('secrets/aws-access-key');

  it('names the rule it will act on', () => {
    expect(lines.join(' ')).toContain('secrets/aws-access-key');
  });

  it('states that a later scan will not reopen them', () => {
    // The fact a reader can discover nowhere else in the product. The scanner's
    // redetect pass reopens a key whose latest disposition is `resolved`, and a
    // dismissal is deliberately not that — so a still-present secret stays
    // closed. A dialog that omits this describes a reversible act.
    expect(lines.some((l) => /not\b.*reopen/i.test(l))).toBe(true);
  });

  it('states there is no undo', () => {
    expect(lines.some((l) => /no undo/i.test(l))).toBe(true);
  });

  it('says the findings are closed rather than deleted', () => {
    // The other half of being honest: a reader who thinks this deletes evidence
    // will not use it, and one who thinks it deletes findings is also wrong.
    expect(lines.some((l) => /not deleted|closed, not deleted/i.test(l))).toBe(true);
  });
});
