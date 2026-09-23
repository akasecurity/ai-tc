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

  it('qualifies the no-reopen claim instead of making it unconditional', () => {
    // A dismissal survives re-detection and does NOT survive removal followed by
    // re-addition: once the value leaves the file the removal sweep writes
    // `resolved`/`fixed-at-source` over the dismissal, and the next scan that
    // finds the value again supersedes THAT with `open`/`redetected`. The
    // behaviour is pinned in
    // packages/persistence/test/repositories/resolutions.test.ts; what this
    // file can hold is that the copy does not overstate it.
    const noReopen = lines.filter((l) => /not reopen/i.test(l));
    expect(noReopen).toHaveLength(1);
    // Carries its own condition, rather than asserting it for every case.
    expect(noReopen[0]).toMatch(/while the value stays/i);
    // And the other half is stated rather than left out — a reader who only
    // saw the qualified sentence would still conclude it never comes back.
    expect(lines.some((l) => /removed and later re-added/i.test(l))).toBe(true);
    expect(lines.some((l) => /does reopen/i.test(l))).toBe(true);
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
