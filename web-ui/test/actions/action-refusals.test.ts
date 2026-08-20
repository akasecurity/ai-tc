import { describe, expect, it } from 'vitest';

import {
  malformedInput,
  managedRefusal,
  SETTINGS_WRITE_ERROR,
} from '../../app/lib/action-refusals.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// These are the strings a user reads when a settings write is refused, and each
// carries a rule that is easy to break by editing the wording alone.
//
// They are tested here rather than through the actions because a 'use server'
// module can only export async Server Actions — so reaching the administrative
// branch through one would need a managed file at an absolute OS path (/etc/aka,
// /Library/…) that no test can redirect. That is exactly why the formatting was
// moved out.

describe('malformedInput', () => {
  it('names the schema key so the user knows which control to look at', () => {
    expect(malformedInput({ field: 'historicalAccess', wrongType: true })).toContain(
      'historicalAccess',
    );
  });

  it('answers a non-object payload without naming any field', () => {
    // There is no field to name — the whole request was the wrong shape — and
    // inventing one would point the user at a control that is fine.
    const message = malformedInput({ field: null, wrongType: false });
    expect(message).toContain('expected shape');
    expect(message).not.toContain('undefined');
    expect(message).not.toContain('null');
  });

  it('distinguishes a wrong TYPE from a wrong FORM', () => {
    // Every field on this surface is a bare string or boolean today, so every
    // failure really is a type failure — but a `.min()` or `.url()` added to one
    // would reject a value that IS the right type, and "did not arrive as
    // expected" would then be a false diagnosis pointing at the wrong fix.
    const wrongType = malformedInput({ field: 'endpoint', wrongType: true });
    const wrongForm = malformedInput({ field: 'endpoint', wrongType: false });
    expect(wrongType).not.toBe(wrongForm);
  });

  it('echoes nothing derived from the payload', () => {
    // The formatter is handed only a key and a boolean, so this is a structural
    // property rather than a filter — pinned because a future version that
    // passed a Zod issue message through would break it silently. A settings
    // field can hold whatever the user pasted, including a credential.
    const secretish = 'Zk7QvR2mNbXt4LpW9sHyEc3JdFgA6uTi';
    for (const wrongType of [true, false]) {
      expectNoEchoOf(malformedInput({ field: 'vaultConsent', wrongType }), secretish);
    }
  });
});

describe('managedRefusal', () => {
  it('names the locked fields and attributes the decision to the organization', () => {
    const message = managedRefusal(['vaultConsent', 'runMode']);
    expect(message).toContain('vaultConsent');
    expect(message).toContain('runMode');
    expect(message).toMatch(/organization/i);
  });

  it('says the change was NOT saved', () => {
    // The one fact the user has to take away. A message that only explained the
    // lock would leave them assuming a partial save landed.
    expect(managedRefusal(['runMode'])).toMatch(/not saved/i);
  });

  it('does not read as a fault the user should retry', () => {
    // Retrying cannot help, and the user has done nothing wrong — so this must
    // not borrow the vocabulary of the write-failure message below.
    const message = managedRefusal(['runMode']);
    expect(message).not.toMatch(/try again/i);
    expect(message).not.toMatch(/error|failed/i);
    expect(message).not.toBe(SETTINGS_WRITE_ERROR);
  });

  it('stays coherent for a single field', () => {
    expect(managedRefusal(['historicalAccess'])).toContain('historicalAccess');
  });
});

describe('the three refusals are distinguishable', () => {
  it('no two produce the same message', () => {
    // They mean different things and have different remedies: reload, ask your
    // administrator, or the store is broken. A user who cannot tell them apart
    // takes the wrong action.
    const messages = new Set([
      malformedInput({ field: null, wrongType: false }),
      malformedInput({ field: 'runMode', wrongType: true }),
      managedRefusal(['runMode']),
      SETTINGS_WRITE_ERROR,
    ]);
    expect(messages.size).toBe(4);
  });
});
