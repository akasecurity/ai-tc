import type { AttachmentMode, ConnectionRefusal } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { decideAttachMode, holdsScopedFor, settledDecisionHolds } from '../src/attach-mode.ts';
import type { CredentialFileRead } from '../src/control-plane-credential.ts';

// How an attach chooses between a scoped and a machine-wide attachment. The
// decision is pure: it takes what is known before any network call (the flag
// the user typed, whether an administrator manages the connection, the
// credential file already on the machine, the endpoint, and whether there is a
// terminal) and returns one decision. Nothing here reads a file or the
// environment, so each case is just a value in and a value out.

const ENDPOINT = 'https://aka.example.com';
const OTHER_ENDPOINT = 'https://aka.example.net';
const KEY = 'key-1';
const ORG = 'Acme IT';

const MACHINE: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY },
};
const SCOPED: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY },
};
const SCOPED_ELSEWHERE: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 2, mode: 'scoped', endpoint: OTHER_ENDPOINT, apiKey: KEY },
};
const MACHINE_ELSEWHERE: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 1, endpoint: OTHER_ENDPOINT, apiKey: KEY },
};
const SCOPED_TRAILING_SLASH: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 2, mode: 'scoped', endpoint: `${ENDPOINT}/`, apiKey: KEY },
};
const SCOPED_UPPER_CASE_HOST: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 2, mode: 'scoped', endpoint: 'https://AKA.example.com', apiKey: KEY },
};
const ABSENT: CredentialFileRead = { usable: false, reason: 'absent' };
const MISMATCHED: CredentialFileRead = {
  usable: false,
  reason: 'endpoint-mismatch',
  credentialEndpoint: OTHER_ENDPOINT,
  settingsEndpoint: ENDPOINT,
};
const MANAGED: ConnectionRefusal = { reason: 'scoped-managed', organization: ORG };

const decide = (over: Partial<Parameters<typeof decideAttachMode>[0]>) =>
  decideAttachMode({
    flag: undefined,
    managed: null,
    previous: ABSENT,
    endpoint: ENDPOINT,
    interactive: true,
    ...over,
  });

describe('decideAttachMode: an administrator decides first', () => {
  it('refuses --scoped on a machine whose connection is managed', () => {
    expect(decide({ managed: MANAGED, flag: 'scoped' })).toEqual({
      kind: 'refuse',
      why: 'scoped-managed',
    });
  });

  it('attaches a managed machine machine-wide, and never asks', () => {
    expect(decide({ managed: MANAGED })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'managed',
    });
  });

  it('attaches a managed machine machine-wide over a scoped credential for another endpoint', () => {
    expect(decide({ managed: MANAGED, previous: SCOPED_ELSEWHERE, interactive: false })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'managed',
    });
  });

  it('attaches a managed machine machine-wide without a terminal or a flag, over a credential file that cannot be read', () => {
    expect(
      decide({
        managed: MANAGED,
        previous: { usable: false, reason: 'malformed' },
        interactive: false,
      }),
    ).toEqual({ kind: 'use', mode: 'machine', widening: false, why: 'managed' });
  });

  it('marks a managed attach over a scoped credential for this endpoint as a widening', () => {
    expect(decide({ managed: MANAGED, previous: SCOPED, interactive: false })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: true,
      why: 'managed',
    });
    expect(decide({ managed: MANAGED, previous: SCOPED, flag: 'machine' })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: true,
      why: 'managed',
    });
  });
});

describe('decideAttachMode: a flag decides next', () => {
  it('--scoped narrows without a question, even over an earlier machine-wide credential', () => {
    expect(decide({ flag: 'scoped', previous: MACHINE })).toEqual({
      kind: 'use',
      mode: 'scoped',
      widening: false,
      why: 'flag',
    });
  });

  it('--machine over a scoped credential for this endpoint is a widening', () => {
    expect(decide({ flag: 'machine', previous: SCOPED })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: true,
      why: 'flag',
    });
  });

  it('--machine over a machine-wide credential, or a scoped one for another endpoint, is not', () => {
    expect(decide({ flag: 'machine', previous: MACHINE })).toMatchObject({ widening: false });
    expect(decide({ flag: 'machine', previous: SCOPED_ELSEWHERE })).toMatchObject({
      widening: false,
    });
  });

  it('a flag is enough over a credential file that cannot be read', () => {
    expect(
      decide({
        flag: 'machine',
        previous: { usable: false, reason: 'malformed' },
        interactive: false,
      }),
    ).toEqual({ kind: 'use', mode: 'machine', widening: false, why: 'flag' });
  });

  it('a flag is enough over a scoped credential for another endpoint', () => {
    expect(decide({ flag: 'machine', previous: SCOPED_ELSEWHERE, interactive: false })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'flag',
    });
    expect(decide({ flag: 'scoped', previous: SCOPED_ELSEWHERE, interactive: false })).toEqual({
      kind: 'use',
      mode: 'scoped',
      widening: false,
      why: 'flag',
    });
  });
});

describe('decideAttachMode: with no flag', () => {
  it('keeps the mode of a usable credential for this endpoint, with or without a terminal', () => {
    expect(decide({ previous: SCOPED, interactive: false })).toEqual({
      kind: 'use',
      mode: 'scoped',
      widening: false,
      why: 'kept',
    });
    expect(decide({ previous: MACHINE, interactive: true })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'kept',
    });
  });

  it('compares the endpoint as an exact string, so another spelling keeps nothing', () => {
    expect(decide({ previous: SCOPED_TRAILING_SLASH, interactive: true })).toEqual({ kind: 'ask' });
    // And without a terminal, another spelling is still a scoped machine being
    // pointed elsewhere: it stops rather than widening.
    expect(decide({ previous: SCOPED_TRAILING_SLASH, interactive: false })).toEqual({
      kind: 'refuse',
      why: 'needs-flag',
    });
  });

  it('does not take a host that differs only in case for the same endpoint', () => {
    expect(decide({ previous: SCOPED_UPPER_CASE_HOST, interactive: true })).toEqual({
      kind: 'ask',
    });
    expect(decide({ previous: SCOPED_UPPER_CASE_HOST, interactive: false })).toEqual({
      kind: 'refuse',
      why: 'needs-flag',
    });
  });

  it('does not take an endpoint with a trailing slash for the credential written without one', () => {
    expect(decide({ previous: SCOPED, endpoint: `${ENDPOINT}/`, interactive: true })).toEqual({
      kind: 'ask',
    });
    expect(decide({ previous: SCOPED, endpoint: `${ENDPOINT}/`, interactive: false })).toEqual({
      kind: 'refuse',
      why: 'needs-flag',
    });
  });

  it('asks on a terminal when the credential is for another endpoint, scoped or not', () => {
    expect(decide({ previous: SCOPED_ELSEWHERE, interactive: true })).toEqual({ kind: 'ask' });
    expect(decide({ previous: MACHINE_ELSEWHERE, interactive: true })).toEqual({ kind: 'ask' });
  });

  it('refuses to guess without a terminal when a scoped credential is for another endpoint', () => {
    expect(decide({ previous: SCOPED_ELSEWHERE, interactive: false })).toEqual({
      kind: 'refuse',
      why: 'needs-flag',
    });
  });

  it('attaches machine-wide without a terminal when a machine-wide credential is for another endpoint', () => {
    expect(decide({ previous: MACHINE_ELSEWHERE, interactive: false })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'non-interactive',
    });
  });

  it('asks on a terminal on a first attach', () => {
    expect(decide({ previous: ABSENT, interactive: true })).toEqual({ kind: 'ask' });
  });

  it('attaches machine-wide without a terminal on a first attach', () => {
    expect(decide({ previous: ABSENT, interactive: false })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: false,
      why: 'non-interactive',
    });
  });

  it.each(['malformed', 'unreadable', 'untrusted-file', 'unsafe-endpoint'] as const)(
    'refuses to guess over a credential file that is %s, without a terminal, and asks with one',
    (reason) => {
      const previous: CredentialFileRead = { usable: false, reason };
      expect(decide({ previous, interactive: false })).toEqual({
        kind: 'refuse',
        why: 'needs-flag',
      });
      expect(decide({ previous, interactive: true })).toEqual({ kind: 'ask' });
    },
  );

  it('treats a read that reports an endpoint mismatch like any other credential file that cannot be used', () => {
    expect(decide({ previous: MISMATCHED, interactive: false })).toEqual({
      kind: 'refuse',
      why: 'needs-flag',
    });
    expect(decide({ previous: MISMATCHED, interactive: true })).toEqual({ kind: 'ask' });
  });
});

// The two checks a caller shares with the decision above, so that every surface
// that attaches a machine asks them the same way.

const UNREADABLE: CredentialFileRead = { usable: false, reason: 'malformed' };

describe('holdsScopedFor', () => {
  it('holds for a usable scoped credential for exactly this endpoint', () => {
    expect(holdsScopedFor(SCOPED, ENDPOINT)).toBe(true);
  });

  it('does not hold for a machine-wide credential for this endpoint', () => {
    expect(holdsScopedFor(MACHINE, ENDPOINT)).toBe(false);
  });

  it('does not hold for a scoped credential for another endpoint', () => {
    expect(holdsScopedFor(SCOPED_ELSEWHERE, ENDPOINT)).toBe(false);
  });

  it('compares the endpoint as an exact string, so another spelling of it does not hold', () => {
    expect(holdsScopedFor(SCOPED_TRAILING_SLASH, ENDPOINT)).toBe(false);
    expect(holdsScopedFor(SCOPED_UPPER_CASE_HOST, ENDPOINT)).toBe(false);
    expect(holdsScopedFor(SCOPED, `${ENDPOINT}/`)).toBe(false);
  });

  it.each<[string, CredentialFileRead]>([
    ['absent', ABSENT],
    ['unreadable', UNREADABLE],
    ['reported as an endpoint mismatch', MISMATCHED],
  ])('does not hold for a credential file that is %s', (_name, previous) => {
    expect(holdsScopedFor(previous, ENDPOINT)).toBe(false);
  });

  it('is the same fact the decision calls a widening, for every credential', () => {
    // The decision's `widening` and this predicate are one definition: a
    // machine-wide write over a credential widens exactly when it holds.
    const credentials = [
      ABSENT,
      UNREADABLE,
      MISMATCHED,
      MACHINE,
      MACHINE_ELSEWHERE,
      SCOPED,
      SCOPED_ELSEWHERE,
      SCOPED_TRAILING_SLASH,
      SCOPED_UPPER_CASE_HOST,
    ];
    for (const previous of credentials) {
      expect(decide({ flag: 'machine', previous })).toMatchObject({
        widening: holdsScopedFor(previous, ENDPOINT),
      });
    }
  });
});

describe('settledDecisionHolds', () => {
  type Inputs = Parameters<typeof decideAttachMode>[0];

  /**
   * Settle a decision from `before`, then put it again on `now`, the file as it
   * is when the write comes, with everything else as it was. `answered` is the
   * mode a question settled on, for a decision that was to ask.
   */
  function holdsAfter(
    before: Partial<Inputs>,
    now: CredentialFileRead,
    answered?: AttachmentMode,
  ): boolean {
    const inputs: Inputs = {
      flag: undefined,
      managed: null,
      previous: ABSENT,
      endpoint: ENDPOINT,
      interactive: true,
      ...before,
    };
    const settled = decideAttachMode(inputs);
    if (settled.kind === 'refuse') throw new Error('a refusal is never settled');
    const mode = settled.kind === 'use' ? settled.mode : answered;
    if (mode === undefined) throw new Error('a question settles on an answer');
    return settledDecisionHolds({ ...inputs, previous: now, settled, mode });
  }

  describe('when the file is as it was', () => {
    it.each<[string, Partial<Inputs>, CredentialFileRead]>([
      ['a kept scoped credential', { previous: SCOPED, interactive: false }, SCOPED],
      ['a kept machine-wide credential', { previous: MACHINE }, MACHINE],
      ['no file and no terminal', { previous: ABSENT, interactive: false }, ABSENT],
      [
        'a flag over a file that cannot be read',
        { flag: 'scoped', previous: UNREADABLE },
        UNREADABLE,
      ],
    ])('holds for %s', (_name, before, now) => {
      expect(holdsAfter(before, now)).toBe(true);
    });

    it('holds for a question answered either way', () => {
      expect(holdsAfter({ previous: ABSENT }, ABSENT, 'scoped')).toBe(true);
      expect(holdsAfter({ previous: ABSENT }, ABSENT, 'machine')).toBe(true);
    });
  });

  describe('when the file has changed', () => {
    it('does not hold if the decision would now refuse', () => {
      // No terminal and no flag: a file that cannot be read, or a personal
      // device for another endpoint, stops the run instead of widening it.
      expect(holdsAfter({ previous: ABSENT, interactive: false }, UNREADABLE)).toBe(false);
      expect(holdsAfter({ previous: ABSENT, interactive: false }, SCOPED_ELSEWHERE)).toBe(false);
    });

    it('does not hold if the decision would now ask where it did not', () => {
      expect(holdsAfter({ previous: MACHINE }, UNREADABLE)).toBe(false);
      // A personal device detached in the meantime leaves nothing to keep.
      expect(holdsAfter({ previous: SCOPED }, ABSENT)).toBe(false);
    });

    it('holds if the decision was to ask and still is, whatever the file now is', () => {
      expect(holdsAfter({ previous: ABSENT }, MACHINE_ELSEWHERE, 'scoped')).toBe(true);
      expect(holdsAfter({ previous: ABSENT }, UNREADABLE, 'machine')).toBe(true);
    });

    it('does not hold if the settled mode is not the mode the file now keeps', () => {
      expect(holdsAfter({ previous: MACHINE }, SCOPED)).toBe(false);
      expect(holdsAfter({ previous: SCOPED, interactive: false }, MACHINE)).toBe(false);
    });

    it('does not hold if a question was answered against a mode the file now keeps', () => {
      expect(holdsAfter({ previous: ABSENT }, SCOPED, 'machine')).toBe(false);
      expect(holdsAfter({ previous: ABSENT }, MACHINE, 'scoped')).toBe(false);
    });

    it('holds if the answered mode is the one the file now keeps', () => {
      expect(holdsAfter({ previous: ABSENT }, MACHINE, 'machine')).toBe(true);
      expect(holdsAfter({ previous: ABSENT }, SCOPED, 'scoped')).toBe(true);
    });

    it('applies the flag again to the file as it is, so a flag still decides', () => {
      expect(holdsAfter({ flag: 'machine', previous: MACHINE }, UNREADABLE)).toBe(true);
      expect(holdsAfter({ flag: 'scoped', previous: MACHINE }, SCOPED_ELSEWHERE)).toBe(true);
    });
  });

  describe('a widening', () => {
    it('does not hold if a personal device for this endpoint appeared where none was agreed to', () => {
      expect(holdsAfter({ flag: 'machine', previous: ABSENT }, SCOPED)).toBe(false);
      expect(holdsAfter({ flag: 'machine', previous: MACHINE }, SCOPED)).toBe(false);
    });

    it('does not hold under an administrator either, where it asks nobody', () => {
      expect(holdsAfter({ managed: MANAGED, previous: ABSENT }, SCOPED)).toBe(false);
    });

    it('holds if the widening was agreed to and is still there', () => {
      expect(holdsAfter({ flag: 'machine', previous: SCOPED }, SCOPED)).toBe(true);
      expect(holdsAfter({ managed: MANAGED, previous: SCOPED }, SCOPED)).toBe(true);
    });

    it('holds if the widening was agreed to and has since gone away', () => {
      // Detached, or already machine-wide: what is written still sends no more
      // than was agreed to.
      expect(holdsAfter({ flag: 'machine', previous: SCOPED }, ABSENT)).toBe(true);
      expect(holdsAfter({ flag: 'machine', previous: SCOPED }, MACHINE)).toBe(true);
      expect(holdsAfter({ managed: MANAGED, previous: SCOPED }, ABSENT)).toBe(true);
    });

    it('does not take an agreement made for a personal device elsewhere as one for this endpoint', () => {
      expect(holdsAfter({ flag: 'machine', previous: SCOPED_ELSEWHERE }, SCOPED)).toBe(false);
    });
  });
});
