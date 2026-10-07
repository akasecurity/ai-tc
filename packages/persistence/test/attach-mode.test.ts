import type { ConnectionRefusal } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { decideAttachMode } from '../src/attach-mode.ts';
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
