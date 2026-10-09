import type { AttachmentMode, ConnectionRefusal, WorkspaceSettings } from '@akasecurity/schema';
import { defaultWorkspaceSettings, HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  decideAttachMode,
  holdsScopedFor,
  mayBePersonalDevice,
  settledDecisionHolds,
  writesSettingsFirst,
} from '../src/attach-mode.ts';
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
const scopedFor = (endpoint: string): CredentialFileRead => ({
  usable: true,
  credential: { specVersion: 2, mode: 'scoped', endpoint, apiKey: KEY },
});

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

  it('is the fact the decision calls a widening, for every credential spelled as the endpoint is', () => {
    // A machine-wide write over one of these widens exactly where this holds.
    // The decision also counts another spelling of the endpoint: see below.
    const credentials = [
      ABSENT,
      UNREADABLE,
      MISMATCHED,
      MACHINE,
      MACHINE_ELSEWHERE,
      SCOPED,
      SCOPED_ELSEWHERE,
    ];
    for (const previous of credentials) {
      expect(decide({ flag: 'machine', previous })).toMatchObject({
        widening: holdsScopedFor(previous, ENDPOINT),
      });
    }
  });
});

describe('decideAttachMode: a widening over another spelling of the endpoint', () => {
  it.each<[string, string, string]>([
    ['a trailing slash on the endpoint typed', ENDPOINT, `${ENDPOINT}/`],
    ['a trailing slash on the endpoint held', `${ENDPOINT}/`, ENDPOINT],
    ['a host in another case', 'https://AKA.example.com', ENDPOINT],
    ['a host with a trailing dot', 'https://aka.example.com.', ENDPOINT],
    ['the default port spelled out', 'https://aka.example.com:443', ENDPOINT],
    [
      'a path in another case, with a trailing slash',
      `${ENDPOINT}/Gateway/`,
      `${ENDPOINT}/gateway`,
    ],
  ])('calls --machine a widening over %s, which holdsScopedFor does not', (_name, held, typed) => {
    const previous = scopedFor(held);
    expect(decide({ flag: 'machine', previous, endpoint: typed })).toEqual({
      kind: 'use',
      mode: 'machine',
      widening: true,
      why: 'flag',
    });
    expect(decide({ managed: MANAGED, previous, endpoint: typed })).toMatchObject({
      widening: true,
    });
    expect(holdsScopedFor(previous, typed)).toBe(false);
  });

  it.each<[string, string]>([
    ['another port', 'https://aka.example.com:8443'],
    ['another path', `${ENDPOINT}/other`],
    ['another scheme', 'http://aka.example.com'],
    ['another host', OTHER_ENDPOINT],
  ])('does not call --machine a widening over a personal device on %s', (_name, held) => {
    expect(decide({ flag: 'machine', previous: scopedFor(held) })).toMatchObject({
      widening: false,
    });
  });

  it('does not take a machine-wide credential in another spelling for a widening', () => {
    const previous: CredentialFileRead = {
      usable: true,
      credential: { specVersion: 1, endpoint: `${ENDPOINT}/`, apiKey: KEY },
    };
    expect(decide({ flag: 'machine', previous })).toMatchObject({ widening: false });
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

    it('does not hold if a personal device for another spelling of this endpoint appeared where none was agreed to', () => {
      expect(holdsAfter({ flag: 'machine', previous: ABSENT }, SCOPED_TRAILING_SLASH)).toBe(false);
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

  describe('with the administrator answer read again after the wait', () => {
    const put = (before: Inputs, managedNow: ConnectionRefusal | null, mode: AttachmentMode) => {
      const settled = decideAttachMode(before);
      if (settled.kind === 'refuse') throw new Error('a refusal is never settled');
      return settledDecisionHolds({ ...before, managed: managedNow, settled, mode });
    };
    const quiet: Inputs = {
      flag: undefined,
      managed: MANAGED,
      previous: ABSENT,
      endpoint: ENDPOINT,
      interactive: false,
    };

    it('does not hold for a mode only the administrator settled, once they stop managing the machine', () => {
      expect(put({ ...quiet, previous: SCOPED }, MANAGED, 'machine')).toBe(true);
      expect(put({ ...quiet, previous: SCOPED }, null, 'machine')).toBe(false);
      expect(put({ ...quiet, interactive: true }, null, 'machine')).toBe(false);
    });

    it('holds where the decision is the same whoever manages the machine now', () => {
      expect(put(quiet, null, 'machine')).toBe(true);
      expect(put({ ...quiet, flag: 'machine', managed: null }, MANAGED, 'machine')).toBe(true);
    });

    // Under management a machine-wide flag over a personal device asks nobody:
    // the administrator decided. That is an agreement to the widening only while
    // they still manage the machine when the decision is put again.
    describe('an agreement to widen that only the administrator gave', () => {
      /** The decision settled from `before`, put again on a different file with the same administrator. */
      const putOnFile = (before: Inputs, now: CredentialFileRead): boolean => {
        const settled = decideAttachMode(before);
        if (settled.kind === 'refuse') throw new Error('a refusal is never settled');
        return settledDecisionHolds({ ...before, previous: now, settled, mode: 'machine' });
      };
      const widening: Inputs = { ...quiet, flag: 'machine', previous: SCOPED };

      it('does not count once they stop managing the machine and a terminal would ask', () => {
        expect(put({ ...widening, interactive: true }, null, 'machine')).toBe(false);
        expect(
          put({ ...widening, interactive: true, previous: SCOPED_TRAILING_SLASH }, null, 'machine'),
        ).toBe(false);
      });

      it('counts while they still manage the machine', () => {
        expect(put({ ...widening, interactive: true }, MANAGED, 'machine')).toBe(true);
        expect(put(widening, MANAGED, 'machine')).toBe(true);
      });

      it('turns on the administrator answer at the re-read and on nothing else', () => {
        // One settled decision put twice: only whether the machine is still managed then differs.
        const settledUnderManagement: Inputs = { ...widening, interactive: true };
        expect(put(settledUnderManagement, MANAGED, 'machine')).toBe(true);
        expect(put(settledUnderManagement, null, 'machine')).toBe(false);
      });

      // Deliberate. The overlay names no administrator that can be checked: its organization
      // is an optional name, shown to the user and not verified. So an agreement given under
      // one administrator stands under another's, and what another could change that matters
      // here, the deployment or the name the connection is pinned to, is refused before this
      // is asked (managedAttachRefusal).
      it('counts under a different administrator, or one who names no organization', () => {
        const other: ConnectionRefusal = { reason: 'scoped-managed', organization: 'Other IT' };
        const nameless: ConnectionRefusal = { reason: 'scoped-managed' };
        expect(put({ ...widening, interactive: true }, other, 'machine')).toBe(true);
        expect(put({ ...widening, interactive: true }, nameless, 'machine')).toBe(true);
      });

      it('counts without a terminal once they stop, where the flag typed is the answer', () => {
        expect(put(widening, null, 'machine')).toBe(true);
      });

      it('is not needed once the widening has gone away', () => {
        expect(putOnFile({ ...widening, interactive: true }, ABSENT)).toBe(true);
        expect(putOnFile({ ...widening, interactive: true }, MACHINE)).toBe(true);
      });

      it('leaves an agreement a person gave alone, whoever manages the machine now', () => {
        const confirmed: Inputs = { ...widening, managed: null, interactive: true };
        expect(put(confirmed, null, 'machine')).toBe(true);
        expect(put(confirmed, MANAGED, 'machine')).toBe(true);
      });
    });
  });
});

// The order of an attach's two writes, shared by every surface that attaches a
// machine, so that each orders them by the same rule.

describe('mayBePersonalDevice', () => {
  it.each<[string, CredentialFileRead, boolean]>([
    ['a scoped credential for this endpoint', SCOPED, true],
    ['a scoped credential for another endpoint', SCOPED_ELSEWHERE, true],
    ['a machine-wide credential for this endpoint', MACHINE, false],
    ['a machine-wide credential for another endpoint', MACHINE_ELSEWHERE, false],
    ['no credential file', ABSENT, false],
    ['a file that is malformed', { usable: false, reason: 'malformed' }, true],
    ['a file that is unreadable', { usable: false, reason: 'unreadable' }, true],
    ['a file that is untrusted', { usable: false, reason: 'untrusted-file' }, true],
    ['a file that names an unsafe endpoint', { usable: false, reason: 'unsafe-endpoint' }, true],
    ['a file reported as an endpoint mismatch', MISMATCHED, true],
  ])('answers for %s', (_name, read, expected) => {
    expect(mayBePersonalDevice(read)).toBe(expected);
  });
});

describe('writesSettingsFirst', () => {
  const CONSENT = {
    acknowledgedAt: '2026-10-01T09:00:00.000Z',
    payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    endpoint: ENDPOINT,
  };
  const NOTHING: WorkspaceSettings = defaultWorkspaceSettings();
  const LIST: WorkspaceSettings = {
    ...NOTHING,
    attachmentScope: { endpoint: ENDPOINT, entries: [] },
  };
  const GRANT: WorkspaceSettings = { ...NOTHING, historySyncConsent: CONSENT };
  const BOTH: WorkspaceSettings = { ...LIST, historySyncConsent: CONSENT };

  it.each<[string, AttachmentMode, CredentialFileRead, WorkspaceSettings, boolean, boolean]>([
    [
      'machine-wide over a scoped credential for this endpoint',
      'machine',
      SCOPED,
      NOTHING,
      false,
      true,
    ],
    [
      'machine-wide over a scoped credential for another endpoint',
      'machine',
      SCOPED_ELSEWHERE,
      NOTHING,
      false,
      true,
    ],
    ['machine-wide over a file that cannot be read', 'machine', UNREADABLE, NOTHING, false, true],
    [
      'machine-wide over a file reported as an endpoint mismatch',
      'machine',
      MISMATCHED,
      NOTHING,
      false,
      true,
    ],
    ['machine-wide with no file and a list stored', 'machine', ABSENT, LIST, false, true],
    ['machine-wide with no file and a grant stored', 'machine', ABSENT, GRANT, false, true],
    ['machine-wide with no file and nothing stored', 'machine', ABSENT, NOTHING, false, false],
    [
      'machine-wide over a machine-wide credential, a list and a grant stored',
      'machine',
      MACHINE,
      BOTH,
      false,
      false,
    ],
    [
      'machine-wide over a machine-wide credential for another endpoint, a list stored',
      'machine',
      MACHINE_ELSEWHERE,
      LIST,
      false,
      false,
    ],
    ['scoped with no file, a list stored and not kept', 'scoped', ABSENT, LIST, false, true],
    ['scoped with no file, a grant stored and not kept', 'scoped', ABSENT, GRANT, false, true],
    [
      'scoped over a scoped credential, a list stored and not kept',
      'scoped',
      SCOPED,
      LIST,
      false,
      true,
    ],
    [
      'scoped over a file that cannot be read, a grant stored and not kept',
      'scoped',
      UNREADABLE,
      GRANT,
      false,
      true,
    ],
    [
      'scoped over a scoped credential, a list and a grant stored and kept',
      'scoped',
      SCOPED,
      BOTH,
      true,
      false,
    ],
    [
      'scoped over a machine-wide credential, a list and a grant stored and not kept',
      'scoped',
      MACHINE,
      BOTH,
      false,
      false,
    ],
    ['scoped with no file and nothing stored', 'scoped', ABSENT, NOTHING, false, false],
  ])('answers for a %s', (_name, mode, previous, stored, kept, expected) => {
    expect(writesSettingsFirst(mode, previous, stored, () => kept)).toBe(expected);
  });

  it('asks keepsList about the stored list itself', () => {
    const seen: unknown[] = [];
    writesSettingsFirst('scoped', SCOPED, LIST, (stored) => {
      seen.push(stored);
      return false;
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBe(LIST.attachmentScope);
  });

  it('asks keepsList nothing on a machine-wide attach', () => {
    const seen: unknown[] = [];
    for (const previous of [SCOPED, UNREADABLE, ABSENT, MACHINE]) {
      writesSettingsFirst('machine', previous, BOTH, (stored) => {
        seen.push(stored);
        return false;
      });
    }
    expect(seen).toEqual([]);
  });
});
