import type { AttachedCredentialV2 } from '@akasecurity/schema';
import { WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CredentialFileRead } from '../src/control-plane-credential.ts';
import { captureBackfillScope } from '../src/history-backfill.ts';

// `captureBackfillScope` is the key list the consent-time capture seed marks
// under, shared by the three places a grant is recorded. Pure: it takes the
// credential read and the settings the caller already holds and does no I/O.

const ENDPOINT = 'https://plane.example.test';
const AT = '2026-08-24T10:00:00.000Z';
const WORK = 'github.com/acme/work';
const OTHER = 'github.com/acme/another';

const settings = (scope: { endpoint: string; keys: readonly string[] } | undefined) =>
  WorkspaceSettings.parse({
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    ...(scope === undefined
      ? {}
      : {
          attachmentScope: {
            endpoint: scope.endpoint,
            entries: scope.keys.map((identity) => ({ kind: 'repo', identity, enrolledAt: AT })),
          },
        }),
  });

const machineRead: CredentialFileRead = {
  usable: true,
  credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: 'placeholder', mintedAt: AT },
};

// A scoped read, built directly rather than read from a file, so this suite
// does not depend on which credential shapes the reader accepts. It goes
// through `unknown`, the way the callers' own suites arm a scoped read.
const scopedRead = {
  usable: true,
  credential: {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: 'placeholder',
    mintedAt: AT,
  } satisfies AttachedCredentialV2,
} as unknown as CredentialFileRead;

describe('captureBackfillScope', () => {
  // A machine attachment's grant covers every capture, and a stored scope (left
  // by an earlier scoped attachment, or written by hand) does not narrow it.
  it('is no filter on a machine attachment, whatever scope is stored', () => {
    expect(captureBackfillScope(machineRead, settings({ endpoint: ENDPOINT, keys: [WORK] }))).toBe(
      undefined,
    );
    expect(captureBackfillScope(machineRead, settings(undefined))).toBe(undefined);
  });

  it('is the enrolled keys, sorted, on a scoped attachment', () => {
    const scoped = settings({ endpoint: ENDPOINT, keys: [WORK, OTHER] });

    expect(captureBackfillScope(scopedRead, scoped)).toEqual([OTHER, WORK]);
  });

  // An empty list is a real answer that marks nothing, never "no filter".
  it('is an empty list, not no filter, when a scoped attachment has nothing enrolled', () => {
    expect(captureBackfillScope(scopedRead, settings(undefined))).toEqual([]);
  });

  it('counts only the scope recorded for the connection endpoint', () => {
    const foreign = settings({ endpoint: 'https://elsewhere.example.test', keys: [WORK] });

    expect(captureBackfillScope(scopedRead, foreign)).toEqual([]);
  });

  // Marking is not sending: with no readable credential there is no mode to
  // scope by, and the drain cannot run until there is one, at which point its
  // own read applies the scope.
  it('is no filter when the credential cannot be read', () => {
    const enrolled = settings({ endpoint: ENDPOINT, keys: [WORK] });

    expect(captureBackfillScope({ usable: false, reason: 'absent' }, enrolled)).toBe(undefined);
    expect(captureBackfillScope({ usable: false, reason: 'malformed' }, enrolled)).toBe(undefined);
  });

  it('is no filter when there is no connection to read a credential for', () => {
    const detached = WorkspaceSettings.parse({});

    expect(captureBackfillScope(undefined, detached)).toBe(undefined);
    expect(captureBackfillScope(scopedRead, detached)).toBe(undefined);
  });
});
