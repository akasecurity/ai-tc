import { writeFileSync } from 'node:fs';

import type { AttachedCredentialV1, ControlPlaneConnection } from '@akasecurity/schema';
import { AttachedCredentialV2 } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  controlPlaneCredentialPath,
  readControlPlaneCredential,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  writeControlPlaneCredential,
} from '../src/control-plane-credential.ts';
import { DATA_FILE_MODE } from '../src/paths.ts';
import { useTempStore } from './helpers/temp-store.ts';

// THE INVARIANT THIS FILE HOLDS: this reader accepts a scoped (specVersion 2)
// credential because every path that forwards what this machine recorded
// decides from the attachment's mode and enrolled scope before it sends — the
// attached gateway, the history drain, the Data Shares forward and the
// device-command channel's scan. The policy pull, the posture report and the
// command poll and ack send without a verdict, by design.
//
// A build that predates scoped attachments reads a v2 file as malformed and
// forwards nothing. That is a claim about a reader this file cannot import, so
// it lives in @akasecurity/plugin-sdk's frozen-reader suite, against a verbatim
// copy of that reader.
//
// Version 2 MEANS scoped. A v2 file without the mode, or naming another one, is
// refused rather than half-read as either kind, and so is any version no build
// has written. Version 1 means machine-wide and names no mode at all, so a v1
// file that carries a `mode` key is refused too.

// A home of its own per test. The store itself is never opened: only the
// credential file under its settings directory is read.
const store = useTempStore('aka-cpc-v2-');

const ENDPOINT = 'https://cp.example';
const CONNECTION: ControlPlaneConnection = {
  endpoint: ENDPOINT,
  attachedAt: '2026-10-01T00:00:00.000Z',
};
const KEY = 'not-a-real-key';
const MALFORMED = { usable: false, reason: 'malformed' } as const;

const MACHINE: AttachedCredentialV1 = { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY };
// Built THROUGH the live schema, so a fixture that is not a genuine v2 record
// throws here instead of passing a case about a shape no writer could emit.
const SCOPED_MINIMAL = AttachedCredentialV2.parse({
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
});
const SCOPED_FULL = AttachedCredentialV2.parse({
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
  keyPrefix: 'abcd1234',
  mintedAt: '2026-10-01T00:00:00.000Z',
});

/** A record no writer would emit, put where the reader looks, owner-only. */
function writeRawCredential(record: unknown): void {
  writeFileSync(controlPlaneCredentialPath(store.settingsDir), JSON.stringify(record, null, 2), {
    mode: DATA_FILE_MODE,
  });
}

/** Every reader this package exports refuses the file the same way. */
function expectEveryReaderRefuses(): void {
  expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual(MALFORMED);
  expect(readControlPlaneCredentialFile(store.settingsDir)).toEqual(MALFORMED);
  expect(readControlPlaneCredentialState(store.settingsDir, CONNECTION)).toEqual(MALFORMED);
  expect(readControlPlaneCredential(store.settingsDir, CONNECTION)).toBeNull();
}

describe('the credential reader accepts a scoped credential', () => {
  it('reads a machine (v1) credential exactly as before', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);

    expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual({
      usable: true,
      credential: MACHINE,
    });
    expect(readControlPlaneCredentialState(store.settingsDir, CONNECTION)).toEqual({
      usable: true,
    });
  });

  it.each([SCOPED_MINIMAL, SCOPED_FULL])(
    'reads a scoped (v2) credential as usable, with its mode intact (%#)',
    (scoped) => {
      // The mode is the attachment's whole answer to "what may leave this
      // machine", and every forwarder reads it off this value. A reader that
      // dropped it would hand them a credential they could not tell from v1.
      writeControlPlaneCredential(store.settingsDir, scoped);

      expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual({
        usable: true,
        credential: scoped,
      });
      expect(readControlPlaneCredential(store.settingsDir, CONNECTION)).toEqual(scoped);
    },
  );

  it('projects a scoped credential to the same bare { usable: true } as a machine one', () => {
    // The narrow state is rebuilt, never spread, so neither the key nor the
    // mode reaches a surface by way of a field added to the wide read.
    writeControlPlaneCredential(store.settingsDir, SCOPED_FULL);

    expect(readControlPlaneCredentialState(store.settingsDir, CONNECTION)).toEqual({
      usable: true,
    });
  });

  it('binds a scoped credential to the endpoint it was minted against, exactly as v1', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED_FULL);
    const elsewhere: ControlPlaneConnection = {
      ...CONNECTION,
      endpoint: 'https://cp.other.example',
    };

    expect(readControlPlaneCredentialFile(store.settingsDir, elsewhere)).toEqual({
      usable: false,
      reason: 'endpoint-mismatch',
      credentialEndpoint: ENDPOINT,
      settingsEndpoint: 'https://cp.other.example',
    });
    expect(readControlPlaneCredential(store.settingsDir, elsewhere)).toBeNull();
  });

  it('refuses a scoped credential for an endpoint it will not present a key to', () => {
    // The writer refuses this endpoint, so the file is written raw, as a hand
    // edit would leave it. A scoped file passes the same gate a v1 file does.
    writeRawCredential({ ...SCOPED_MINIMAL, endpoint: 'http://cp.example' });

    expect(readControlPlaneCredentialFile(store.settingsDir)).toEqual({
      usable: false,
      reason: 'unsafe-endpoint',
    });
  });
});

describe('the credential reader refuses a credential it cannot place', () => {
  it.each([
    ['no mode', { specVersion: 2, endpoint: ENDPOINT, apiKey: KEY }],
    ['a machine mode', { specVersion: 2, mode: 'machine', endpoint: ENDPOINT, apiKey: KEY }],
    ['an unknown mode', { specVersion: 2, mode: 'everything', endpoint: ENDPOINT, apiKey: KEY }],
  ])('reads a version-2 file with %s as malformed', (_label, record) => {
    // Version 2 MEANS scoped. Half-reading this as either kind would be
    // guessing which side of the scope to fail on.
    writeRawCredential(record);
    expectEveryReaderRefuses();
  });

  it('reads a specVersion no build has written as malformed', () => {
    writeRawCredential({ ...SCOPED_MINIMAL, specVersion: 3 });
    expectEveryReaderRefuses();
  });

  it.each([
    ['a scoped mode', { mode: 'scoped' }],
    ['a machine mode', { mode: 'machine' }],
    ['an unknown mode', { mode: 'everything' }],
    ['a null mode', { mode: null }],
  ])('reads a version-1 file with %s as malformed', (_label, mode) => {
    // Version 1 names no mode: a machine-wide attachment is the absence of one.
    // The version-1 shape is not strict, so parsing alone drops an unknown key
    // and would read this file as a usable machine-wide credential, forwarding
    // everything a machine that asked for scope was meant to keep. No writer
    // emits this record, so refusing it costs nothing.
    writeRawCredential({ specVersion: 1, endpoint: ENDPOINT, apiKey: KEY, ...mode });
    expectEveryReaderRefuses();
  });
});
