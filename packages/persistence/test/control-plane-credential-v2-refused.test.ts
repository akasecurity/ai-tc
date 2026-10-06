import { writeFileSync } from 'node:fs';

import type { ControlPlaneConnection } from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  AttachedCredentialAny,
  AttachedCredentialV1,
  AttachedCredentialV2,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  controlPlaneCredentialPath,
  readControlPlaneCredential,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
} from '../src/control-plane-credential.ts';
import { DATA_FILE_MODE } from '../src/paths.ts';
import { useTempStore } from './helpers/temp-store.ts';

// THE INVARIANT THIS FILE HOLDS: a build may read a scoped (specVersion 2)
// credential as usable only if every path that forwards to the control plane
// also consults the attachment mode.
//
// @akasecurity/schema defines the v2 shape before any forward path consults the
// mode, so this reader must keep parsing v1 alone and call a v2 file
// `malformed`. Every forwarder treats an unusable credential as not attached and
// falls back to standalone, so such a build forwards nothing on a scoped
// machine, rather than everything.
//
// The change that widens the reader to `AttachedCredentialAny` is the change
// that rewrites this file, and it must also be the change that makes the last
// forward path consult the mode. Turning this file green by any other route —
// editing an expectation, deleting a case — ships a build that forwards
// everything a scoped machine captures.

// A home of its own per test. The store itself is never opened: only the
// credential file under its settings directory is read.
const store = useTempStore('aka-cred-v2-');

const ENDPOINT = 'https://cp.example';
const CONNECTION: ControlPlaneConnection = {
  endpoint: ENDPOINT,
  attachedAt: '2026-10-01T00:00:00.000Z',
};
const TEST_KEY = 'not-a-real-key';
const MALFORMED = { usable: false, reason: 'malformed' };

/** Put `record` where the reader looks, as indented JSON, owner-only. */
function writeCredentialFile(record: unknown): void {
  writeFileSync(controlPlaneCredentialPath(store.settingsDir), JSON.stringify(record, null, 2), {
    mode: DATA_FILE_MODE,
  });
}

/** Every reader this package exports must refuse the file the same way. */
function expectEveryReaderRefuses(): void {
  expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual(MALFORMED);
  expect(readControlPlaneCredentialFile(store.settingsDir)).toEqual(MALFORMED);
  expect(readControlPlaneCredentialState(store.settingsDir, CONNECTION)).toEqual(MALFORMED);
  expect(readControlPlaneCredential(store.settingsDir, CONNECTION)).toBeNull();
}

describe('the credential reader stays v1-only until every forward path enforces scope', () => {
  // The control: the same harness writes a v1 file and the reader accepts it, so
  // the refusals below are about the shape and nothing else.
  it('reads a v1 credential written this way as usable', () => {
    const v1 = AttachedCredentialV1.parse({
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
    });
    writeCredentialFile(v1);
    expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual({
      usable: true,
      credential: v1,
    });
  });

  it('reads a minimal v2 (scoped) credential as malformed', () => {
    const v2 = AttachedCredentialV2.parse({
      specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
    });
    // A real v2 record: the union a widened reader would use accepts it.
    expect(AttachedCredentialAny.parse(v2)).toEqual(v2);
    writeCredentialFile(v2);
    expectEveryReaderRefuses();
  });

  it('reads a full v2 (scoped) credential as malformed', () => {
    const v2 = AttachedCredentialV2.parse({
      specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      keyPrefix: 'abcd1234',
      mintedAt: '2026-10-01T00:00:00.000Z',
    });
    expect(AttachedCredentialAny.parse(v2)).toEqual(v2);
    writeCredentialFile(v2);
    expectEveryReaderRefuses();
  });
});
