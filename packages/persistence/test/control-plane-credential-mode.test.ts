import { readFileSync, rmSync, writeFileSync } from 'node:fs';

import type { AttachedCredentialAny, ControlPlaneConnection } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  controlPlaneCredentialPath,
  isScopedAttachment,
  readControlPlaneAttachmentMode,
  readControlPlaneCredentialFile,
  writeControlPlaneCredential,
} from '../src/control-plane-credential.ts';
import { DATA_FILE_MODE } from '../src/paths.ts';
import { expectNoEchoOf } from './helpers/no-echo.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The credential file in its two shapes: the scoped one (version 2) and the
// machine-wide one (version 1) the writer has always emitted. Three properties:
// the writer never emits a file its own reader calls malformed; a machine
// credential's bytes are the ones the writer produced before scoped attachments
// existed; and the mode can be read without holding the key.

const store = useTempStore('aka-cpc-mode-');

const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
// A plain word standing in for the key. The fixture was captured with it.
const KEY = 'placeholder';
const CONNECTION: ControlPlaneConnection = { endpoint: ENDPOINT, attachedAt: MINTED_AT };

/**
 * Captured from the writer as it stood before scoped attachments could be
 * written, for exactly MACHINE below. Never regenerate it from the current
 * writer: a fixture made by the code it pins pins nothing.
 */
const FIXTURE = new URL('./fixtures/machine-credential-v1.json', import.meta.url);

/** The CLI's and the dashboard's machine credential: these members, in this order. */
const MACHINE: AttachedCredentialAny = {
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey: KEY,
  mintedAt: MINTED_AT,
};

const SCOPED: AttachedCredentialAny = {
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: KEY,
  mintedAt: MINTED_AT,
};

const credentialFile = (): string => controlPlaneCredentialPath(store.settingsDir);

/** A record put where the reader looks, as a hand edit or another build would. */
function writeRaw(record: unknown): void {
  writeFileSync(credentialFile(), JSON.stringify(record, null, 2), { mode: DATA_FILE_MODE });
}

/** Hand the writer something its type does not allow, as a cast would. */
function writeUnchecked(record: unknown): void {
  writeControlPlaneCredential(store.settingsDir, record as AttachedCredentialAny);
}

// Every object here is one the reader reads back as `malformed`. The writer
// must refuse each of them, and the second `it.each` proves the reader really
// does refuse each, so the two halves cannot drift apart unnoticed.
const UNREADABLE: [string, unknown][] = [
  ['a version-1 credential that names a scoped mode', { ...MACHINE, mode: 'scoped' }],
  ['a version-1 credential that names a machine mode', { ...MACHINE, mode: 'machine' }],
  ['a version-2 credential with no mode', { specVersion: 2, endpoint: ENDPOINT, apiKey: KEY }],
  [
    'a version-2 credential naming a machine mode',
    { specVersion: 2, mode: 'machine', endpoint: ENDPOINT, apiKey: KEY },
  ],
  ['a version no build writes', { ...SCOPED, specVersion: 3 }],
  ['an empty key', { ...MACHINE, apiKey: '' }],
  ['a key prefix longer than sixteen characters', { ...MACHINE, keyPrefix: 'x'.repeat(17) }],
  ['a mint time that is not a timestamp', { ...MACHINE, mintedAt: 'yesterday' }],
];

describe('a machine credential is written byte for byte as before', () => {
  it('writes the bytes captured from the writer before scoped attachments existed', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);

    const written = readFileSync(credentialFile());
    const fixture = readFileSync(FIXTURE);
    // The string comparison first, for a readable diff; the byte comparison is
    // the claim.
    expect(written.toString('utf8')).toBe(fixture.toString('utf8'));
    expect(Buffer.compare(written, fixture)).toBe(0);
  });

  it('serialises the object it was handed, in its own key order, not the parse output', () => {
    const reordered = {
      apiKey: KEY,
      mintedAt: MINTED_AT,
      endpoint: ENDPOINT,
      specVersion: 1,
    } as const;
    writeControlPlaneCredential(store.settingsDir, reordered);

    expect(readFileSync(credentialFile(), 'utf8')).toBe(`${JSON.stringify(reordered, null, 2)}\n`);
  });
});

describe('writeControlPlaneCredential refuses what its reader would refuse', () => {
  it.each(UNREADABLE)('refuses %s, and writes nothing', (_label, record) => {
    expect(() => {
      writeUnchecked(record);
    }).toThrow(/is not a credential this build would read back/);
    expect(readControlPlaneCredentialFile(store.settingsDir)).toEqual({
      usable: false,
      reason: 'absent',
    });
  });

  it.each(UNREADABLE)(
    'is right to refuse %s: the reader calls that file malformed',
    (_l, record) => {
      writeRaw(record);
      expect(readControlPlaneCredentialFile(store.settingsDir)).toEqual({
        usable: false,
        reason: 'malformed',
      });
    },
  );

  it('leaves the credential already on disk untouched when it refuses', () => {
    // A failed rotation must not cost the machine the credential it has.
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    const before = readFileSync(credentialFile(), 'utf8');

    expect(() => {
      writeUnchecked({ ...MACHINE, mode: 'scoped' });
    }).toThrow();
    expect(readFileSync(credentialFile(), 'utf8')).toBe(before);
  });

  it('names the deployment in its refusal and never the key', () => {
    const key = 'placeholder-for-the-echo-check';
    let message: string | undefined;
    try {
      writeUnchecked({ ...MACHINE, apiKey: key, mode: 'scoped' });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    // Positive control on the same bytes first: a refusal that said nothing
    // would pass any "does not contain" check.
    expect(message).toContain('https://cp.example');
    expectNoEchoOf(message, key);
  });

  it('still refuses an endpoint it will not present a key to, with the reason it always gave', () => {
    expect(() => {
      writeControlPlaneCredential(store.settingsDir, { ...MACHINE, endpoint: 'http://cp.example' });
    }).toThrow(/non-HTTPS endpoint/);
  });

  it.each<[string, AttachedCredentialAny]>([
    ['a machine credential', MACHINE],
    ['a scoped credential', SCOPED],
    ['a scoped credential with a key prefix', { ...SCOPED, keyPrefix: 'prefix' }],
  ])('writes %s, and its own reader reads it back usable', (_label, credential) => {
    writeControlPlaneCredential(store.settingsDir, credential);

    expect(readControlPlaneCredentialFile(store.settingsDir, CONNECTION)).toEqual({
      usable: true,
      credential,
    });
  });
});

describe('readControlPlaneAttachmentMode', () => {
  it('is machine for a version-1 credential for this deployment', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBe('machine');
  });

  it('is scoped for a version-2 credential for this deployment', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBe('scoped');
  });

  it('is undefined with no connection, whatever the file holds', () => {
    // No descriptor means no attachment for the mode to describe; a credential
    // left behind is not one.
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(readControlPlaneAttachmentMode(store.settingsDir, undefined)).toBeUndefined();
  });

  it('is undefined for a credential bound to another deployment', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    const elsewhere: ControlPlaneConnection = {
      ...CONNECTION,
      endpoint: 'https://cp.other.example',
    };
    expect(readControlPlaneAttachmentMode(store.settingsDir, elsewhere)).toBeUndefined();
  });

  it('is undefined with no credential file', () => {
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBeUndefined();
  });

  it('is undefined for a version-1 file that names a mode', () => {
    writeRaw({ ...MACHINE, mode: 'scoped' });
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBeUndefined();
  });

  it('is undefined for a file that is not JSON', () => {
    writeFileSync(credentialFile(), 'not json at all', { mode: DATA_FILE_MODE });
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBeUndefined();
  });

  it('is undefined, and does not throw, where a regular file stands in for the settings directory', () => {
    // The file read can throw rather than answer: looking inside a path whose
    // directory is really a file raises ENOTDIR. The answer must be total: a
    // throw would reach the caller instead of reading as no known mode.
    rmSync(store.settingsDir, { recursive: true, force: true });
    writeFileSync(store.settingsDir, 'this is a file, not a directory');

    expect(() => readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).not.toThrow();
    expect(readControlPlaneAttachmentMode(store.settingsDir, CONNECTION)).toBeUndefined();
  });
});

describe('isScopedAttachment', () => {
  it('is true for a version-2 credential for this deployment', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(isScopedAttachment(store.settingsDir, CONNECTION)).toBe(true);
  });

  it('is false for a version-1 (machine) credential for this deployment', () => {
    writeControlPlaneCredential(store.settingsDir, MACHINE);
    expect(isScopedAttachment(store.settingsDir, CONNECTION)).toBe(false);
  });

  it('is false with no connection, whatever the file holds', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(isScopedAttachment(store.settingsDir, undefined)).toBe(false);
  });

  it('is false for a scoped credential bound to another deployment', () => {
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    const elsewhere: ControlPlaneConnection = {
      ...CONNECTION,
      endpoint: 'https://cp.other.example',
    };
    expect(isScopedAttachment(store.settingsDir, elsewhere)).toBe(false);
  });

  it('is false with no credential file', () => {
    expect(isScopedAttachment(store.settingsDir, CONNECTION)).toBe(false);
  });

  it('is false, and does not throw, where a regular file stands in for the settings directory', () => {
    rmSync(store.settingsDir, { recursive: true, force: true });
    writeFileSync(store.settingsDir, 'this is a file, not a directory');

    expect(() => isScopedAttachment(store.settingsDir, CONNECTION)).not.toThrow();
    expect(isScopedAttachment(store.settingsDir, CONNECTION)).toBe(false);
  });
});
