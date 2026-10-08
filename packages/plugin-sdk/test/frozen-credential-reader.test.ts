import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  controlPlaneCredentialPath,
  readControlPlaneCredentialFile,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedCredentialAny } from '@akasecurity/schema';
import { AttachedCredential, AttachedCredentialV2 } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  FrozenAttachedCredential,
  frozenClassifyCredential,
} from './helpers/frozen-credential-reader-8bfc99c4.ts';

// What a build that predates scoped attachments makes of the credential files
// this build writes.
//
// The property is not "a literal 1 refuses a 2" — a copy that only asserted
// that would pass while proving nothing. It is: whatever the REAL writer puts
// on disk for a scoped attachment, the SHIPPED reader classifies as malformed,
// so an older build on a scoped machine falls back to standalone and forwards
// nothing. Each case writes through `writeControlPlaneCredential` and hands the
// exact bytes it left to the frozen reader. A writer that ever emitted a scoped
// credential as `{ specVersion: 1, mode: 'scoped' }` would fail here: the
// shipped schema strips unknown keys and would read it as machine-wide.

const ENDPOINT = 'https://aka.acme.test';
const KEY = 'not-a-real-key';
const OPTIONAL_FIELDS = [
  {},
  { keyPrefix: 'akp_test' },
  { mintedAt: '2026-10-01T09:00:00.000Z' },
  { keyPrefix: 'akp_test', mintedAt: '2026-10-01T09:00:00.000Z' },
];

// Built THROUGH the live schemas, so a fixture that is not a genuine credential
// of its version throws here rather than passing a case about a shape no
// writer could emit.
const SCOPED = OPTIONAL_FIELDS.map((extra) =>
  AttachedCredentialV2.parse({
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: KEY,
    ...extra,
  }),
);
const MACHINE = OPTIONAL_FIELDS.map((extra) =>
  AttachedCredential.parse({ specVersion: 1, endpoint: ENDPOINT, apiKey: KEY, ...extra }),
);

let settingsDir: string;

beforeEach(() => {
  settingsDir = mkdtempSync(join(tmpdir(), 'aka-frozen-reader-'));
});

afterEach(() => {
  rmSync(settingsDir, { recursive: true, force: true });
});

/** Write through the REAL writer, and hand back the exact bytes it left on disk. */
function writtenBytes(credential: AttachedCredentialAny): string {
  writeControlPlaneCredential(settingsDir, credential);
  return readFileSync(controlPlaneCredentialPath(settingsDir), 'utf8');
}

/** A schema's JSON Schema, minus the one keyword a deliberate `.strict()` may change. */
function shapeOf(schema: z.ZodType): Record<string, unknown> {
  const json: Record<string, unknown> = { ...z.toJSONSchema(schema) };
  delete json.additionalProperties;
  return json;
}

describe('the reader as it shipped before scoped attachments', () => {
  it.each(SCOPED)(
    'reads a scoped credential, as the writer emits it, as malformed (%#)',
    (credential) => {
      expect(frozenClassifyCredential(writtenBytes(credential))).toEqual({
        usable: false,
        reason: 'malformed',
      });
    },
  );

  it.each(MACHINE)('reads a machine credential exactly as this build does (%#)', (credential) => {
    // Machine-wide attachments are byte-identical across the change: the same
    // bytes, the same answer, from the reader that shipped and this one.
    const bytes = writtenBytes(credential);

    expect(readControlPlaneCredentialFile(settingsDir)).toEqual({ usable: true, credential });
    expect(frozenClassifyCredential(bytes)).toEqual({ usable: true, credential });
  });

  it('would read a scoped mode written at specVersion 1 as a MACHINE credential', () => {
    // Why a scoped attachment has its own version rather than a field on v1:
    // the shipped schema strips the key it does not know and forwards
    // everything. This pins that hazard, so the reason is on record next to
    // the cases that depend on it.
    const bytes = JSON.stringify({
      specVersion: 1,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: KEY,
    });

    expect(frozenClassifyCredential(bytes)).toEqual({
      usable: true,
      credential: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY },
    });
  });
});

describe('the same bytes through this build', () => {
  it.each(SCOPED)('reads a scoped credential as usable, mode intact (%#)', (credential) => {
    writtenBytes(credential);

    expect(readControlPlaneCredentialFile(settingsDir)).toEqual({ usable: true, credential });
  });
});

describe('the frozen copy', () => {
  it('still describes the live machine-wide member', () => {
    // If this fails, the live v1 schema moved. Re-decide whether the readers
    // already in the field still refuse what this build writes before changing
    // either side — and never by editing the frozen copy.
    expect(shapeOf(AttachedCredential)).toEqual(shapeOf(FrozenAttachedCredential));
  });
});

// What `aka attach --scoped` writes, byte for byte. The CLI's own suite proves
// its attach emits exactly these bytes (cli/test/commands/attach-write.test.ts),
// so the cases below are about the CLI's output, not a shape built here.
const CLI_SCOPED_BYTES = readFileSync(
  new URL('./fixtures/cli-scoped-credential-v2.json', import.meta.url),
  'utf8',
);

describe('what aka attach --scoped writes', () => {
  it('reads as malformed to the reader that shipped before scoped attachments', () => {
    expect(frozenClassifyCredential(CLI_SCOPED_BYTES)).toEqual({
      usable: false,
      reason: 'malformed',
    });
  });

  it('reads as a usable scoped credential through this build', () => {
    writeFileSync(controlPlaneCredentialPath(settingsDir), CLI_SCOPED_BYTES, { mode: 0o600 });

    expect(readControlPlaneCredentialFile(settingsDir)).toEqual({
      usable: true,
      credential: {
        specVersion: 2,
        endpoint: 'https://aka.example.com',
        apiKey: 'key-1',
        mintedAt: '2026-10-01T09:00:00.000Z',
        mode: 'scoped',
      },
    });
  });

  it('comes back as the same bytes when what the reader returned is written again', () => {
    // A failed re-attach rolls back by writing what this reader returned, so a
    // scoped machine whose re-attach fails keeps exactly the file it had.
    writeFileSync(controlPlaneCredentialPath(settingsDir), CLI_SCOPED_BYTES, { mode: 0o600 });
    const read = readControlPlaneCredentialFile(settingsDir);
    if (!read.usable) throw new Error(`expected a usable credential, got ${read.reason}`);

    expect(writtenBytes(read.credential)).toBe(CLI_SCOPED_BYTES);
  });
});
