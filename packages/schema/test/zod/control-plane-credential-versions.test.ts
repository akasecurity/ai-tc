import { describe, expect, it } from 'vitest';

import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  AttachedCredential,
  AttachedCredentialAny,
  AttachedCredentialV1,
  AttachedCredentialV2,
  AttachmentMode,
  attachmentModeOf,
} from '../../src/zod/control-plane.ts';

// The two credential versions and the mode they record. A machine attachment
// keeps the v1 file byte-for-byte; a scoped one is a v2 file, which every build
// that predates the mode reads as malformed.
const ENDPOINT = 'https://cp.example';
const TEST_KEY = 'not-a-real-key';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const V1_RECORD = { specVersion: 1, endpoint: ENDPOINT, apiKey: TEST_KEY };
const V2_RECORD = { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: TEST_KEY };

describe('AttachedCredentialV1', () => {
  it('is the same schema object as AttachedCredential, the member v1 files parse as', () => {
    // `AttachedCredentialAny` dispatches a specVersion-1 file to this object, so
    // a machine-wide credential reads exactly as it did when the reader parsed
    // v1 alone. One object, not two copies, so the two names cannot drift apart.
    expect(AttachedCredentialV1).toBe(AttachedCredential);
  });

  it('stays at specVersion 1, so a machine attachment writes the file it always has', () => {
    expect(ATTACHED_CREDENTIAL_SPEC_VERSION).toBe(1);
    expect(AttachedCredentialV1.parse(V1_RECORD)).toEqual(V1_RECORD);
  });
});

describe('AttachedCredentialV2', () => {
  it('is specVersion 2 with mode scoped, minimal or full', () => {
    expect(ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION).toBe(2);
    expect(AttachedCredentialV2.parse(V2_RECORD)).toEqual(V2_RECORD);
    const full = { ...V2_RECORD, keyPrefix: 'abcd1234', mintedAt: MINTED_AT };
    expect(AttachedCredentialV2.parse(full)).toEqual(full);
  });

  it('applies the v1 member rules to every shared member', () => {
    const broken = [
      { endpoint: '' },
      { apiKey: '' },
      { keyPrefix: '' },
      { keyPrefix: 'x'.repeat(17) },
      { mintedAt: 'yesterday' },
    ];
    for (const patch of broken) {
      const label = JSON.stringify(patch);
      expect(AttachedCredentialV1.safeParse({ ...V1_RECORD, ...patch }).success, label).toBe(false);
      expect(AttachedCredentialV2.safeParse({ ...V2_RECORD, ...patch }).success, label).toBe(false);
    }
  });

  it('refuses a v2 record with no mode, a machine mode, or the v1 version', () => {
    const noMode = { specVersion: 2, endpoint: ENDPOINT, apiKey: TEST_KEY };
    expect(AttachedCredentialV2.safeParse(noMode).success).toBe(false);
    expect(AttachedCredentialV2.safeParse({ ...V2_RECORD, mode: 'machine' }).success).toBe(false);
    expect(AttachedCredentialV2.safeParse({ ...V2_RECORD, specVersion: 1 }).success).toBe(false);
  });
});

describe('AttachedCredentialAny', () => {
  it('parses both versions, dispatched on specVersion', () => {
    expect(AttachedCredentialAny.parse(V1_RECORD)).toEqual(V1_RECORD);
    expect(AttachedCredentialAny.parse(V2_RECORD)).toEqual(V2_RECORD);
  });

  it('refuses any other version, so a credential from a newer build still reads as malformed', () => {
    for (const specVersion of [0, 3, '1', undefined]) {
      expect(AttachedCredentialAny.safeParse({ ...V2_RECORD, specVersion }).success).toBe(false);
    }
  });

  // v1 stays non-strict, exactly as every installed build parses it, so an
  // unknown key is stripped and THIS SCHEMA reads a `{ specVersion: 1, mode:
  // 'scoped' }` record as machine-wide. Two things keep such a file from being
  // used: the writer, which writes a scoped attachment as v2, and the credential
  // file reader in @akasecurity/persistence, which refuses a v1 file that names a
  // mode after this parse (its credential suite pins that). Pinned so a change to
  // the parse is a decision.
  it('reads a v1 record that carries a stray mode as machine-wide', () => {
    const stray = AttachedCredentialAny.parse({ ...V1_RECORD, mode: 'scoped' });
    expect(stray).toEqual(V1_RECORD);
    expect(attachmentModeOf(stray)).toBe('machine');
  });
});

describe('attachmentModeOf', () => {
  it('reads v1 as machine and v2 as its own mode', () => {
    expect(attachmentModeOf(AttachedCredentialAny.parse(V1_RECORD))).toBe('machine');
    const v2 = AttachedCredentialV2.parse(V2_RECORD);
    expect(attachmentModeOf(v2)).toBe(v2.mode);
    expect(attachmentModeOf(v2)).toBe('scoped');
  });

  it('answers scoped, never machine, for a value that is not exactly a v1 record', () => {
    // A value that reached the helper without a parse must not read as
    // machine-wide, which is the direction that forwards more.
    expect(attachmentModeOf({ specVersion: 3 } as never)).toBe('scoped');
  });

  it('only ever names a mode in the AttachmentMode vocabulary', () => {
    expect(AttachmentMode.options).toEqual(['machine', 'scoped']);
    expect(AttachmentMode.options).toContain(AttachedCredentialV2.shape.mode.value);
  });
});

describe('registry ids on the credential shapes and the mode', () => {
  // An id registers a shape in Zod's global registry, and a consumer walking that
  // registry publishes it. These shapes describe a bearer credential.
  it('carries NO meta id on AttachedCredentialV1, AttachedCredentialV2, AttachedCredentialAny or AttachmentMode', () => {
    expect(AttachedCredentialV1.meta()?.id).toBeUndefined();
    expect(AttachedCredentialV2.meta()?.id).toBeUndefined();
    expect(AttachedCredentialAny.meta()?.id).toBeUndefined();
    expect(AttachmentMode.meta()?.id).toBeUndefined();
  });
});
