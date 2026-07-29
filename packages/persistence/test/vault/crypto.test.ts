import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  base32Decode,
  base32Encode,
  bindingInput,
  decodeKeyVersion,
  deriveSubkeys,
  encodeKeyVersion,
  formatPointer,
  NONCE_BYTES,
  open,
  POINTER_ID_BYTES,
  seal,
  signPointer,
  TAG_BYTES,
  verifyPointerTag,
} from '../../src/vault/crypto.ts';

const master = Buffer.alloc(32, 7);
const keys = deriveSubkeys(master);
const pointerId = Buffer.alloc(POINTER_ID_BYTES, 3);
const nonce = Buffer.alloc(NONCE_BYTES, 9);

describe('base32', () => {
  it('round-trips arbitrary bytes', () => {
    for (const length of [1, 2, 5, 10, 16, 31, 32]) {
      const bytes = randomBytes(length);
      expect(base32Decode(base32Encode(bytes)).equals(bytes)).toBe(true);
    }
  });

  it('emits only alphabet characters', () => {
    expect(base32Encode(randomBytes(64))).toMatch(/^[A-Z2-7]+$/);
  });

  it('produces the widths the pointer grammar assumes', () => {
    expect(base32Encode(Buffer.alloc(POINTER_ID_BYTES)).length).toBe(26);
    expect(base32Encode(Buffer.alloc(TAG_BYTES)).length).toBe(16);
    expect(base32Encode(Buffer.alloc(1)).length).toBe(2);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base32Decode('AB0C')).toThrow();
    expect(() => base32Decode('abc')).toThrow();
  });
});

describe('key version encoding', () => {
  it('round-trips', () => {
    for (const version of [1, 2, 255, 256, 65535, 16777216, 0xffffffff]) {
      expect(decodeKeyVersion(encodeKeyVersion(version))).toBe(version);
    }
  });

  it('stays minimal-width for the common case', () => {
    expect(encodeKeyVersion(1)).toBe('AE');
  });

  it('rejects out-of-range versions', () => {
    expect(() => encodeKeyVersion(0)).toThrow();
    expect(() => encodeKeyVersion(-1)).toThrow();
    expect(() => encodeKeyVersion(1.5)).toThrow();
    expect(() => encodeKeyVersion(0x1_0000_0000)).toThrow();
  });
});

describe('subkey derivation', () => {
  it('is deterministic for the same master key', () => {
    const again = deriveSubkeys(master);
    expect(again.enc.equals(keys.enc)).toBe(true);
    expect(again.sign.equals(keys.sign)).toBe(true);
  });

  // Signing and encryption must never share key bytes.
  it('separates the encryption and signing subkeys', () => {
    expect(keys.enc.equals(keys.sign)).toBe(false);
  });

  it('yields different subkeys for different master keys', () => {
    const other = deriveSubkeys(Buffer.alloc(32, 8));
    expect(other.enc.equals(keys.enc)).toBe(false);
    expect(other.sign.equals(keys.sign)).toBe(false);
  });
});

describe('bindingInput', () => {
  // The reason the encoding is fixed-width: with variable-width numerics,
  // (key_version=1, category='2secret') and (key_version=12, category='secret')
  // would collide — letting a pointer be relabelled into another category and
  // confusing which key epoch to verify under.
  it('is injective across the key-version/category boundary', () => {
    const a = bindingInput(1, pointerId, '2secret');
    const b = bindingInput(12, pointerId, 'secret');
    expect(a.equals(b)).toBe(false);
  });

  it('produces distinct tags for that ambiguity pair', () => {
    const a = signPointer(keys.sign, 1, pointerId, '2secret');
    const b = signPointer(keys.sign, 12, pointerId, 'secret');
    expect(a.equals(b)).toBe(false);
  });

  it('neither half of the ambiguity pair verifies against the other', () => {
    const a = signPointer(keys.sign, 1, pointerId, '2secret');
    expect(verifyPointerTag(keys.sign, 12, pointerId, 'secret', a)).toBe(false);
  });

  it('changes with every field', () => {
    const base = bindingInput(1, pointerId, 'secret');
    expect(bindingInput(2, pointerId, 'secret').equals(base)).toBe(false);
    expect(bindingInput(1, Buffer.alloc(POINTER_ID_BYTES, 4), 'secret').equals(base)).toBe(false);
    expect(bindingInput(1, pointerId, 'pii').equals(base)).toBe(false);
    expect(bindingInput(1, pointerId, 'secret', 99).equals(base)).toBe(false);
  });

  it('rejects a wrong-width pointer id', () => {
    expect(() => bindingInput(1, Buffer.alloc(15), 'secret')).toThrow();
    expect(() => bindingInput(1, Buffer.alloc(17), 'secret')).toThrow();
  });
});

describe('AEAD seal/open', () => {
  const aad = bindingInput(1, pointerId, 'secret');

  it('round-trips a value byte-for-byte', () => {
    for (const raw of ['AKIAIOSFODNN7EXAMPLE', '', 'ünïcøde ✓ 秘密', 'x'.repeat(4096)]) {
      const sealed = seal(keys.enc, raw, aad, nonce);
      expect(open(keys.enc, sealed, aad)).toBe(raw);
    }
  });

  it('does not leave the plaintext in the ciphertext', () => {
    const raw = 'AKIAIOSFODNN7EXAMPLE';
    const sealed = seal(keys.enc, raw, aad, nonce);
    expect(sealed.ciphertext.toString('utf8')).not.toContain(raw);
    expect(sealed.ciphertext.toString('base64')).not.toContain(raw);
  });

  // Ciphertext copied under a different pointer must fail to open, rather than
  // yielding some other row's plaintext.
  it('refuses ciphertext replayed under another pointer', () => {
    const sealed = seal(keys.enc, 'secret-value', aad, nonce);
    const otherPointer = bindingInput(1, Buffer.alloc(POINTER_ID_BYTES, 4), 'secret');
    expect(open(keys.enc, sealed, otherPointer)).toBeNull();
  });

  it('refuses ciphertext replayed under another key epoch', () => {
    const sealed = seal(keys.enc, 'secret-value', aad, nonce);
    expect(open(keys.enc, sealed, bindingInput(2, pointerId, 'secret'))).toBeNull();
  });

  it('refuses ciphertext relabelled into another category', () => {
    const sealed = seal(keys.enc, 'secret-value', aad, nonce);
    expect(open(keys.enc, sealed, bindingInput(1, pointerId, 'pii'))).toBeNull();
  });

  it('refuses a tampered auth tag, ciphertext, or nonce', () => {
    const sealed = seal(keys.enc, 'secret-value', aad, nonce);
    const bend = (buf: Buffer): Buffer => {
      const copy = Buffer.from(buf);
      copy.writeUInt8(copy.readUInt8(0) ^ 0xff, 0);
      return copy;
    };
    expect(open(keys.enc, { ...sealed, authTag: bend(sealed.authTag) }, aad)).toBeNull();
    expect(open(keys.enc, { ...sealed, ciphertext: bend(sealed.ciphertext) }, aad)).toBeNull();
    expect(open(keys.enc, { ...sealed, nonce: bend(sealed.nonce) }, aad)).toBeNull();
  });

  it('refuses the wrong key', () => {
    const sealed = seal(keys.enc, 'secret-value', aad, nonce);
    expect(open(deriveSubkeys(Buffer.alloc(32, 8)).enc, sealed, aad)).toBeNull();
  });

  // A caller that cannot open a row degrades to "unavailable"; a throw here
  // would have to be caught at every call site to stay inside a hook's
  // fail-open boundary.
  it('returns null rather than throwing on garbage input', () => {
    expect(
      open(keys.enc, { ciphertext: randomBytes(16), nonce, authTag: randomBytes(16) }, aad),
    ).toBeNull();
  });
});

describe('pointer tag', () => {
  it('verifies a tag it just produced', () => {
    const tag = signPointer(keys.sign, 1, pointerId, 'secret');
    expect(tag.length).toBe(TAG_BYTES);
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'secret', tag)).toBe(true);
  });

  it('rejects a relabelled category', () => {
    const tag = signPointer(keys.sign, 1, pointerId, 'secret');
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'pii', tag)).toBe(false);
  });

  it('rejects a different key epoch, pointer id, or signing key', () => {
    const tag = signPointer(keys.sign, 1, pointerId, 'secret');
    expect(verifyPointerTag(keys.sign, 2, pointerId, 'secret', tag)).toBe(false);
    expect(verifyPointerTag(keys.sign, 1, Buffer.alloc(POINTER_ID_BYTES, 4), 'secret', tag)).toBe(
      false,
    );
    expect(
      verifyPointerTag(deriveSubkeys(Buffer.alloc(32, 8)).sign, 1, pointerId, 'secret', tag),
    ).toBe(false);
  });

  it('rejects a tampered tag', () => {
    const tag = Buffer.from(signPointer(keys.sign, 1, pointerId, 'secret'));
    tag.writeUInt8(tag.readUInt8(0) ^ 0xff, 0);
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'secret', tag)).toBe(false);
  });

  it('rejects a wrong-length tag without throwing', () => {
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'secret', Buffer.alloc(9))).toBe(false);
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'secret', Buffer.alloc(0))).toBe(false);
    expect(verifyPointerTag(keys.sign, 1, pointerId, 'secret', Buffer.alloc(32))).toBe(false);
  });

  // A guessed or incremented pointer id cannot be paired with a valid tag.
  it('rejects a fabricated pointer', () => {
    for (let i = 0; i < 32; i++) {
      const forged = randomBytes(TAG_BYTES);
      expect(verifyPointerTag(keys.sign, 1, randomBytes(POINTER_ID_BYTES), 'secret', forged)).toBe(
        false,
      );
    }
  });
});

describe('formatPointer', () => {
  it('emits a token the schema grammar accepts', async () => {
    const { PointerToken } = await import('@akasecurity/schema');
    const tag = signPointer(keys.sign, 1, pointerId, 'secret');
    const token = formatPointer('secret', 1, pointerId, tag);
    expect(PointerToken.safeParse(token).success).toBe(true);
  });

  it('carries no pointer-id or tag bytes in a decodable non-base32 form', () => {
    const tag = signPointer(keys.sign, 1, pointerId, 'secret');
    const token = formatPointer('secret', 1, pointerId, tag);
    expect(token.startsWith('[[aka:secret:')).toBe(true);
    expect(token.endsWith(']]')).toBe(true);
  });
});
