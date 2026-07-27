// Vault cryptography: subkey derivation, AEAD seal/open, and the pointer tag.
//
// Three properties this module exists to guarantee:
//
//  1. Signing and encryption never share key bytes. One stored master key is
//     expanded through HKDF into two subkeys with distinct info labels.
//  2. A ciphertext is bound to exactly its pointer and key epoch. The AAD is the
//     pointer's own identity, so ciphertext copied under another row's pointer
//     fails to open rather than yielding a wrong plaintext.
//  3. A pointer cannot be forged or relabelled. The tag covers the category, so
//     re-badging `[[aka:secret:...]]` as `[[aka:pii:...]]` breaks verification.
//
// The field encoding below is load-bearing for (2) and (3) — see `bindingInput`.
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  timingSafeEqual,
} from 'node:crypto';

import { POINTER_FORMAT_VERSION } from '@akasecurity/schema';

export const POINTER_ID_BYTES = 16;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 10;
export const SUBKEY_BYTES = 32;

const HKDF_INFO_ENC = 'aka:vault:enc:v1';
const HKDF_INFO_SIGN = 'aka:vault:sign:v1';
// HKDF's salt is a domain separator here, not a secret; the master key already
// carries the entropy.
const HKDF_SALT = 'aka:vault:v1';

// ─── base32 (RFC 4648, no padding) ───────────────────────────────────────────
// Chosen for the wire because it survives being pasted, quoted, and
// case-folded far better than base64, and its alphabet cannot introduce a
// character that would terminate the `[[...]]` sentinel.

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET.charAt((buffer << (5 - bits)) & 31);
  return out;
}

export function base32Decode(text: string): Buffer {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const value = B32_ALPHABET.indexOf(char);
    if (value < 0) throw new Error('base32: character outside the alphabet');
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// A key version on the wire, as the fewest big-endian bytes that hold it. Kept
// minimal because every pointer carries it into model context and into files;
// the MAC input below always uses the fixed 4-byte form regardless.
export function encodeKeyVersion(version: number): string {
  if (!Number.isInteger(version) || version < 1 || version > 0xffffffff) {
    throw new Error('vault: key version out of range');
  }
  const bytes: number[] = [];
  let remaining = version;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return base32Encode(Uint8Array.from(bytes));
}

export function decodeKeyVersion(encoded: string): number {
  const bytes = base32Decode(encoded);
  if (bytes.length === 0 || bytes.length > 4) throw new Error('vault: bad key version encoding');
  let version = 0;
  for (const byte of bytes) version = version * 256 + byte;
  if (version < 1) throw new Error('vault: bad key version');
  return version;
}

// ─── Subkeys ─────────────────────────────────────────────────────────────────

export interface VaultSubkeys {
  enc: Buffer;
  sign: Buffer;
}

export function deriveSubkeys(master: Uint8Array): VaultSubkeys {
  const derive = (info: string): Buffer =>
    Buffer.from(hkdfSync('sha256', master, HKDF_SALT, info, SUBKEY_BYTES));
  return { enc: derive(HKDF_INFO_ENC), sign: derive(HKDF_INFO_SIGN) };
}

// ─── The binding input (AAD and tag input are the same bytes) ────────────────

/**
 * The canonical byte encoding of a pointer's identity, used BOTH as the AEAD
 * additional data and as the pointer tag's MAC input.
 *
 *   uint16be(format_version) ‖ uint32be(key_version) ‖ pointer_id[16] ‖ utf8(category)
 *
 * Every field before `category` is fixed-width and `category` is last, which
 * makes the encoding injective. That is the whole point: with variable-width
 * numerics, (key_version=1, category='2secret') and (key_version=12,
 * category='secret') would produce identical bytes — letting a pointer be
 * relabelled into another category and confusing which key epoch to verify
 * under. Do not make any field before `category` variable-width.
 */
export function bindingInput(
  keyVersion: number,
  pointerId: Uint8Array,
  category: string,
  formatVersion: number = POINTER_FORMAT_VERSION,
): Buffer {
  if (pointerId.length !== POINTER_ID_BYTES) {
    throw new Error('vault: pointer id must be 16 bytes');
  }
  const head = Buffer.alloc(6);
  head.writeUInt16BE(formatVersion, 0);
  head.writeUInt32BE(keyVersion, 2);
  return Buffer.concat([head, Buffer.from(pointerId), Buffer.from(category, 'utf8')]);
}

// ─── AEAD ────────────────────────────────────────────────────────────────────

export interface SealedValue {
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
}

export function seal(encKey: Buffer, plaintext: string, aad: Buffer, nonce: Buffer): SealedValue {
  const cipher = createCipheriv('aes-256-gcm', encKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

/**
 * Open a sealed value. Returns null on ANY verification failure rather than
 * throwing — a caller that cannot open a row must degrade to "unavailable", and
 * a thrown error here would have to be caught at every call site to avoid
 * escaping a hook's fail-open boundary.
 */
export function open(encKey: Buffer, sealed: SealedValue, aad: Buffer): string | null {
  try {
    const decipher = createDecipheriv('aes-256-gcm', encKey, sealed.nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(sealed.authTag);
    return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// ─── Pointer tag ─────────────────────────────────────────────────────────────

export function signPointer(
  signKey: Buffer,
  keyVersion: number,
  pointerId: Uint8Array,
  category: string,
): Buffer {
  return createHmac('sha256', signKey)
    .update(bindingInput(keyVersion, pointerId, category))
    .digest()
    .subarray(0, TAG_BYTES);
}

/** Constant-time tag check. A length mismatch is a mismatch, not an exception. */
export function verifyPointerTag(
  signKey: Buffer,
  keyVersion: number,
  pointerId: Uint8Array,
  category: string,
  tag: Uint8Array,
): boolean {
  if (tag.length !== TAG_BYTES) return false;
  const expected = signPointer(signKey, keyVersion, pointerId, category);
  return timingSafeEqual(expected, Buffer.from(tag));
}

// ─── Wire format ─────────────────────────────────────────────────────────────

export function formatPointer(
  category: string,
  keyVersion: number,
  pointerId: Uint8Array,
  tag: Uint8Array,
): string {
  return `[[aka:${category}:${encodeKeyVersion(keyVersion)}.${base32Encode(pointerId)}.${base32Encode(tag)}]]`;
}
