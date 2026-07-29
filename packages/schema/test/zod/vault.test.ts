import { describe, expect, it } from 'vitest';

import { DetectionCategory } from '../../src/zod/finding.ts';
import {
  BATCHED_DEREF_REASONS,
  isBatchedDerefReason,
  isVaultConsentValid,
  POINTER_FORMAT_VERSION,
  POINTER_TOKEN_ANCHORED,
  PointerDescriptor,
  PointerToken,
  pointerTokenScanner,
  VAULT_CONSENT_VERSION,
  VAULT_INLINE_REVEAL_MAX_PER_MESSAGE,
  VaultDeref,
  VaultDerefReason,
  VaultInlineReveal,
  VaultKeyCustody,
} from '../../src/zod/vault.ts';

// A structurally valid pointer: 1-byte key version (2 b32 chars), 16-byte
// pointer id (26), 10-byte tag (16). Shape only — nothing here verifies a tag.
const KV = 'AE';
const ID = 'A'.repeat(26);
const TAG = 'B'.repeat(16);
const token = (category = 'secret', kv = KV, id = ID, tag = TAG): string =>
  `[[aka:${category}:${kv}.${id}.${tag}]]`;

describe('PointerToken grammar', () => {
  it('accepts a well-formed pointer for every DetectionCategory', () => {
    for (const category of DetectionCategory.options) {
      expect(PointerToken.safeParse(token(category)).success).toBe(true);
    }
  });

  it('accepts key versions from 1 to 4 bytes wide', () => {
    for (const kv of ['AE', 'AAAA', 'AAAAAA', 'AAAAAAA']) {
      expect(PointerToken.safeParse(token('secret', kv)).success).toBe(true);
    }
  });

  // The category segment is pinned to the enum precisely so a lookalike cannot
  // reach the de-reference path or trip an executable-field deny.
  it('rejects a category outside the DetectionCategory enum', () => {
    for (const bogus of ['tok', 'bogus', 'token', 'SECRET', 'secrets', '']) {
      expect(PointerToken.safeParse(token(bogus)).success).toBe(false);
    }
  });

  it('rejects the retired R0 category-free form', () => {
    expect(PointerToken.safeParse(`[[aka:tok:${KV}.${ID}.${TAG}]]`).success).toBe(false);
  });

  it('rejects wrong segment widths', () => {
    expect(PointerToken.safeParse(token('secret', 'A')).success).toBe(false);
    expect(PointerToken.safeParse(token('secret', 'A'.repeat(8))).success).toBe(false);
    expect(PointerToken.safeParse(token('secret', KV, 'A'.repeat(25))).success).toBe(false);
    expect(PointerToken.safeParse(token('secret', KV, ID, 'B'.repeat(15))).success).toBe(false);
  });

  it('rejects non-base32 alphabet characters', () => {
    // 0, 1, 8, 9 and lowercase are outside RFC 4648 base32.
    expect(PointerToken.safeParse(token('secret', KV, `0${ID.slice(1)}`)).success).toBe(false);
    expect(PointerToken.safeParse(token('secret', KV, `a${ID.slice(1)}`)).success).toBe(false);
  });

  it('rejects a malformed or missing sentinel', () => {
    expect(PointerToken.safeParse(`[aka:secret:${KV}.${ID}.${TAG}]`).success).toBe(false);
    expect(PointerToken.safeParse(`aka:secret:${KV}.${ID}.${TAG}`).success).toBe(false);
    expect(PointerToken.safeParse(`<aka:secret:${KV}.${ID}.${TAG}>`).success).toBe(false);
  });

  it('anchors — a pointer with trailing junk is not a valid token', () => {
    expect(POINTER_TOKEN_ANCHORED.test(`${token()} trailing`)).toBe(false);
    expect(POINTER_TOKEN_ANCHORED.test(`leading ${token()}`)).toBe(false);
  });
});

describe('pointerTokenScanner', () => {
  it('finds every pointer embedded in surrounding text', () => {
    const a = token('secret');
    const b = token('pii', 'AAAA', 'C'.repeat(26), 'D'.repeat(16));
    const text = `set KEY=${a} and mail ${b} done`;
    expect(text.match(pointerTokenScanner())).toEqual([a, b]);
  });

  // A shared /g regex carries lastIndex across calls and silently skips
  // matches; each call must get a fresh one.
  it('returns a fresh regex each call, so scans do not interfere', () => {
    const text = `x ${token()} y`;
    expect(pointerTokenScanner().test(text)).toBe(true);
    expect(pointerTokenScanner().test(text)).toBe(true);
  });

  it('does not match a lookalike with an invented category', () => {
    expect(`[[aka:bogus:${KV}.${ID}.${TAG}]]`.match(pointerTokenScanner())).toBeNull();
  });
});

describe('deref audit taxonomy', () => {
  it('is a closed vocabulary', () => {
    expect(VaultDerefReason.options).toEqual([
      'display',
      'explicit-reveal',
      'view-render',
      'model-input',
      'remediation',
    ]);
    expect(VaultDerefReason.safeParse('whatever').success).toBe(false);
  });

  // Model crossings are the rows the threat model reads as its anomaly signal —
  // batching them would bury them under display volume.
  it('batches only the human-volume reasons, never model crossings', () => {
    expect(BATCHED_DEREF_REASONS).toEqual(['display', 'view-render']);
    expect(isBatchedDerefReason('display')).toBe(true);
    expect(isBatchedDerefReason('view-render')).toBe(true);
    expect(isBatchedDerefReason('model-input')).toBe(false);
    expect(isBatchedDerefReason('explicit-reveal')).toBe(false);
    expect(isBatchedDerefReason('remediation')).toBe(false);
  });

  it('defaults pointerCount to 1 for an unbatched row', () => {
    const row = VaultDeref.parse({
      id: '3f1b8c2e-9a4d-4f6b-8c1e-2d5a7b9c0e13',
      pointerId: 'p1',
      at: '2026-07-27T00:00:00.000Z',
      target: 'model',
      reason: 'model-input',
      outcome: 'revealed',
    });
    expect(row.pointerCount).toBe(1);
  });

  it('carries no raw value or ciphertext field', () => {
    const keys = Object.keys(VaultDeref.shape);
    expect(keys).not.toContain('raw');
    expect(keys).not.toContain('value');
    expect(keys).not.toContain('ciphertext');
  });
});

describe('PointerDescriptor', () => {
  // Badge/listing data only: the keyed fingerprint is a correlation key and must
  // never reach a view layer or the browser.
  it('exposes no raw value and no fingerprint', () => {
    const keys = Object.keys(PointerDescriptor.shape);
    expect(keys).not.toContain('valueFingerprint');
    expect(keys).not.toContain('raw');
    expect(keys).not.toContain('ciphertext');
    expect(keys).toContain('maskedMatch');
    expect(keys).toContain('category');
  });
});

describe('vault consent', () => {
  it('is invalid when absent', () => {
    expect(isVaultConsentValid(undefined)).toBe(false);
  });

  it('is valid at the current version', () => {
    expect(
      isVaultConsentValid({
        acknowledgedAt: '2026-07-27T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION,
      }),
    ).toBe(true);
  });

  // Widening what the vault does must force a re-ask rather than ride an old grant.
  it('is invalid when recorded against an older version', () => {
    expect(
      isVaultConsentValid({
        acknowledgedAt: '2026-07-27T00:00:00.000Z',
        version: VAULT_CONSENT_VERSION - 1,
      }),
    ).toBe(false);
  });
});

describe('inline reveal', () => {
  it('defaults to masked, so raw exposure is never ambient', () => {
    expect(VaultInlineReveal.parse('masked')).toBe('masked');
    expect(VaultInlineReveal.options).toEqual(['masked', 'full', 'off']);
  });

  it('caps full-mode reveals per message', () => {
    expect(VAULT_INLINE_REVEAL_MAX_PER_MESSAGE).toBe(2);
  });
});

describe('format version', () => {
  it('is 2 — the category-bearing generation', () => {
    expect(POINTER_FORMAT_VERSION).toBe(2);
  });
});

// The custody field is an OPEN discriminant: the runtime accepts any string so a
// build can name a provider this schema has never heard of. These pin that the
// openness is REAL (an unknown name parses) and that it is honest — nothing here
// may start rejecting names, because the resolver, not the schema, decides which
// ones it can serve.
describe('vault key custody', () => {
  it('accepts the two names this build resolves', () => {
    expect(VaultKeyCustody.parse('file')).toBe('file');
    expect(VaultKeyCustody.parse('keychain')).toBe('keychain');
  });

  it('accepts a provider name it has never heard of', () => {
    expect(VaultKeyCustody.parse('sharded-hsm')).toBe('sharded-hsm');
  });

  // The whole point of the open discriminant: a typo is indistinguishable from a
  // legitimately unfamiliar provider name at the schema layer, so validation
  // cannot be what catches it. Stated as a test so nobody "tightens" this into
  // an enum and breaks a build that was relying on the openness.
  it('cannot distinguish a typo from an unfamiliar provider name — by design', () => {
    expect(VaultKeyCustody.parse('keychian')).toBe('keychian');
  });

  it('still rejects values that are not strings at all', () => {
    expect(VaultKeyCustody.safeParse(7).success).toBe(false);
    expect(VaultKeyCustody.safeParse(undefined).success).toBe(false);
  });
});
