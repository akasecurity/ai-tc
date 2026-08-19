import { describe, expect, it } from 'vitest';

import { DetectionCategory } from '../../src/zod/finding.ts';
import {
  BATCHED_DEREF_REASONS,
  DEFAULT_VAULT_DEREFS_LIMIT,
  DEFAULT_VAULT_INVENTORY_LIMIT,
  isBatchedDerefReason,
  isVaultConsentValid,
  ListVaultDerefsQuery,
  ListVaultDerefsResponse,
  ListVaultInventoryQuery,
  ListVaultInventoryResponse,
  ListVaultReuseQuery,
  ListVaultReuseResponse,
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
      'purge',
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
    expect(isBatchedDerefReason('purge')).toBe(false);
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

// ─── Paged reads ─────────────────────────────────────────────────────────────

// The three paged queries share one shape, so the range and coercion rules are
// driven against all of them rather than whichever one was edited last.
const PAGED_VAULT_QUERIES = [
  ListVaultInventoryQuery,
  ListVaultReuseQuery,
  ListVaultDerefsQuery,
] as const;

// A minimal inventory row: every required field, nothing optional. `provider` is
// the only optional key, and `revealGrantId` is nullable-but-required.
const inventoryEntry = {
  pointerId: 'p1',
  category: 'secret',
  maskedMatch: 'A******E',
  occurrences: 3,
  firstSeen: '2026-07-27T00:00:00.000Z',
  lastSeen: '2026-07-28T00:00:00.000Z',
  revealGrantId: null,
  sightings: [
    {
      location: 'src/config/database.ts',
      kind: 'file',
      firstSeen: '2026-07-27T00:00:00.000Z',
      lastSeen: '2026-07-28T00:00:00.000Z',
    },
  ],
};

const derefRow = {
  id: '3f1b8c2e-9a4d-4f6b-8c1e-2d5a7b9c0e13',
  pointerId: 'p1',
  at: '2026-07-28T00:00:00.000Z',
  target: 'model',
  reason: 'model-input',
  outcome: 'revealed',
};

describe('paged vault queries', () => {
  it('parses an empty query — limit and cursor are both optional', () => {
    for (const schema of PAGED_VAULT_QUERIES) {
      const result = schema.safeParse({});
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.limit).toBeUndefined();
        expect(result.data.cursor).toBeUndefined();
      }
    }
  });

  it('accepts the ends of the range and rejects either side of it', () => {
    for (const schema of PAGED_VAULT_QUERIES) {
      expect(schema.safeParse({ limit: 1 }).success).toBe(true);
      expect(schema.safeParse({ limit: 200 }).success).toBe(true);
      expect(schema.safeParse({ limit: 0 }).success).toBe(false);
      expect(schema.safeParse({ limit: 201 }).success).toBe(false);
    }
  });

  it('rejects a fractional limit', () => {
    for (const schema of PAGED_VAULT_QUERIES) {
      expect(schema.safeParse({ limit: 1.5 }).success).toBe(false);
    }
  });

  // These cross a Server Action boundary the browser can post anything to, so a
  // numeric string has to arrive as a number — asserting only `.success` here
  // would stay green with the coercion dropped.
  it('coerces a string limit to a number', () => {
    for (const schema of PAGED_VAULT_QUERIES) {
      const result = schema.safeParse({ limit: '25' });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.limit).toBe(25);
    }
  });

  it('takes an arbitrary opaque cursor string', () => {
    for (const schema of PAGED_VAULT_QUERIES) {
      const result = schema.safeParse({ cursor: 'eyJzdGFydGVkQXRNcyI6MSwiaWQiOiJwMSJ9' });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.cursor).toBe('eyJzdGFydGVkQXRNcyI6MSwiaWQiOiJwMSJ9');
    }
  });

  // The store applies these when a query omits `limit`. A default outside the
  // boundary's own range would let the two page at different sizes, so it has to
  // parse as a limit itself.
  it('accepts its own default page size as a limit', () => {
    const inventory = ListVaultInventoryQuery.safeParse({ limit: DEFAULT_VAULT_INVENTORY_LIMIT });
    expect(inventory.success).toBe(true);
    if (inventory.success) expect(inventory.data.limit).toBe(DEFAULT_VAULT_INVENTORY_LIMIT);

    const reuse = ListVaultReuseQuery.safeParse({ limit: DEFAULT_VAULT_INVENTORY_LIMIT });
    expect(reuse.success).toBe(true);
    if (reuse.success) expect(reuse.data.limit).toBe(DEFAULT_VAULT_INVENTORY_LIMIT);

    const derefs = ListVaultDerefsQuery.safeParse({ limit: DEFAULT_VAULT_DEREFS_LIMIT });
    expect(derefs.success).toBe(true);
    if (derefs.success) expect(derefs.data.limit).toBe(DEFAULT_VAULT_DEREFS_LIMIT);
  });
});

describe('ListVaultDerefsQuery.includeBatched', () => {
  // A real boolean, not a stringbool: this arrives over a Server Action, which
  // preserves the type, never as a URL param.
  it('accepts a real boolean either way round', () => {
    for (const raw of [true, false]) {
      const result = ListVaultDerefsQuery.safeParse({ includeBatched: raw });
      expect(result.success).toBe(true);
      if (result.success) expect(result.data.includeBatched).toBe(raw);
    }
  });

  it('is optional — absent means the batched reasons stay hidden', () => {
    const result = ListVaultDerefsQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.includeBatched).toBeUndefined();
  });
});

describe('ListVaultInventoryResponse', () => {
  it('parses a page with its store-wide total', () => {
    const result = ListVaultInventoryResponse.safeParse({
      totals: { values: 9323 },
      items: [inventoryEntry],
      nextCursor: 'opaque-cursor',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.totals.values).toBe(9323);
      expect(result.data.items[0]?.sightings[0]?.kind).toBe('file');
    }
  });

  it('parses a null nextCursor at the last page', () => {
    expect(
      ListVaultInventoryResponse.safeParse({
        totals: { values: 0 },
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(true);
  });

  // `.nullable()`, deliberately not `.optional()` — the convention the whole
  // package follows. An omitted key would read as "no further pages" to a
  // consumer that only checks falsiness, so a producer that forgot to emit it
  // must fail here rather than silently truncate the list.
  it('rejects an omitted nextCursor key', () => {
    expect(ListVaultInventoryResponse.safeParse({ totals: { values: 0 }, items: [] }).success).toBe(
      false,
    );
  });

  it('rejects a missing totals key', () => {
    expect(ListVaultInventoryResponse.safeParse({ items: [], nextCursor: null }).success).toBe(
      false,
    );
  });
});

describe('ListVaultReuseResponse', () => {
  // The reuse total is a property of the WHOLE store, not of the page — named
  // apart from the inventory's `values` so the two cannot be swapped silently.
  it('parses a page whose total is `reused`, not `values`', () => {
    const result = ListVaultReuseResponse.safeParse({
      totals: { reused: 12 },
      items: [inventoryEntry],
      nextCursor: null,
    });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.totals.reused).toBe(12);

    expect(
      ListVaultReuseResponse.safeParse({
        totals: { values: 12 },
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it('rejects an omitted nextCursor key', () => {
    expect(ListVaultReuseResponse.safeParse({ totals: { reused: 0 }, items: [] }).success).toBe(
      false,
    );
  });

  it('rejects a negative reuse total', () => {
    expect(
      ListVaultReuseResponse.safeParse({
        totals: { reused: -1 },
        items: [],
        nextCursor: null,
      }).success,
    ).toBe(false);
  });
});

describe('ListVaultDerefsResponse', () => {
  it('parses a page with the whole-trail hidden count', () => {
    const result = ListVaultDerefsResponse.safeParse({
      items: [derefRow],
      nextCursor: 'opaque-cursor',
      hiddenBatched: 4172,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.hiddenBatched).toBe(4172);
      expect(result.data.items[0]?.pointerCount).toBe(1);
    }
  });

  it('parses a null nextCursor at the last page', () => {
    expect(
      ListVaultDerefsResponse.safeParse({ items: [], nextCursor: null, hiddenBatched: 0 }).success,
    ).toBe(true);
  });

  it('rejects an omitted nextCursor key', () => {
    expect(ListVaultDerefsResponse.safeParse({ items: [], hiddenBatched: 0 }).success).toBe(false);
  });

  // The count the "N hidden" line and its toggle speak for — a response that
  // omits it would render the toggle with nothing behind it.
  it('rejects a missing or negative hiddenBatched', () => {
    expect(ListVaultDerefsResponse.safeParse({ items: [], nextCursor: null }).success).toBe(false);
    expect(
      ListVaultDerefsResponse.safeParse({ items: [], nextCursor: null, hiddenBatched: -1 }).success,
    ).toBe(false);
  });
});

// The vault's deliberate departure from the findings/activity list convention:
// those responses register an OpenAPI component id, these do not. Per the
// vault.ts file header, an id registers the schema globally and a swagger setup
// would emit it as a public component — and nothing about the vault belongs on a
// public API surface. Adding one is a one-word change that nothing else notices.
describe('paged vault schemas carry no OpenAPI component id', () => {
  it('leaves every one of the six id-less', () => {
    expect(ListVaultInventoryQuery.meta()?.id).toBeUndefined();
    expect(ListVaultInventoryResponse.meta()?.id).toBeUndefined();
    expect(ListVaultReuseQuery.meta()?.id).toBeUndefined();
    expect(ListVaultReuseResponse.meta()?.id).toBeUndefined();
    expect(ListVaultDerefsQuery.meta()?.id).toBeUndefined();
    expect(ListVaultDerefsResponse.meta()?.id).toBeUndefined();
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
