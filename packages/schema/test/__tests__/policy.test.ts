import { describe, expect, it } from 'vitest';
import type { z } from 'zod';

import { InstalledPack, PatchInstalledPackRequest } from '../../src/zod/installed-pack.ts';
import {
  BUILTIN_POLICIES,
  BuiltinPolicyId,
  builtinPolicyIsReversible,
  builtinPolicyToAction,
  CATEGORY_EXPRESSIBLE_IDS,
  CATEGORY_INEXPRESSIBLE_IDS,
  CategoryPolicyId,
  DEFAULT_PACK_POLICY_ID,
  KNOWN_BUILTIN_IDS,
  ListPoliciesResponse,
  Policy,
  PolicyDetail,
  policyDisplayName,
  policyIdIsReversible,
  policyIdToAction,
  PolicyKind,
  PolicyListItem,
  PolicyProvenance,
  PolicyStatsResponse,
} from '../../src/zod/policy.ts';

// ─── PolicyKind ──────────────────────────────────────────────────────────────

describe('PolicyKind', () => {
  it('parses valid values', () => {
    expect(PolicyKind.parse('builtin')).toBe('builtin');
    expect(PolicyKind.parse('custom')).toBe('custom');
  });

  it('rejects invalid values', () => {
    expect(() => PolicyKind.parse('unknown')).toThrow();
    expect(() => PolicyKind.parse('')).toThrow();
    expect(() => PolicyKind.parse(null)).toThrow();
  });
});

// ─── PolicyProvenance ────────────────────────────────────────────────────────
//
// The axis Policy carries, and deliberately NOT PolicyKind. The two answer
// different questions — which ARCHETYPE catalog entry a row is, versus whether
// this deployment AUTHORED the row — and only the second one a device locks on.
// Sharing one enum published one component under two meanings, so these cases
// are about the two staying apart rather than about either one's members.

describe('PolicyProvenance', () => {
  it('parses valid values', () => {
    expect(PolicyProvenance.parse('builtin')).toBe('builtin');
    expect(PolicyProvenance.parse('authored')).toBe('authored');
  });

  it("rejects PolicyKind's own 'custom' member, so the two cannot be aliased", () => {
    expect(() => PolicyProvenance.parse('custom')).toThrow();
    expect(() => PolicyProvenance.parse('')).toThrow();
    expect(() => PolicyProvenance.parse(null)).toThrow();
  });

  it('registers a component id of its own', () => {
    // What a generated client sees. One id for both axes is exactly the defect:
    // a consumer reads the archetype answer where the provenance answer was
    // meant, and the device-side lock keys on the provenance one.
    expect(PolicyProvenance.meta()?.id).toBe('PolicyProvenance');
    expect(PolicyKind.meta()?.id).toBe('PolicyKind');
  });

  it('is the axis Policy carries — `kind` is not a Policy field', () => {
    const base = {
      id: '0b3f5f6e-6c1a-4a4f-9a2e-6c9d1f0c9a11',
      scope: 'global' as const,
      target: { category: 'secret' as const },
      action: 'block' as const,
      enabled: true,
    };
    expect(Policy.parse({ ...base, provenance: 'authored' }).provenance).toBe('authored');
    // Zod strips what the shape does not declare, so a producer still sending
    // the old key loses it here rather than locking a device by accident.
    expect(Policy.parse({ ...base, kind: 'custom' })).not.toHaveProperty('kind');
    expect(Policy.parse({ ...base, kind: 'custom' }).provenance).toBeUndefined();
  });
});

// ─── BuiltinPolicyId ─────────────────────────────────────────────────────────

describe('BuiltinPolicyId', () => {
  it('parses all 4 valid slugs', () => {
    expect(BuiltinPolicyId.parse('monitor')).toBe('monitor');
    expect(BuiltinPolicyId.parse('warn')).toBe('warn');
    expect(BuiltinPolicyId.parse('redact')).toBe('redact');
    expect(BuiltinPolicyId.parse('block')).toBe('block');
  });

  it('rejects unknown slugs', () => {
    expect(() => BuiltinPolicyId.parse('unknown')).toThrow();
    expect(() => BuiltinPolicyId.parse('log')).toThrow();
    expect(() => BuiltinPolicyId.parse('')).toThrow();
  });

  it('KNOWN_BUILTIN_IDS matches BuiltinPolicyId enum values', () => {
    expect(KNOWN_BUILTIN_IDS).toEqual(['monitor', 'warn', 'redact', 'vault', 'block']);
  });
});

// The reversibility axis. It is the ONLY thing that distinguishes Redact from
// Redact & Vault — both resolve to the same `redact` ActionTaken — so every
// consumer that decides whether a stripped value survives reads through these.

describe('builtinPolicyIsReversible', () => {
  it('is true for exactly the archetypes that keep what they strip', () => {
    expect(builtinPolicyIsReversible('vault')).toBe(true);
    for (const id of KNOWN_BUILTIN_IDS.filter((i) => i !== 'vault')) {
      expect(builtinPolicyIsReversible(id), `${id} must not be reversible`).toBe(false);
    }
  });

  it('agrees with the catalog it is derived from', () => {
    for (const id of KNOWN_BUILTIN_IDS) {
      expect(builtinPolicyIsReversible(id)).toBe(BUILTIN_POLICIES[id].reversible);
    }
  });

  it('never disagrees with the action axis: a reversible archetype still redacts', () => {
    // The pairing the whole design rests on. A reversible archetype that
    // resolved to some OTHER action would mean a value kept without being
    // removed from the request.
    for (const id of KNOWN_BUILTIN_IDS.filter((i) => builtinPolicyIsReversible(i))) {
      expect(builtinPolicyToAction(id)).toBe('redact');
    }
  });
});

describe('policyDisplayName — one spelling for four surfaces', () => {
  it('renders each built-in by its catalog name', () => {
    for (const id of KNOWN_BUILTIN_IDS) {
      expect(policyDisplayName(id)).toBe(BUILTIN_POLICIES[id].name);
    }
  });

  it('coalesces an unassigned pack exactly as its two siblings do', () => {
    // The three resolvers must agree about what an unassigned pack IS, or one
    // surface reads Monitor while another reads blank.
    for (const absent of [null, undefined]) {
      expect(policyDisplayName(absent)).toBe(BUILTIN_POLICIES[DEFAULT_PACK_POLICY_ID].name);
      expect(policyIdToAction(absent)).toBe(builtinPolicyToAction(DEFAULT_PACK_POLICY_ID));
      expect(policyIdIsReversible(absent)).toBe(builtinPolicyIsReversible(DEFAULT_PACK_POLICY_ID));
    }
  });

  it('returns a custom id verbatim rather than as a built-in', () => {
    // Least of all as Monitor, which would read as log-only for a policy that
    // may block.
    for (const custom of ['my-custom-policy', 'VAULT', 'constructor']) {
      expect(policyDisplayName(custom)).toBe(custom);
    }
  });
});

describe('CategoryPolicyId narrows at the TYPE level, not only at runtime', () => {
  it('refuses a reversible archetype at runtime', () => {
    for (const id of CATEGORY_INEXPRESSIBLE_IDS) {
      expect(CategoryPolicyId.safeParse(id).success, `${id} must not parse`).toBe(false);
    }
  });

  it('accepts every archetype the category axis CAN store', () => {
    for (const id of CATEGORY_EXPRESSIBLE_IDS) {
      expect(CategoryPolicyId.safeParse(id).success, `${id} must parse`).toBe(true);
    }
  });

  it('the two sets partition the catalog', () => {
    expect([...CATEGORY_EXPRESSIBLE_IDS, ...CATEGORY_INEXPRESSIBLE_IDS].sort()).toEqual(
      [...KNOWN_BUILTIN_IDS].sort(),
    );
  });

  it('the INFERRED type excludes the reversible ids', () => {
    // The half that was missing. The enum was cast to the WIDE element type, so
    // z.infer gave back the whole union and every "narrowed" signature accepted
    // 'vault' — the runtime refused it while the compiler waved it through.
    //
    // Asserted as an assignability fact rather than with a compiler-error
    // directive: this fails to COMPILE if the narrowing regresses, which is the
    // property, and it does not pin tsc's wording.
    type Narrow = z.infer<typeof CategoryPolicyId>;
    type ReversibleIsExcluded = 'vault' extends Narrow ? false : true;
    const narrowed: ReversibleIsExcluded = true;
    expect(narrowed).toBe(true);

    // And the companion direction: a non-reversible id IS in the narrow type.
    type RedactIsIncluded = 'redact' extends Narrow ? true : false;
    const included: RedactIsIncluded = true;
    expect(included).toBe(true);
  });
});

describe('policyIdIsReversible — the PACK axis', () => {
  it('reads a real assignment', () => {
    expect(policyIdIsReversible('vault')).toBe(true);
    expect(policyIdIsReversible('redact')).toBe(false);
    expect(policyIdIsReversible('block')).toBe(false);
  });

  it('coalesces an unassigned pack the same way policyIdToAction does', () => {
    // Both must land on DEFAULT_PACK_POLICY_ID, or the two axes describe
    // different policies for one unassigned pack.
    for (const absent of [null, undefined]) {
      expect(policyIdIsReversible(absent)).toBe(builtinPolicyIsReversible(DEFAULT_PACK_POLICY_ID));
      expect(policyIdToAction(absent)).toBe(builtinPolicyToAction(DEFAULT_PACK_POLICY_ID));
    }
  });

  it('treats an UNKNOWN id as the default rather than as reversible', () => {
    // A custom policy, or a row written by a newer build. Defaulting to
    // not-reversible is the safe direction: destroying a value that could have
    // been recovered is survivable; keeping one the policy said to destroy is not.
    for (const unknown of ['my-custom-policy', '', 'VAULT', 'constructor']) {
      expect(policyIdIsReversible(unknown), `${unknown} must not read as reversible`).toBe(false);
    }
  });
});

// ─── PolicyListItem ───────────────────────────────────────────────────────────

describe('PolicyListItem', () => {
  it('validates a valid shape', () => {
    const input = {
      id: 'redact',
      kind: 'builtin',
      name: 'Redact',
      enabled: true,
      usedByCount: 3,
    };
    const result = PolicyListItem.parse(input);
    expect(result).toEqual(input);
  });

  it('rejects negative usedByCount', () => {
    expect(() =>
      PolicyListItem.parse({
        id: 'redact',
        kind: 'builtin',
        name: 'Redact',
        enabled: true,
        usedByCount: -1,
      }),
    ).toThrow();
  });

  it('rejects missing required fields', () => {
    expect(() =>
      PolicyListItem.parse({ id: 'monitor', kind: 'builtin', name: 'Monitor', enabled: true }),
    ).toThrow();
  });
});

// ─── PolicyDetail ─────────────────────────────────────────────────────────────

describe('PolicyDetail', () => {
  it('validates a valid shape with empty usedBy', () => {
    const input = {
      specVersion: 1 as const,
      id: 'monitor',
      kind: 'builtin',
      name: 'Monitor',
      enabled: true,
      description: 'Log every match for audit. The request is allowed through untouched.',
      usedBy: [],
    };
    expect(PolicyDetail.parse(input)).toEqual(input);
  });

  it('validates a valid shape with populated usedBy', () => {
    const input = {
      specVersion: 1 as const,
      id: 'block',
      kind: 'builtin',
      name: 'Block',
      enabled: true,
      description: 'Refuse the request entirely whenever any rule in this detection matches.',
      usedBy: [
        { id: 'aka/us-ssn', name: 'US Social Security numbers', ruleCount: 1, enabled: true },
      ],
    };
    const result = PolicyDetail.parse(input);
    expect(result.usedBy).toHaveLength(1);
  });

  it('requires specVersion to be literal 1', () => {
    const base = {
      id: 'warn',
      kind: 'builtin',
      name: 'Warn',
      enabled: true,
      description: 'Allow the request, but warn the user inline before it is sent.',
      usedBy: [],
    };
    expect(() => PolicyDetail.parse({ ...base, specVersion: 2 })).toThrow();
    expect(() => PolicyDetail.parse({ ...base, specVersion: '1' })).toThrow();
    expect(PolicyDetail.parse({ ...base, specVersion: 1 }).specVersion).toBe(1);
  });
});

// ─── PolicyStatsResponse ──────────────────────────────────────────────────────

describe('PolicyStatsResponse', () => {
  it('validates a valid shape', () => {
    const input = { policies: 4, builtin: 4, custom: 0, detectionsGoverned: 2 };
    expect(PolicyStatsResponse.parse(input)).toEqual(input);
  });

  it('rejects negative values', () => {
    expect(() =>
      PolicyStatsResponse.parse({ policies: 4, builtin: 4, custom: 0, detectionsGoverned: -1 }),
    ).toThrow();
  });

  it('rejects missing fields', () => {
    expect(() => PolicyStatsResponse.parse({ policies: 4, builtin: 4, custom: 0 })).toThrow();
  });
});

// ─── ListPoliciesResponse (PolicyListItem[]) ──────────────────────────────────

describe('ListPoliciesResponse', () => {
  it('accepts an array of PolicyListItem', () => {
    const input = {
      items: [
        { id: 'monitor', kind: 'builtin', name: 'Monitor', enabled: true, usedByCount: 0 },
        { id: 'warn', kind: 'builtin', name: 'Warn', enabled: true, usedByCount: 0 },
      ],
    };
    const result = ListPoliciesResponse.parse(input);
    expect(result.items).toHaveLength(2);
  });

  it('rejects the old Policy[] shape (missing usedByCount)', () => {
    const input = {
      items: [
        {
          id: '00000000-0000-0000-0000-000000000001',
          tenantId: '00000000-0000-0000-0000-000000000001',
          scope: 'global',
          target: { category: 'pii' },
          action: 'redact',
          enabled: true,
        },
      ],
    };
    expect(() => ListPoliciesResponse.parse(input)).toThrow();
  });
});

// ─── InstalledPack — with and without policyId ───────────────────────────────

describe('InstalledPack', () => {
  const base = {
    id: '00000000-0000-0000-0000-000000000001',
    tenantId: '00000000-0000-0000-0000-000000000002',
    namespace: 'aka',
    packId: 'us-ssn',
    version: '1.0.0',
    name: 'US Social Security numbers',
    enabled: true,
  };

  it('parses without policyId (existing rows)', () => {
    const result = InstalledPack.parse(base);
    expect(result.policyId).toBeUndefined();
  });

  it('parses with policyId present', () => {
    const result = InstalledPack.parse({ ...base, policyId: 'redact' });
    expect(result.policyId).toBe('redact');
  });
});

// ─── PatchInstalledPackRequest ────────────────────────────────────────────────

describe('PatchInstalledPackRequest', () => {
  it('accepts policyId as string (assign)', () => {
    const result = PatchInstalledPackRequest.parse({ policyId: 'block' });
    expect(result.policyId).toBe('block');
  });

  it('accepts policyId as null (unassign)', () => {
    const result = PatchInstalledPackRequest.parse({ policyId: null });
    expect(result.policyId).toBeNull();
  });

  it('accepts policyId as undefined (field absent)', () => {
    const result = PatchInstalledPackRequest.parse({ enabled: true });
    expect(result.policyId).toBeUndefined();
  });

  it('accepts both enabled and policyId together', () => {
    const result = PatchInstalledPackRequest.parse({ enabled: false, policyId: 'warn' });
    expect(result.enabled).toBe(false);
    expect(result.policyId).toBe('warn');
  });

  it('refine rejects empty object {}', () => {
    expect(() => PatchInstalledPackRequest.parse({})).toThrow(
      'At least one field must be provided',
    );
  });
});
