import { describe, expect, it } from 'vitest';

import { GetPolicyStatsResponse, ListPoliciesResponse } from '../zod/api.ts';
import { InstalledPack, PatchInstalledPackRequest } from '../zod/installed-pack.ts';
import {
  BuiltinPolicyId,
  KNOWN_BUILTIN_IDS,
  PolicyDetail,
  PolicyKind,
  PolicyListItem,
  PolicyStatsResponse,
} from '../zod/policy.ts';

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
    expect(KNOWN_BUILTIN_IDS).toEqual(['monitor', 'warn', 'redact', 'block']);
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

// ─── GetPolicyStatsResponse (alias check) ────────────────────────────────────

describe('GetPolicyStatsResponse', () => {
  it('is the same schema as PolicyStatsResponse', () => {
    const input = { policies: 4, builtin: 4, custom: 0, detectionsGoverned: 7 };
    expect(GetPolicyStatsResponse.parse(input)).toEqual(input);
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
