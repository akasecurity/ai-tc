import { describe, expect, expectTypeOf, it } from 'vitest';
import type { z } from 'zod';

import {
  DetectedFinding,
  Finding,
  FindingAction,
  FindingCategory,
  FindingInstance,
  FindingOrigin,
  FindingPolicyRef,
  FindingProvider,
  FindingStatus,
  ListGroupedFindingsQuery,
  ResolutionMethod,
} from './finding.ts';
import { Policy } from './policy.ts';

// The base schema (Finding) is tenant-free and equals the producer-side shape
// (DetectedFinding) — it is the public API contract. `tenantId` is never part
// of the shape: a downstream schema may extend the base with scoping columns,
// but the base itself must drop them. These assertions lock that in.
const validRow = {
  id: '00000000-0000-0000-0000-000000000001',
  tenantId: '00000000-0000-0000-0000-000000000002',
  eventId: '00000000-0000-0000-0000-000000000003',
  ruleId: 'pii.email',
  category: 'pii' as const,
  severity: 'high' as const,
  span: { start: 0, end: 5 },
  maskedMatch: 'a***@b.com',
  actionTaken: 'redact' as const,
  confidence: 0.9,
};

describe('Finding schema (tenant-free base)', () => {
  it('Finding is the tenant-free base, equal to the producer-side DetectedFinding', () => {
    const withoutTenant = DetectedFinding.parse(validRow);
    expect(Finding.safeParse(withoutTenant).success).toBe(true);
    expect(DetectedFinding.safeParse(withoutTenant).success).toBe(true);
    // tenantId is stripped (unknown key), not required, on the base shape.
    expect(Finding.safeParse(validRow).success).toBe(true);
    expectTypeOf<z.output<typeof Finding>>().not.toHaveProperty('tenantId');
    expectTypeOf<z.output<typeof DetectedFinding>>().not.toHaveProperty('tenantId');
  });
});

describe('FindingAction enum', () => {
  it('accepts all 6 normative values', () => {
    for (const v of ['blocked', 'redacted', 'warned', 'allowed', 'quarantined', 'monitored']) {
      expect(FindingAction.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown values', () => {
    expect(FindingAction.safeParse('block').success).toBe(false);
    expect(FindingAction.safeParse('log').success).toBe(false);
  });
});

describe('FindingProvider enum', () => {
  it('includes claudedesktop as a distinct value (not merged with claudecode)', () => {
    expect(FindingProvider.safeParse('claudedesktop').success).toBe(true);
    expect(FindingProvider.safeParse('claudecode').success).toBe(true);
  });

  it('accepts all 6 provider values', () => {
    for (const v of ['claudecode', 'claudedesktop', 'cursor', 'copilot', 'chatgpt', 'api']) {
      expect(FindingProvider.safeParse(v).success).toBe(true);
    }
  });

  it('rejects raw source_tool values', () => {
    expect(FindingProvider.safeParse('claude-code').success).toBe(false);
    expect(FindingProvider.safeParse('claude-desktop').success).toBe(false);
  });
});

describe('FindingCategory enum', () => {
  it('includes source_code (maps from DB code_context)', () => {
    expect(FindingCategory.safeParse('source_code').success).toBe(true);
  });

  it('accepts all 9 category values', () => {
    for (const v of [
      'secret',
      'pii',
      'source_code',
      'external_share',
      'mcp_server',
      'customer_data',
      'financial',
      'phi',
      'custom',
    ]) {
      expect(FindingCategory.safeParse(v).success).toBe(true);
    }
  });

  it('accepts forward-compat values external_share, mcp_server, customer_data', () => {
    expect(FindingCategory.safeParse('external_share').success).toBe(true);
    expect(FindingCategory.safeParse('mcp_server').success).toBe(true);
    expect(FindingCategory.safeParse('customer_data').success).toBe(true);
  });

  it('rejects raw DB category value code_context', () => {
    expect(FindingCategory.safeParse('code_context').success).toBe(false);
  });
});

describe('FindingOrigin enum', () => {
  it('accepts both origin values', () => {
    for (const v of ['in-flight', 'at-rest']) {
      expect(FindingOrigin.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown values', () => {
    expect(FindingOrigin.safeParse('inflight').success).toBe(false);
    expect(FindingOrigin.safeParse('x').success).toBe(false);
  });
});

describe('FindingStatus enum', () => {
  it('accepts all 4 status values', () => {
    for (const v of ['open', 'handled', 'resolved', 'dismissed']) {
      expect(FindingStatus.safeParse(v).success).toBe(true);
    }
  });

  it('parses resolved and rejects unknown', () => {
    expect(FindingStatus.parse('resolved')).toBe('resolved');
    expect(() => FindingStatus.parse('x')).toThrow();
  });
});

describe('FindingInstance.status', () => {
  const baseInstance = {
    id: 'i1',
    provider: 'claudecode' as const,
    repo: 'acme/api',
    file: 'a.ts',
    action: 'blocked' as const,
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 0.9,
  };

  it('parses with a valid status', () => {
    const result = FindingInstance.safeParse({ ...baseInstance, status: 'resolved' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBe('resolved');
    }
  });

  it('parses with status absent (optional, backward-compatible)', () => {
    const result = FindingInstance.safeParse(baseInstance);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status).toBeUndefined();
    }
  });

  it('rejects an unknown status value', () => {
    expect(() => FindingInstance.parse({ ...baseInstance, status: 'x' })).toThrow();
  });
});

describe('ResolutionMethod enum', () => {
  it('accepts all 6 resolution methods', () => {
    for (const v of [
      'enforced-in-flight',
      'fixed-at-source',
      'exception',
      'acknowledged',
      'false-positive',
      'redetected',
    ]) {
      expect(ResolutionMethod.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown values', () => {
    expect(ResolutionMethod.safeParse('resolved').success).toBe(false);
    expect(ResolutionMethod.safeParse('x').success).toBe(false);
  });
});

describe('FindingPolicyRef', () => {
  it('requires name as a non-null string', () => {
    expect(FindingPolicyRef.safeParse({ id: 'policy-1', name: 'Block credentials' }).success).toBe(
      true,
    );
  });

  it('rejects when name is absent', () => {
    expect(FindingPolicyRef.safeParse({ id: 'policy-1' }).success).toBe(false);
  });

  it('rejects when name is null', () => {
    expect(FindingPolicyRef.safeParse({ id: 'policy-1', name: null }).success).toBe(false);
  });
});

describe('ListGroupedFindingsQuery.severity', () => {
  it('accepts Severity[] values (not FindingAction[])', () => {
    const result = ListGroupedFindingsQuery.safeParse({ severity: ['critical', 'high'] });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.severity).toEqual(['critical', 'high']);
    }
  });

  it('rejects FindingAction values in severity field', () => {
    expect(ListGroupedFindingsQuery.safeParse({ severity: ['blocked'] }).success).toBe(false);
    expect(ListGroupedFindingsQuery.safeParse({ severity: ['monitored'] }).success).toBe(false);
  });
});

describe('Policy schema extension (name field)', () => {
  const basePolicy = {
    id: '00000000-0000-0000-0000-000000000001',
    tenantId: '00000000-0000-0000-0000-000000000002',
    scope: 'global' as const,
    target: { ruleId: 'pii.email' },
    action: 'redact' as const,
    enabled: true,
  };

  it('parses with name absent (backward-compatible)', () => {
    const result = Policy.safeParse(basePolicy);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.name).toBeUndefined();
    }
  });

  it('parses with name present', () => {
    const result = Policy.safeParse({ ...basePolicy, name: 'Block cloud credentials' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.name).toBe('Block cloud credentials');
    }
  });
});
