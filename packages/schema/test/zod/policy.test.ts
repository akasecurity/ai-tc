import { describe, expect, it } from 'vitest';

import { DetectionCategory } from '../../src/zod/finding.ts';
import {
  DEFAULT_ACTIONS,
  FULL_ENFORCEMENT_POSTURE,
  Policy,
  POLICY_BUNDLE_SHAPE_ID,
  PolicyBundle,
} from '../../src/zod/policy.ts';

describe('DEFAULT_ACTIONS — severity-floor cold-start values', () => {
  it('never hard-enforces (block) or silently rewrites payloads (redact) before onboarding', () => {
    // A fresh store with no per-category policy falls back to these. None may
    // block or redact on its own — the cold-start floor only ever surfaces
    // (warn) or logs. This guards against a category quietly regaining an
    // enforcing default and hard-acting on an un-onboarded machine.
    for (const [category, action] of Object.entries(DEFAULT_ACTIONS)) {
      expect(action, `${category} cold-start action`).not.toBe('block');
      expect(action, `${category} cold-start action`).not.toBe('redact');
    }
  });

  it('assigns a fallback action to every detection category', () => {
    expect(new Set(Object.keys(DEFAULT_ACTIONS))).toEqual(new Set(DetectionCategory.options));
  });

  it('floors critical/high-severity categories to warn, low/observe-only categories to log', () => {
    expect(DEFAULT_ACTIONS.secret).toBe('warn');
    expect(DEFAULT_ACTIONS.pii).toBe('warn');
    expect(DEFAULT_ACTIONS.financial).toBe('warn');
    expect(DEFAULT_ACTIONS.phi).toBe('warn');
    expect(DEFAULT_ACTIONS.code_flaw).toBe('warn');
    expect(DEFAULT_ACTIONS.custom).toBe('warn');
    expect(DEFAULT_ACTIONS.code_context).toBe('log');
    expect(DEFAULT_ACTIONS.config).toBe('log');
  });
});

describe('FULL_ENFORCEMENT_POSTURE — the "Actively redact" onboarding preset', () => {
  it('pins the pre-severity-floor enforcement mapping', () => {
    expect(FULL_ENFORCEMENT_POSTURE).toEqual({
      secret: 'block',
      pii: 'redact',
      financial: 'redact',
      phi: 'redact',
      code_flaw: 'warn',
      custom: 'warn',
      code_context: 'warn',
      config: 'warn',
    });
  });

  it('assigns a value to every detection category', () => {
    expect(new Set(Object.keys(FULL_ENFORCEMENT_POSTURE))).toEqual(
      new Set(DetectionCategory.options),
    );
  });
});

describe('PolicyBundle.ruleVersions', () => {
  const baseBundle = {
    version: '1',
    policies: [],
    customKeywords: [],
    fetchedAt: '2025-12-31T00:00:00.000Z',
  };

  it('parses without ruleVersions (older backends / on-disk caches omit it)', () => {
    const result = PolicyBundle.safeParse(baseBundle);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.ruleVersions).toBeUndefined();
    }
  });

  it('parses with ruleVersions present, keyed by ruleId', () => {
    const result = PolicyBundle.safeParse({
      ...baseBundle,
      ruleVersions: { 'secrets/aws-access-key': '2.3.1' },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.ruleVersions).toEqual({ 'secrets/aws-access-key': '2.3.1' });
    }
  });
});

// The stamp exists so a cache narrowed by an older build can be told apart from
// one this build wrote. It is only worth anything if it actually tracks the
// schema — a constant that drifted free of `PolicyBundle` would go on matching
// every record forever, which is indistinguishable from not having it.
describe('POLICY_BUNDLE_SHAPE_ID tracks the schema it describes', () => {
  it('names every top-level bundle field', () => {
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = Object.keys(PolicyBundle.shape).filter((key) => !named.has(key));
    expect(missing, 'bundle fields absent from the stamp').toEqual([]);
  });

  it('names the NESTED policy fields too', () => {
    // The top level alone is not enough, and this is the case that shows why:
    // `Policy` is a plain object, so Zod narrows it exactly as it narrows the
    // bundle, while `policies` stays one unchanged key. A build that widens
    // `Policy` would move no top-level key, its stamp would read as a match,
    // and the same 304 would replay the same narrowed policies.
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = Object.keys(Policy.shape).filter((key) => !named.has(`policies.${key}`));
    expect(missing, 'policy fields absent from the stamp').toEqual([]);
  });

  it('carries the two fields whose loss this was built for', () => {
    // Named rather than derived, so the assertion is not satisfied by whatever
    // the schema happens to say today. `prohibitedModels` is the governance
    // decision that went missing; `provenance` is the nested field added one
    // commit before the stamp existed, and the reason the nested half is here.
    expect(POLICY_BUNDLE_SHAPE_ID.split(',')).toContain('prohibitedModels');
    expect(POLICY_BUNDLE_SHAPE_ID.split(',')).toContain('policies.provenance');
  });

  it('is stable across reads and sorted', () => {
    // A set comparison downstream splits on the comma, but the value is also
    // written to disk and compared by equality, so an unstable order would make
    // every record read as a foreign shape.
    const parts = POLICY_BUNDLE_SHAPE_ID.split(',');
    expect(parts).toEqual([...parts].sort());
    expect(POLICY_BUNDLE_SHAPE_ID).toBe(POLICY_BUNDLE_SHAPE_ID);
  });
});
