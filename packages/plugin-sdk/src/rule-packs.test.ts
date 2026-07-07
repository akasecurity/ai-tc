import { getLoadedRules, scan } from '@akasecurity/detections';
import { describe, expect, it } from 'vitest';

import { bundledDetections, registerBundledPacks, uniqueRuleIds } from './rule-packs.ts';

describe('registerBundledPacks', () => {
  it('loads the bundled secret + PII rule JSON and makes it scannable', () => {
    registerBundledPacks();
    // secrets (aws, github-pat) + core-pii (email, ssn) = 4 bundled rules.
    expect(getLoadedRules().length).toBeGreaterThanOrEqual(4);
    // A canonical AWS key is caught by the bundled secret pack.
    const findings = scan('export AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    expect(findings.some((f) => f.category === 'secret')).toBe(true);
  });
});

describe('bundledDetections', () => {
  it('reports each bundled pack with its manifest version + parsed rule snapshot', () => {
    const packs = bundledDetections();
    expect(packs.map((p) => p.packId).sort()).toEqual(['code-flaws', 'core-pii', 'secrets']);

    const secrets = packs.find((p) => p.packId === 'secrets');
    expect(secrets).toBeDefined();
    // version comes from the manifest; rules are the loaded snapshot, each parsed
    // into a valid Rule whose id is namespaced under the pack.
    expect(secrets?.namespace).toBe('aka');
    expect(secrets?.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(secrets?.rules.length).toBeGreaterThan(0);
    expect(secrets?.rules.every((r) => r.id.startsWith('secrets/'))).toBe(true);
  });
});

describe('uniqueRuleIds', () => {
  it('dedupes and joins rule ids for a one-line summary', () => {
    expect(uniqueRuleIds([{ ruleId: 'a' }, { ruleId: 'a' }, { ruleId: 'b' }])).toBe('a, b');
    expect(uniqueRuleIds([])).toBe('');
  });
});
