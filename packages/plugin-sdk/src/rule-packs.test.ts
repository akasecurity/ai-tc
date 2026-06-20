import { getLoadedRules, scan } from '@aka/detections';
import { describe, expect, it } from 'vitest';

import { registerBundledPacks, uniqueRuleIds } from './rule-packs.ts';

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

describe('uniqueRuleIds', () => {
  it('dedupes and joins rule ids for a one-line summary', () => {
    expect(uniqueRuleIds([{ ruleId: 'a' }, { ruleId: 'a' }, { ruleId: 'b' }])).toBe('a, b');
    expect(uniqueRuleIds([])).toBe('');
  });
});
