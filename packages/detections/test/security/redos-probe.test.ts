import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { BUDGET_MS, checkRuleTiming } from '../../src/security/redos-probe.ts';

function regexRule(pattern: string): Rule {
  return Rule.parse({
    specVersion: 1,
    id: 'test-pack/evil',
    name: 'evil',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  });
}

describe('checkRuleTiming', () => {
  it('flags a catastrophic pattern as unsafe', () => {
    const result = checkRuleTiming(regexRule('^(a+)+$'));
    expect(result.safe).toBe(false);
    expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
  });

  it('passes a benign pattern as safe', () => {
    const result = checkRuleTiming(regexRule('AKIA[A-Z0-9]{16}'));
    expect(result.safe).toBe(true);
    expect(result.worstMs).toBeLessThan(BUDGET_MS);
  });
});
