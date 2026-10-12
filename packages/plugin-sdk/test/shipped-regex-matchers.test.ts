import { describe, expect, it } from 'vitest';

import { bundledDetections, shippedRegexMatchers } from '../src/rule-packs.ts';
import { ruleProbeKey } from '../src/rule-quarantine.ts';

describe('shippedRegexMatchers', () => {
  it('names the regex of every bundled regex rule, and nothing else', () => {
    const regexRules = bundledDetections()
      .flatMap((pack) => pack.rules)
      .filter((rule) => rule.matcher.type === 'regex');
    const matchers = shippedRegexMatchers();

    expect(regexRules.length).toBeGreaterThan(0);
    expect(matchers).toHaveLength(regexRules.length);
    for (const rule of regexRules) {
      if (rule.matcher.type !== 'regex') continue;
      expect(matchers).toContainEqual({ pattern: rule.matcher.pattern, flags: rule.matcher.flags });
      expect(ruleProbeKey(rule)).toBeDefined();
    }
  });
});
