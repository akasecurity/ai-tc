import { describe, expect, it } from 'vitest';

import { Rule } from '../../src/zod/rule.ts';

function keywordRule(matcher: Record<string, unknown>) {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'keyword', ...matcher },
  };
}

describe('Rule keyword matcher contract', () => {
  it('accepts a keyword rule and defaults caseSensitive to false', () => {
    const parsed = Rule.parse(keywordRule({ keywords: ['password'] }));
    expect(parsed.matcher).toEqual({
      type: 'keyword',
      keywords: ['password'],
      caseSensitive: false,
    });
  });

  it('rejects an empty keyword', () => {
    // An empty keyword matches at every position; the KeywordMatcher has no
    // per-rule match ceiling, so a large input would allocate a span per byte.
    expect(Rule.safeParse(keywordRule({ keywords: [''] })).success).toBe(false);
    expect(Rule.safeParse(keywordRule({ keywords: ['password', ''] })).success).toBe(false);
  });

  it('rejects an empty keyword list', () => {
    expect(Rule.safeParse(keywordRule({ keywords: [] })).success).toBe(false);
  });

  it('accepts keywords containing regex metacharacters', () => {
    // Bundled rules ship these verbatim — core-code-context/db-table-name has
    // "SELECT * FROM ", core-financial/salary has "i make $". The matcher
    // escapes them; the schema must not reject them.
    const parsed = Rule.parse(
      keywordRule({ keywords: ['SELECT * FROM ', 'SELECT COUNT(*) FROM ', 'i make $'] }),
    );
    expect(parsed.matcher.type).toBe('keyword');
  });
});
