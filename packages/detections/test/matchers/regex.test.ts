import type { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { RegexMatcher } from '../../src/matchers/regex.ts';

// Constructed as plain objects (not Rule.parse()) — the matcher must stay safe
// on its own even if a pathological pattern somehow bypasses schema validation
// (the schema-level reject lives in packages/schema's RegexMatcher refine).
function regexRule(pattern: string, flags: string, captureGroup?: number): Rule {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags, captureGroup },
  };
}

describe('RegexMatcher', () => {
  it('does not hang on a whole-match pattern that can match the empty string', () => {
    const matcher = new RegexMatcher();
    const start = Date.now();
    const spans = matcher.match('abc123', regexRule('\\d*', 'g'));
    expect(Date.now() - start).toBeLessThan(1000);
    // Every zero-length match is skipped; only the non-empty "123" run is kept.
    expect(spans).toEqual([{ start: 3, end: 6 }]);
  });

  it('does not hang on (?:) matching an all-empty string', () => {
    const matcher = new RegexMatcher();
    const start = Date.now();
    const spans = matcher.match('xxxxx', regexRule('(?:)', 'g'));
    expect(Date.now() - start).toBeLessThan(1000);
    expect(spans).toEqual([]);
  });

  it('caps total matches at MAX_MATCHES_PER_RULE instead of growing unbounded', () => {
    const matcher = new RegexMatcher();
    const text = 'a'.repeat(20_000);
    const spans = matcher.match(text, regexRule('a', 'g'));
    expect(spans.length).toBe(10_000);
  });

  it('still returns correct spans for a normal global rule (no regression)', () => {
    const matcher = new RegexMatcher();
    const spans = matcher.match('foo bar foo', regexRule('foo', 'g'));
    expect(spans).toEqual([
      { start: 0, end: 3 },
      { start: 8, end: 11 },
    ]);
  });

  it('still returns the correct captureGroup span (no regression)', () => {
    const matcher = new RegexMatcher();
    const spans = matcher.match('key=secret123', regexRule('key=(\\w+)', 'g', 1));
    expect(spans).toEqual([{ start: 4, end: 13 }]);
  });

  it('does not hang on a non-global pattern whose captureGroup never participates', () => {
    const matcher = new RegexMatcher();
    const start = Date.now();
    // captureGroup 1 never participates when "b" matches (group 2 does) — the
    // old `continue`-on-falsy-group path re-ran the same non-global exec() forever.
    const spans = matcher.match('b', regexRule('(a)|(b)', '', 1));
    expect(Date.now() - start).toBeLessThan(1000);
    expect(spans).toEqual([]);
  });
});
