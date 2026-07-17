import type { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { KeywordMatcher } from '../../src/matchers/keyword.ts';

// Constructed as plain objects (not Rule.parse()) — the matcher must stay safe
// on its own even if a keyword somehow bypasses schema validation (the
// empty-keyword reject lives in packages/schema's KeywordMatcher).
function keywordRule(keywords: string[], caseSensitive?: boolean): Rule {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords, caseSensitive: caseSensitive ?? false },
  };
}

// Spans are only meaningful against the text they were found in.
function slices(text: string, rule: Rule): string[] {
  return new KeywordMatcher().match(text, rule).map((s) => text.slice(s.start, s.end));
}

describe('KeywordMatcher', () => {
  it('returns spans that index the original text, not a case-folded copy', () => {
    const matcher = new KeywordMatcher();
    // "İ".toLowerCase() is two code units, so a lowercased haystack is one char
    // longer than the input. Searching that copy while sizing the span with the
    // original keyword's length shifted every later span by one, which made
    // redact() mask the wrong characters and leak the match's first char.
    const text = 'İ my password is hunter2';
    expect(matcher.match(text, keywordRule(['password']))).toEqual([{ start: 5, end: 13 }]);
    expect(slices(text, keywordRule(['password']))).toEqual(['password']);
  });

  it('keeps spans aligned for every keyword after a length-changing char', () => {
    const text = 'İ password ﬁ secret';
    expect(slices(text, keywordRule(['password', 'secret']))).toEqual(['password', 'secret']);
  });

  it('measures the span from the matched text, not the keyword', () => {
    // The matched run and the keyword can differ under case-folding; the span
    // must describe what is actually in `text`.
    expect(slices('the STRASSE sign', keywordRule(['strasse']))).toEqual(['STRASSE']);
  });

  it('matches case-insensitively by default', () => {
    const matcher = new KeywordMatcher();
    expect(matcher.match('MY PASSWORD', keywordRule(['password']))).toEqual([
      { start: 3, end: 11 },
    ]);
  });

  it('honours caseSensitive', () => {
    const matcher = new KeywordMatcher();
    expect(matcher.match('MY PASSWORD', keywordRule(['password'], true))).toEqual([]);
    expect(matcher.match('my password', keywordRule(['password'], true))).toEqual([
      { start: 3, end: 11 },
    ]);
  });

  it('treats regex metacharacters in a keyword as literal text', () => {
    // Bundled rules ship keywords containing regex syntax — core-code-context/
    // db-table-name has "SELECT * FROM ", core-financial/salary has "i make $".
    // Unescaped, "*" would quantify the preceding space and "$" would anchor.
    expect(slices('SELECT * FROM users', keywordRule(['SELECT * FROM ']))).toEqual([
      'SELECT * FROM ',
    ]);
    expect(slices('SELECT COUNT(*) FROM t', keywordRule(['SELECT COUNT(*) FROM ']))).toEqual([
      'SELECT COUNT(*) FROM ',
    ]);
    expect(slices('i make $200k', keywordRule(['i make $']))).toEqual(['i make $']);
  });

  it('does not let a metacharacter keyword match as a pattern', () => {
    const matcher = new KeywordMatcher();
    // "SELECT * FROM " as a live pattern would match "SELECTFROM " (zero spaces).
    expect(matcher.match('SELECTFROM users', keywordRule(['SELECT * FROM ']))).toEqual([]);
    // "i make $" anchored would match at end-of-input after "i make ".
    expect(matcher.match('i make ', keywordRule(['i make $']))).toEqual([]);
  });

  it('returns one span per non-overlapping occurrence', () => {
    const matcher = new KeywordMatcher();
    expect(matcher.match('foo bar foo', keywordRule(['foo']))).toEqual([
      { start: 0, end: 3 },
      { start: 8, end: 11 },
    ]);
  });

  it('advances past a self-overlapping keyword instead of re-matching it', () => {
    const matcher = new KeywordMatcher();
    // The `g`-advance keeps only the leading occurrence of a self-overlapping
    // keyword ("aa" in "aaa"). Four bundled keywords do self-overlap with a
    // 1-char border — "todo-secret", "shipping address", and the two name-field
    // keywords in core-pii/name — so on a contrived doubled input the change is
    // observable: "shipping addresshipping address" now yields one span, where
    // the old traversal yielded two. Accepted because the un-redacted remainder
    // is the keyword's own tail, never a third-party secret, and `g`-advance is
    // the correct regex semantics. Verified below.
    expect(matcher.match('aaa', keywordRule(['aa']))).toEqual([{ start: 0, end: 2 }]);
  });

  it('drops the overlapping second match of a self-bordering bundled keyword', () => {
    const matcher = new KeywordMatcher();
    // Pins the real behaviour the comment above describes: the surviving text is
    // the keyword's own suffix ("hipping address"), not leaked third-party data.
    const spans = matcher.match(
      'shipping addresshipping address',
      keywordRule(['shipping address']),
    );
    expect(spans).toEqual([{ start: 0, end: 16 }]);
  });

  it('folds "ß"/"ẞ" under the u flag, which a plain i regex would drop', () => {
    // "ß" and "ẞ" fold to each other under the regex `u` flag but not under a
    // plain `i` regex. The old case-folded-copy matcher folded them too (via
    // toLowerCase), so `u` is what keeps parity here rather than adding folding.
    expect(slices('the ẞ here', keywordRule(['ß']))).toEqual(['ẞ']);
    expect(slices('the ß here', keywordRule(['ẞ']))).toEqual(['ß']);
  });

  it('skips an empty keyword that bypasses schema validation', () => {
    const matcher = new KeywordMatcher();
    const start = Date.now();
    // An empty keyword matches at every position without advancing lastIndex.
    // Under the `u` flag a manual bump lands mid-surrogate and snaps back to
    // the code-point boundary, re-matching the same index forever — so the
    // keyword is skipped outright rather than walked.
    expect(matcher.match('hello 🔑 world', keywordRule(['']))).toEqual([]);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('still matches the other keywords when one is empty', () => {
    expect(slices('my password', keywordRule(['', 'password']))).toEqual(['password']);
  });

  it('returns no spans for a non-keyword matcher', () => {
    const matcher = new KeywordMatcher();
    const rule: Rule = {
      specVersion: 1,
      id: 'test-pack/test-rule',
      name: 'test',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'foo', flags: 'g' },
    };
    expect(matcher.match('foo', rule)).toEqual([]);
  });
});
