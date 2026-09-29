import { describe, expect, it } from 'vitest';

import { mergeOverlappingSameRule } from '../src/engine.ts';
import { mapSpanToOriginal, normalizeFormatChars } from '../src/format-chars.ts';
import type { MatchResult } from '../src/types.ts';
import { FORMAT_CHARS, ZWJ, ZWNJ, ZWSP } from './helpers/format-chars.ts';

describe('normalizeFormatChars', () => {
  it('returns undefined on text with no format character — the fast path', () => {
    expect(normalizeFormatChars('plain ASCII text, nothing invisible here')).toBeUndefined();
    expect(normalizeFormatChars('unicode but not Cf: héllo wörld 🔑')).toBeUndefined();
    expect(normalizeFormatChars('')).toBeUndefined();
  });

  it.each(FORMAT_CHARS)('strips %s out of the normalized text', (_label, char) => {
    const result = normalizeFormatChars(`AB${char}CD`);
    expect(result).toBeDefined();
    expect(result?.normalized).toBe('ABCD');
  });

  it('strips every format character in a run, not just the first', () => {
    const result = normalizeFormatChars(`A${ZWSP}${ZWNJ}${ZWJ}B`);
    expect(result?.normalized).toBe('AB');
  });

  it('strips a leading and a trailing format character', () => {
    const result = normalizeFormatChars(`${ZWSP}ABC${ZWSP}`);
    expect(result?.normalized).toBe('ABC');
  });

  it('produces an all-stripped empty normalized string without throwing', () => {
    const result = normalizeFormatChars(`${ZWSP}${ZWNJ}${ZWJ}`);
    expect(result?.normalized).toBe('');
    expect(result?.segments).toEqual([]);
  });

  it('does not strip ordinary whitespace or visible characters', () => {
    expect(normalizeFormatChars(`a b\tc\nd${ZWSP}e`)?.normalized).toBe('a b\tc\nde');
  });

  it('does not strip a variation selector (Mn, not Cf)', () => {
    // U+FE0F VARIATION SELECTOR-16 forces emoji presentation; it is not Cf and
    // must survive normalization even though it renders with no width of its
    // own in plain text.
    const vs16 = String.fromCodePoint(0xfe0f);
    const withVs = `x${ZWSP}y${vs16}`;
    const result = normalizeFormatChars(withVs);
    expect(result?.normalized).toBe(`xy${vs16}`);
  });

  it('handles an astral (surrogate-pair) character alongside a format character', () => {
    const result = normalizeFormatChars(`🔑${ZWSP}password`);
    expect(result?.normalized).toBe('🔑password');
    // The astral char is 2 UTF-16 units, both kept inside the same leading
    // segment: origStart 0, length 2 — covering normalized positions 0 and 1.
    expect(result?.segments[0]).toEqual({ normStart: 0, origStart: 0, length: 2 });
  });
});

describe('mapSpanToOriginal', () => {
  it('maps a span entirely before any format character unchanged', () => {
    const text = `AB${ZWSP}CD`;
    const normalization = normalizeFormatChars(text);
    expect(normalization).toBeDefined();
    if (!normalization) return;
    // normalized = "ABCD"; span [0,2) covers "AB"
    expect(mapSpanToOriginal({ start: 0, end: 2 }, normalization)).toEqual({
      start: 0,
      end: 2,
    });
  });

  it('maps a span that straddles a stripped character to include it', () => {
    const text = `AB${ZWSP}CD`; // indices: A0 B1 ZWSP2 C3 D4
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    // normalized = "ABCD"; span [1,3) covers "BC" in normalized space, i.e.
    // originally B, the stripped char, then C — the stripped char must be
    // swallowed into the span.
    const mapped = mapSpanToOriginal({ start: 1, end: 3 }, normalization);
    expect(mapped).toEqual({ start: 1, end: 4 });
    expect(text.slice(mapped.start, mapped.end)).toBe(`B${ZWSP}C`);
  });

  it('maps a span reaching the end of normalized text TIGHTLY, excluding a trailing stripped char', () => {
    // Regression guard: a version of this mapping used to special-case "the
    // match reaches the end of the normalized text" by extending `end` all
    // the way to the original text's own length, pulling the trailing ZWSP
    // into the span even though it sits AFTER the match's own last character
    // — the same over-inclusion the "straddles" case above deliberately does
    // NOT apply to a run before the match's first character. That special
    // case is gone: this must match what the unmodified (no format-character
    // handling at all) engine finds for `\bAKIA...{16}\b` against
    // "AKIA...EXAMPLE<ZWSP> end" — exactly the 20-char secret, nothing more.
    const text = `AB${ZWSP}CD${ZWSP}`;
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    // normalized = "ABCD" (length 4); span [2,4) covers "CD" only.
    const mapped = mapSpanToOriginal({ start: 2, end: 4 }, normalization);
    expect(mapped).toEqual({ start: 3, end: 5 });
    expect(text.slice(mapped.start, mapped.end)).toBe('CD');
  });

  it('maps a leading stripped run out of a span starting at 0', () => {
    const text = `${ZWSP}ABC`;
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    const mapped = mapSpanToOriginal({ start: 0, end: 3 }, normalization);
    expect(mapped).toEqual({ start: 1, end: 4 });
    expect(text.slice(mapped.start, mapped.end)).toBe('ABC');
  });
});

describe('mergeOverlappingSameRule', () => {
  const text = 'abcdefghijklmnopqrstuvwxyz';
  const finding = (ruleId: string, start: number, end: number, confidence = 1): MatchResult => ({
    ruleId,
    category: 'secret',
    severity: 'high',
    span: { start, end },
    rawMatch: text.slice(start, end),
    confidence,
  });

  it('returns an empty list unchanged', () => {
    expect(mergeOverlappingSameRule([], text)).toEqual([]);
  });

  it('leaves a single, non-overlapping finding alone', () => {
    const merged = mergeOverlappingSameRule([finding('r', 2, 8)], text);
    expect(merged).toEqual([finding('r', 2, 8)]);
  });

  it('keeps the union of two partly overlapping same-rule spans of equal width', () => {
    // Keeping only one of [2,8) and [5,11) would leave 3 characters of the
    // other one outside the span that redact() replaces.
    const merged = mergeOverlappingSameRule([finding('r', 2, 8), finding('r', 5, 11)], text);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.span).toEqual({ start: 2, end: 11 });
    expect(merged[0]?.rawMatch).toBe(text.slice(2, 11));
  });

  it('keeps a contained span as the wider one', () => {
    const merged = mergeOverlappingSameRule([finding('r', 4, 6), finding('r', 2, 10)], text);
    expect(merged.map((f) => f.span)).toEqual([{ start: 2, end: 10 }]);
  });

  it('keeps overlapping findings of different rules apart, and keeps non-overlapping ones separate', () => {
    const merged = mergeOverlappingSameRule(
      [finding('a', 2, 8), finding('b', 5, 11), finding('a', 20, 24)],
      text,
    );
    expect(merged.map((f) => [f.ruleId, f.span.start, f.span.end])).toEqual([
      ['a', 2, 8],
      ['a', 20, 24],
      ['b', 5, 11],
    ]);
  });

  it('merges a THIRD finding that only overlaps the region the first two already widened into', () => {
    // The exact non-transitivity gap: [0,5) and [4,9) merge to an open
    // region [0,9); a third finding [8,12) does not overlap [0,5) or [4,9)
    // individually, but DOES overlap the region those two produced together.
    // A pairwise "fold into the first overlap, then stop" merge leaves this
    // as two overlapping findings — [0,9) and [8,12) — instead of one.
    const merged = mergeOverlappingSameRule(
      [finding('r', 0, 5), finding('r', 4, 9), finding('r', 8, 12)],
      text,
    );
    expect(merged).toHaveLength(1);
    expect(merged[0]?.span).toEqual({ start: 0, end: 12 });
    expect(merged[0]?.rawMatch).toBe(text.slice(0, 12));
  });

  it('is insensitive to the input order of a same-rule overlapping group', () => {
    const merged = mergeOverlappingSameRule(
      [finding('r', 8, 12), finding('r', 0, 5), finding('r', 4, 9)],
      text,
    );
    expect(merged).toHaveLength(1);
    expect(merged[0]?.span).toEqual({ start: 0, end: 12 });
  });

  it('keeps the higher confidence of a merged group', () => {
    const merged = mergeOverlappingSameRule(
      [finding('r', 2, 8, 0.9), finding('r', 5, 11, 0.99)],
      text,
    );
    expect(merged[0]?.confidence).toBe(0.99);
  });

  it('scales close to n log n, not n², on a single rule with many overlapping pairs', () => {
    // A pairwise "check the candidate against every finding kept so far"
    // merge costs O(n²) in the FINDING COUNT, not in how many of them
    // overlap: the inner loop scans from index 0 every time regardless of
    // where (or whether) a match turns up, so its cost is driven by how
    // long the kept list has grown, which for one rule grows close to n
    // even when most pairs merge down to one entry. Spreading findings
    // across many DIFFERENT rules (as an earlier version of this test did)
    // keeps each rule's kept list short and so stays close to the old
    // algorithm's CHEAPEST case — 20,000 findings over 50 rules merged in
    // 598.5ms against a 2000ms ceiling with the old algorithm restored, more
    // than 3x of headroom that never actually exercises the bug. One rule,
    // with findings that overlap in ADJACENT PAIRS (not one giant run, and
    // not the artificial best case of no overlaps at all — the shape a
    // cross-pass duplicate from scan() actually produces), does.
    //
    // A RATIO, not a fixed ceiling, for the same reason as the scan()-level
    // sibling check in unicode.test.ts: this must hold on a runner tens of
    // times slower than a dev machine. O(n log n) costs a 10x-larger input
    // roughly 10x-15x as long (the log factor); O(n²) costs it roughly
    // 100x. 30x sits with real margin on both sides.
    function buildOverlappingPairs(n: number, text: string): MatchResult[] {
      const findings: MatchResult[] = [];
      for (let i = 0; i < n; i += 2) {
        // Pair i occupies [3i, 3i+6); the next pair starts exactly where
        // this one ends, so pairs merge internally but never into each
        // other — n/2 disjoint two-member groups, not one giant region.
        const base = i * 3;
        findings.push({
          ruleId: 'r',
          category: 'secret',
          severity: 'high',
          span: { start: base, end: base + 4 },
          rawMatch: text.slice(base, base + 4),
          confidence: 1,
        });
        findings.push({
          ruleId: 'r',
          category: 'secret',
          severity: 'high',
          span: { start: base + 2, end: base + 6 },
          rawMatch: text.slice(base + 2, base + 6),
          confidence: 1,
        });
      }
      return findings;
    }

    function timeMerge(n: number): number {
      const bigText = 'x'.repeat(n * 3 + 10);
      const findings = buildOverlappingPairs(n, bigText);
      const start = performance.now();
      const merged = mergeOverlappingSameRule(findings, bigText);
      const ms = performance.now() - start;
      expect(merged).toHaveLength(n / 2);
      return ms;
    }

    const small = timeMerge(2_000);
    const large = timeMerge(20_000); // 10x the input
    expect(
      large,
      `2,000 findings: ${small.toFixed(1)}ms; 20,000 findings: ${large.toFixed(1)}ms`,
    ).toBeLessThan(Math.max(small, 1) * 30);
  });
});
