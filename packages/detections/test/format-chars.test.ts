import { describe, expect, it } from 'vitest';

import { mapSpanToOriginal, normalizeFormatChars } from '../src/format-chars.ts';

// A representative sample of \p{Cf} — not the whole 170-member category (see
// format-chars.ts for the full picture), but every family a real attack or a
// real accident is likely to use: ZW*, word joiner, BOM, soft hyphen, bidi
// embedding/override/isolate controls, and a Unicode "tag" character (the
// mechanism behind invisible flag-emoji payloads).
const FORMAT_CHARS: readonly (readonly [string, string])[] = [
  ['U+200B zero width space', '​'],
  ['U+200C zero width non-joiner', '‌'],
  ['U+200D zero width joiner', '‍'],
  ['U+2060 word joiner', '⁠'],
  ['U+FEFF byte order mark', '﻿'],
  ['U+00AD soft hyphen', '­'],
  ['U+202A left-to-right embedding', '‪'],
  ['U+202E right-to-left override', '‮'],
  ['U+2066 left-to-right isolate', '⁦'],
  ['U+2069 pop directional isolate', '⁩'],
  ['U+E0020 tag space', '\u{E0020}'],
];

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
    const result = normalizeFormatChars('A​‌‍B');
    expect(result?.normalized).toBe('AB');
  });

  it('strips a leading and a trailing format character', () => {
    const result = normalizeFormatChars('​ABC​');
    expect(result?.normalized).toBe('ABC');
  });

  it('produces an all-stripped empty normalized string without throwing', () => {
    const result = normalizeFormatChars('​‌‍');
    expect(result?.normalized).toBe('');
    expect(result?.indexMap).toEqual([]);
  });

  it('does not strip ordinary whitespace or visible characters', () => {
    expect(normalizeFormatChars('a b\tc\nd​e')?.normalized).toBe('a b\tc\nde');
  });

  it('does not strip a variation selector (Mn, not Cf)', () => {
    // U+FE0F VARIATION SELECTOR-16 forces emoji presentation; it is not Cf and
    // must survive normalization even though it renders with no width of its
    // own in plain text.
    const withVs = 'x​y️';
    const result = normalizeFormatChars(withVs);
    expect(result?.normalized).toBe('xy️');
  });

  it('handles an astral (surrogate-pair) character alongside a format character', () => {
    const result = normalizeFormatChars('🔑​password');
    expect(result?.normalized).toBe('🔑password');
    // The astral char is 2 UTF-16 units, so it needs 2 index-map entries to
    // stay index-for-index aligned with `normalized` — one per unit, each
    // pointing at THAT unit's own original index (0 and 1), not both at 0.
    expect(result?.indexMap.slice(0, 2)).toEqual([0, 1]);
  });
});

describe('mapSpanToOriginal', () => {
  it('maps a span entirely before any format character unchanged', () => {
    const text = 'AB​CD';
    const normalization = normalizeFormatChars(text);
    expect(normalization).toBeDefined();
    if (!normalization) return;
    // normalized = "ABCD"; span [0,2) covers "AB"
    expect(mapSpanToOriginal({ start: 0, end: 2 }, normalization, text.length)).toEqual({
      start: 0,
      end: 2,
    });
  });

  it('maps a span that straddles a stripped character to include it', () => {
    const text = 'AB​CD'; // indices: A0 B1 ZWSP2 C3 D4
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    // normalized = "ABCD"; span [1,3) covers "BC" in normalized space, i.e.
    // originally B, the stripped char, then C — the stripped char must be
    // swallowed into the span.
    const mapped = mapSpanToOriginal({ start: 1, end: 3 }, normalization, text.length);
    expect(mapped).toEqual({ start: 1, end: 4 });
    expect(text.slice(mapped.start, mapped.end)).toBe('B​C');
  });

  it('maps a span reaching the end of normalized text to the end of the original', () => {
    const text = 'AB​CD​';
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    // normalized = "ABCD" (length 4); span [2,4) is the whole tail "CD" plus
    // the trailing stripped char, so it must reach the original's full length.
    const mapped = mapSpanToOriginal({ start: 2, end: 4 }, normalization, text.length);
    expect(mapped).toEqual({ start: 3, end: 6 });
    expect(text.slice(mapped.start, mapped.end)).toBe('CD​');
  });

  it('maps a leading stripped run out of a span starting at 0', () => {
    const text = '​ABC';
    const normalization = normalizeFormatChars(text);
    if (!normalization) throw new Error('expected normalization');
    const mapped = mapSpanToOriginal({ start: 0, end: 3 }, normalization, text.length);
    expect(mapped).toEqual({ start: 1, end: 4 });
    expect(text.slice(mapped.start, mapped.end)).toBe('ABC');
  });
});
