import type { Span } from '@akasecurity/schema';

// ---------------------------------------------------------------------------
// Invisible Unicode "format" characters (General_Category=Cf) inside a match.
//
// One ZERO WIDTH SPACE (U+200B) planted mid-secret defeats every regex and
// keyword rule character-for-character while leaving the secret fully usable
// after trivial cleanup — a browser, an editor, or `.replace(/\s/g, '')` never
// even shows it. Nothing upstream of this package normalizes text before
// matching, so scan() has to.
//
// \p{Cf} is used EXACTLY as the JS engine's Unicode Character Database
// defines it (170 code points as of this Unicode version) — no characters
// added or removed by hand. That set covers exactly the families a real
// attack or a real accident would use: zero-width space/joiners (U+200B,
// U+200C, U+200D), the word joiner (U+2060), the byte-order mark used
// mid-string as a zero-width no-break space (U+FEFF), the soft hyphen
// (U+00AD), bidi embedding/override/isolate controls (U+202A-U+202E,
// U+2066-U+2069), Arabic number-sign/letter-mark controls (U+0600-U+0605,
// U+061C, U+06DD, U+0890-U+0891, U+08E2), invisible math operators
// (U+2061-U+2064), interlinear annotation anchors (U+FFF9-U+FFFB), and
// Unicode "tag" characters (U+E0001, U+E0020-U+E007F — the mechanism behind
// invisible flag-emoji payloads and a documented text-smuggling vector).
// Using the whole category rather than a hand-picked list also means this
// stays correct as Unicode's format-character inventory grows, rather than
// silently falling out of date against it.
//
// Two related characters are deliberately NOT stripped, because neither is
// actually invisible-format: variation selectors (U+FE00-U+FE0F, general
// category Mn) select a glyph variant (e.g. text vs. emoji presentation)
// rather than vanishing, and ordinary whitespace (category Zs/Zl/Zp) is
// exactly that — ordinary and visible-width. Stripping either would risk
// corrupting visible rendering rather than only defeating detection, which is
// out of scope for this fix.
const HAS_FORMAT_CHAR = /\p{Cf}/u;

export interface FormatCharNormalization {
  /** `text` with every \p{Cf} character removed. */
  readonly normalized: string;
  /**
   * One entry per UTF-16 code unit of `normalized` — so it lines up directly
   * with matcher span offsets, which are UTF-16 indices — giving the original
   * index that normalized-text position corresponds to. A position at
   * `normalized.length` (i.e. `indexMap.length`) has no entry; map it to the
   * original text's own length instead (see `mapSpanToOriginal`).
   */
  readonly indexMap: readonly number[];
}

/**
 * Strips every \p{Cf} character out of `text` for matching purposes, and
 * records how to map an offset found in the result back onto `text`.
 *
 * Returns `undefined` when there is nothing to strip — the fast path scan()
 * takes on ordinary input: one regex test, no allocation, no map built.
 */
export function normalizeFormatChars(text: string): FormatCharNormalization | undefined {
  if (!HAS_FORMAT_CHAR.test(text)) return undefined;

  const normalizedParts: string[] = [];
  const indexMap: number[] = [];
  let i = 0;
  while (i < text.length) {
    // Walk by code point, not by UTF-16 code unit: a \p{Cf} match is a single
    // logical character even when (rarely — the Egyptian hieroglyph and
    // musical-symbol format controls, and the U+E0001/U+E0020-E007F tag
    // characters) it takes a surrogate pair to represent. Slicing at a code
    // unit that splits a pair would corrupt both the kept text and the map.
    const codePoint = text.codePointAt(i);
    const charLength = codePoint !== undefined && codePoint > 0xffff ? 2 : 1;
    const char = text.slice(i, i + charLength);
    if (!HAS_FORMAT_CHAR.test(char)) {
      normalizedParts.push(char);
      indexMap.push(i);
      // A kept astral character occupies two UTF-16 units in `normalized`
      // too, so it needs two map entries to keep index-for-index alignment.
      if (charLength === 2) indexMap.push(i + 1);
    }
    i += charLength;
  }
  return { normalized: normalizedParts.join(''), indexMap };
}

/**
 * Maps a `Span` found in normalized-text index space back onto the original
 * text `normalization` was built from.
 *
 * `start` is `indexMap[span.start]` — the original index of the match's own
 * first character. `end` is exclusive, so the match's own LAST character sits
 * at normalized position `end - 1`; mapping THAT through `indexMap` and
 * adding one gives the original index one past it. Any run of format
 * characters that sat between two normalized-adjacent matched characters —
 * i.e. genuinely inside the match — falls inside `[start, end)` this way,
 * because `indexMap` jumps straight over it. A format-character run that
 * comes immediately AFTER the match's last character (before the next kept
 * character) is deliberately left OUT: it sits outside what was actually
 * matched, so folding it in would over-redact into whatever follows,
 * including a second, unrelated finding starting right after it. A span
 * reaching the very end of the normalized text is the one case with no
 * "next kept character" to stop at, so it maps to the original text's own
 * length — pulling in any trailing format characters at the true end of the
 * input, which mirrors how a match starting at the very beginning already
 * pulls in a leading run via `indexMap[0]`.
 */
export function mapSpanToOriginal(
  span: Span,
  normalization: FormatCharNormalization,
  originalLength: number,
): Span {
  const { indexMap } = normalization;
  // `indexMap[span.start] ?? originalLength` doubles as the bounds check: an
  // in-range `start` always resolves to a real (possibly zero) original
  // offset, and only `start === indexMap.length` (an empty span at the very
  // end — never produced by a matcher, but handled rather than assumed away)
  // falls through to the fallback.
  const start = indexMap[span.start] ?? originalLength;
  // `end` needs its "ran off the map" check kept SEPARATE from the indexed
  // read, unlike `start` above: `span.end - 1` is the index of the match's
  // own last character, and when `span.end === indexMap.length` that index is
  // `indexMap.length - 1` — the map's LAST element, still very much in
  // bounds — so `?? fallback` on the read alone could never tell "reaches the
  // very end" apart from an ordinary in-bounds read. The `span.end <
  // indexMap.length` check is what actually draws that line; `??` only
  // covers TypeScript's `noUncheckedIndexedAccess` typing of a read this
  // branch has already proven safe.
  // `span.end - 1` is never negative: the matchers never record a zero-length
  // span (see matchers/regex.ts and matchers/keyword.ts), so span.end is
  // always at least span.start + 1.
  const end =
    span.end < indexMap.length
      ? (indexMap[span.end - 1] ?? originalLength - 1) + 1
      : originalLength;
  return { start, end };
}
