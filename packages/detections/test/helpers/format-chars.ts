// Every \p{Cf} character used across the detections test suite, built with
// `String.fromCodePoint()` rather than a raw literal or a `\u` escape pasted
// into a string. A raw invisible/bidi control character sitting directly in
// a string literal is invisible to a reviewer, trips GitHub's hidden-bidi-
// text warning for the RTL/LRI/PDI controls (and visibly reorders the rest
// of the line in an editor for U+202E), and could be silently stripped by an
// editor or formatter configured to clean up zero-width characters — turning
// the case into one that passes without testing anything. A numeric
// codepoint call has none of those failure modes and is exactly as readable
// as a `\u` escape.
//
// Shared here rather than duplicated per test file: two independent copies
// of "the representative \p{Cf} sample" had already drifted apart (one had
// U+202A and U+2069, the other did not).
export const ZWSP = String.fromCodePoint(0x200b); // ZERO WIDTH SPACE
export const ZWNJ = String.fromCodePoint(0x200c); // ZERO WIDTH NON-JOINER
export const ZWJ = String.fromCodePoint(0x200d); // ZERO WIDTH JOINER
export const WORD_JOINER = String.fromCodePoint(0x2060);
export const BOM = String.fromCodePoint(0xfeff); // BYTE ORDER MARK
export const SOFT_HYPHEN = String.fromCodePoint(0x00ad);
export const LRE = String.fromCodePoint(0x202a); // LEFT-TO-RIGHT EMBEDDING
export const RLO = String.fromCodePoint(0x202e); // RIGHT-TO-LEFT OVERRIDE
export const LRI = String.fromCodePoint(0x2066); // LEFT-TO-RIGHT ISOLATE
export const PDI = String.fromCodePoint(0x2069); // POP DIRECTIONAL ISOLATE
export const TAG_SPACE = String.fromCodePoint(0xe0020);

/**
 * A representative sample of \p{Cf} — not the whole category (see
 * `src/format-chars.ts` for the full picture, and why no exact count is
 * given for it) — but every family a real attack or a real accident is
 * likely to use: ZW*, the word joiner, the BOM, the soft hyphen, bidi
 * embedding/override/isolate controls, and a Unicode "tag" character (the
 * mechanism behind invisible flag-emoji payloads).
 */
export const FORMAT_CHARS: readonly (readonly [string, string])[] = [
  ['U+200B zero width space', ZWSP],
  ['U+200C zero width non-joiner', ZWNJ],
  ['U+200D zero width joiner', ZWJ],
  ['U+2060 word joiner', WORD_JOINER],
  ['U+FEFF byte order mark', BOM],
  ['U+00AD soft hyphen', SOFT_HYPHEN],
  ['U+202A left-to-right embedding', LRE],
  ['U+202E right-to-left override', RLO],
  ['U+2066 left-to-right isolate', LRI],
  ['U+2069 pop directional isolate', PDI],
  ['U+E0020 tag space', TAG_SPACE],
];
