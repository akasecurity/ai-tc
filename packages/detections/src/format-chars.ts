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
// defines it — no characters added or removed by hand, so this stays correct
// as Unicode's format-character inventory grows rather than silently falling
// out of date against it (a fixed count pinned here would go stale on the
// next Unicode update, so none is given). That class covers exactly the
// families a real attack or a real accident would use: zero-width
// space/joiners (U+200B, U+200C, U+200D), the word joiner (U+2060), the
// byte-order mark used mid-string as a zero-width no-break space (U+FEFF),
// the soft hyphen (U+00AD), bidi embedding/override/isolate controls
// (U+202A-U+202E, U+2066-U+2069), invisible math operators (U+2061-U+2064),
// interlinear annotation anchors (U+FFF9-U+FFFB), and Unicode "tag"
// characters (U+E0001, U+E0020-U+E007F — the mechanism behind invisible
// flag-emoji payloads and a documented text-smuggling vector).
//
// Not every \p{Cf} character is actually invisible: the Arabic "prepended
// concatenation marks" (U+0600-U+0605, U+061C, U+06DD, U+0890-U+0891,
// U+08E2, U+110BD, U+110CD) render as visible glyphs (a percent sign, a
// currency mark, a stop) in the scripts that use them. Stripping them is
// still harmless for matching — it never touches ordinary whitespace or a
// character any OTHER script renders visibly — but "invisible" is not why
// they belong in this set; being a zero-width-or-visible FORMAT character
// that a matcher's `\b`/lookaround treats as a plain non-word separator is.
//
// Two related categories are deliberately NOT stripped: variation selectors
// (U+FE00-U+FE0F, general category Mn) select a glyph variant (e.g. text vs.
// emoji presentation) rather than acting as a separator, and ordinary
// whitespace (category Zs/Zl/Zp) is exactly that — ordinary and
// visible-width. Stripping either would risk corrupting visible rendering
// rather than only defeating detection, which is out of scope for this fix.
const HAS_FORMAT_CHAR = /\p{Cf}/u;
// Same class, `g` flag: used to walk every format character's position in one
// native regex scan (see `normalizeFormatChars`) rather than testing each
// code point individually. `u` still makes each match exactly one code point
// — one or two UTF-16 units — never a split surrogate half.
const FORMAT_CHAR_GLOBAL = /\p{Cf}/gu;

// A contiguous run of KEPT (non-stripped) characters: `length` UTF-16 units
// starting at `origStart` in the original text, sitting at `normStart` in the
// normalized text. Segments are stored instead of one entry per UTF-16 unit
// so this stays O(number of stripped runs) in memory — a handful for any
// real input — rather than O(text length): a 1 MB file with one leading BOM
// used to push roughly a million numbers into a growable array just to map a
// handful of spans back.
interface Segment {
  readonly normStart: number;
  readonly origStart: number;
  readonly length: number;
}

export interface FormatCharNormalization {
  /** `text` with every \p{Cf} character removed. */
  readonly normalized: string;
  /**
   * Kept-character runs. Two orderings hold, and each reader relies on one:
   * ascending by `normStart` and gapless in normalized space (segment i+1's
   * `normStart` is exactly segment i's `normStart + length`), which
   * `segmentAt` (so `mapSpanToOriginal`) binary-searches; and ascending by
   * `origStart`, non-overlapping in original space, which `normalizedOffset`
   * (so `mapSpanToNormalized`) binary-searches. Both follow from
   * `normalizeFormatChars` walking the text left to right and emitting one
   * segment per kept run; anything that builds segments another way must keep
   * both. Empty when the text is made only of format characters.
   */
  readonly segments: readonly Segment[];
}

/**
 * Strips every \p{Cf} character out of `text` for matching purposes, and
 * records how to map an offset found in the result back onto `text`.
 *
 * Returns `undefined` when there is nothing to strip — the fast path scan()
 * takes on ordinary input: one regex test, no allocation, no segments built.
 */
export function normalizeFormatChars(text: string): FormatCharNormalization | undefined {
  if (!HAS_FORMAT_CHAR.test(text)) return undefined;

  // One native regex scan over `text` locates every format character (never
  // more than a handful in real input); everything BETWEEN two of them — or
  // before the first / after the last — is copied and recorded as ONE
  // segment rather than tested and pushed code point by code point: real
  // input on the slow path is still overwhelmingly ordinary text around a
  // small number of format characters, not format characters throughout.
  const normalizedParts: string[] = [];
  const segments: Segment[] = [];
  let cursor = 0;
  let normLength = 0;
  for (const match of text.matchAll(FORMAT_CHAR_GLOBAL)) {
    const matchStart = match.index;
    if (matchStart > cursor) {
      const length = matchStart - cursor;
      normalizedParts.push(text.slice(cursor, matchStart));
      segments.push({ normStart: normLength, origStart: cursor, length });
      normLength += length;
    }
    cursor = matchStart + match[0].length;
  }
  if (cursor < text.length) {
    const length = text.length - cursor;
    normalizedParts.push(text.slice(cursor));
    segments.push({ normStart: normLength, origStart: cursor, length });
  }
  return { normalized: normalizedParts.join(''), segments };
}

// The segment whose kept run contains normalized position `normPos`. Binary
// search over `segments` (ascending, gapless, non-overlapping in normalized
// space), O(log k) where k is the number of stripped runs. `segments` is
// never empty here: the only caller passes a position taken from a span a
// matcher produced against `normalization.normalized`, and a matcher never
// produces a span outside the text it matched against — so some segment
// always covers it.
function segmentAt(segments: readonly Segment[], normPos: number): Segment {
  let lo = 0;
  let hi = segments.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const segment = segments[mid];
    if (segment !== undefined && normPos >= segment.normStart + segment.length) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  const found = segments[lo];
  if (found === undefined) {
    // Unreachable per the invariant above; a thrown error is preferable to a
    // silently wrong span if it is ever violated.
    throw new Error(`normPos ${String(normPos)} has no covering segment`);
  }
  return found;
}

/**
 * Maps a `Span` found in normalized-text index space back onto the original
 * text `normalization` was built from. Both ends are mapped the SAME way —
 * locate the covering segment, then offset from its `origStart` by the same
 * distance the position sits from its `normStart` — which is what keeps the
 * result TIGHT at both ends: a stripped run strictly BETWEEN two matched
 * characters is swallowed into the span (there is no segment gap to stop at
 * in between), while a stripped run immediately before the match's first
 * character or after its last is excluded (each end resolves through its OWN
 * matched character's segment, never a neighboring one). This holds even
 * when a match reaches the very start or the very end of the normalized
 * text: there is no special case for either edge, because a real original
 * text position exists for every character actually matched, and this never
 * needs to describe a character that was not.
 */
export function mapSpanToOriginal(span: Span, normalization: FormatCharNormalization): Span {
  const { segments } = normalization;
  const startSegment = segmentAt(segments, span.start);
  const start = startSegment.origStart + (span.start - startSegment.normStart);
  // `span.end` is exclusive, so the match's own last character sits at
  // `span.end - 1`; mapping that (never negative — see matchers/regex.ts and
  // matchers/keyword.ts, neither of which ever records a zero-length span)
  // and adding one gives the original index one past it.
  const endSegment = segmentAt(segments, span.end - 1);
  const end = endSegment.origStart + (span.end - 1 - endSegment.normStart) + 1;
  return { start, end };
}

// How many KEPT (non-stripped) characters lie before original position
// `origPos` — that position's index in the normalized text, with a position
// inside or at the start of a stripped run resolving to the next kept
// character. Binary search over `segments` (ascending by `origStart`, see
// `FormatCharNormalization.segments`), O(log k).
function normalizedOffset(origPos: number, segments: readonly Segment[]): number {
  let lo = 0;
  let hi = segments.length;
  // First segment whose kept run ends after `origPos`.
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const segment = segments[mid];
    if (segment !== undefined && segment.origStart + segment.length <= origPos) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  // `lo` can only reach `segments.length` for a position past the last kept
  // run (inside a trailing stripped run); clamping onto the last segment gives
  // the total normalized length there.
  const found = segments[Math.min(lo, segments.length - 1)];
  // No segments means the text is made only of format characters, so nothing
  // is kept and every position has zero kept characters before it. That is a
  // correct answer, not an invariant violation, so it is returned rather than
  // thrown (contrast `segmentAt`, whose caller holds a span a matcher found in
  // the normalized text, which cannot exist when that text is empty).
  if (found === undefined) return 0;
  return found.normStart + Math.min(Math.max(0, origPos - found.origStart), found.length);
}

/**
 * Maps a `Span` given in ORIGINAL-text coordinates onto the normalized text:
 * the inverse direction of `mapSpanToOriginal`. Each end becomes the count of
 * kept characters before it, so the result's length is the number of visible
 * characters the span covers, and the distance between two mapped spans is the
 * number of visible characters between them — the unit `windowChars` is
 * measured in. A span end sitting inside or at the start of a stripped run
 * resolves to the next kept character. O(log k); the engine calls it once per
 * candidate, never per pair.
 */
export function mapSpanToNormalized(span: Span, normalization: FormatCharNormalization): Span {
  const { segments } = normalization;
  return {
    start: normalizedOffset(span.start, segments),
    end: normalizedOffset(span.end, segments),
  };
}
