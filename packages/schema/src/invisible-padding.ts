// Invisible characters that carry no text of their own and can be planted
// inside a value without changing how it reads: zero-width space, word joiner,
// byte-order mark used mid-string, soft hyphen, the left-to-right,
// right-to-left and Arabic letter marks, bidi embedding/override/isolate
// controls, invisible math operators, the Mongolian vowel separator, the
// interlinear annotation controls (U+FFF9-U+FFFB), and Unicode "tag"
// characters.
//
// This is the set a value's IDENTITY ignores — the fingerprint behind
// exceptions, grants, vault reveal grants and finding keys — so one secret seen
// clean and seen padded is one secret. A finding's masked preview
// (`maskMatch` in the detections package) ignores it too, so a finding key that
// falls back to the preview agrees with the fingerprint on what is padding.
//
// It is deliberately NARROWER than the set detection strips before matching
// (every General_Category=Cf character, see the detections package). Matching
// only has to find the value, so over-stripping is harmless there. Identity
// decides that two values are the same credential, so it must not merge values
// that differ by a character that means something:
//  - ZWJ/ZWNJ (U+200D, U+200C) join or separate letters in several scripts;
//  - the Arabic prepended concatenation marks (U+0600-U+0605, U+06DD, ...)
//    render as visible glyphs;
//  - variation selectors and ordinary whitespace are not format characters.
// The consequence is an asymmetry that is intended: a match containing one of
// those keeps it in its identity, even though matching looked past it.
// Every code point listed here must also be stripped by the matching
// normalizer, so the identity set is a subset of the matching set; a test in the
// detections package pins that.
//
// Pure: no I/O, no dependencies. A global regex is used only through
// `String.prototype.replace`, which resets its cursor; it is never `.test()`ed.
const INVISIBLE_PADDING =
  /[\u00AD\u061C\u180E\u200B\u200E\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF\uFFF9-\uFFFB\u{E0001}\u{E0020}-\u{E007F}]/gu;

/** `text` with every invisible padding character removed. */
export function stripInvisiblePadding(text: string): string {
  return text.replace(INVISIBLE_PADDING, '');
}
