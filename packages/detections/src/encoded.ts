// Encoded-secret discovery: base64 runs and hex dumps decoded back to text so
// the secret rules can read what they encode. Covered shapes: base64 on one line
// or wrapped, plain hex (`xxd -p`), `xxd`, `hexdump -C`, plain `hexdump` and
// `od -x` (16-bit little-endian words), and `od -tx1` / `od -An -tx1` (one byte
// per space-separated token).
//
// A rule matches characters, so `base64 < .env` or `xxd -p .env` hands it a
// stream in which no secret appears. This module finds bounded candidate runs,
// decodes them as UTF-8, and keeps a map from every decoded UTF-16 unit back to
// the encoded characters that produced it. The engine scans each decoded
// segment and maps every finding onto the encoded span that produced it, so a
// redaction masks the encoding itself.
//
// Cost is bounded by the text, not by the number of runs: only the first
// MAX_ENCODED_SEARCH_CHARS characters are searched, and the decoded total is
// held to MAX_DECODED_CHARS — a segment that would cross the budget, or that
// the search window cut mid-value, is REFUSED whole rather than scanned as a
// truncated prefix (a sliced decode lets a rule match a partial value and
// redact only it). Every refusal raises `truncated`/`unscannedChars` on the
// decode's coverage result, so a caller (and `aka status`) can say that
// coverage stopped. Every pattern here is linear (single character classes
// separated by mandatory line breaks, with no nested quantifier that can match
// the same character two ways); dump lines are parsed by hand. Decoding is one
// level deep: a decoded segment is never itself searched for encodings.

/** One decoded run, as text, with a source span for every UTF-16 unit. */
export interface DecodedSegment {
  text: string;
  /** Source offset of the first encoded character behind each unit. */
  starts: Int32Array;
  /** Source offset just past the last encoded character behind each unit. */
  ends: Int32Array;
}

/** What the decode covered, and what it had to leave out. */
export interface DecodedCoverage {
  segments: DecodedSegment[];
  /**
   * Decoded characters that were decoded but not admitted: segments refused
   * because they crossed the decoded budget or touch the search window's cut
   * edge. Alignment offers of one run decode the same source characters, so a
   * refused run can count its characters more than once here — the number is
   * a conservative "this much decoded text was never scanned", not an exact
   * source-character count.
   */
  unscannedChars: number;
  /** True when coverage stopped before the end of the text. */
  truncated: boolean;
}

export interface DecodeLimits {
  maxSearchChars?: number;
  maxDecodedChars?: number;
}

// The search window matches the regex matcher's own input bound, so an encoded
// secret is found over exactly the range a plain one would be.
export const MAX_ENCODED_SEARCH_CHARS = 200_000;
// Total decoded characters handed to the rules per scan: a hard cap.
export const MAX_DECODED_CHARS = 200_000;
// The shortest decoded run worth scanning. Eight bytes holds the shortest
// assignment a secret rule reports (`pin=4417`).
export const MIN_DECODED_BYTES = 8;
// Share of decoded characters that must be printable (tab, CR and LF count;
// other C0 and C1 controls and invalid UTF-8 do not). Random bytes, compressed
// data, hashes and identifiers that merely use the base64 alphabet decode far
// below this, so they are dropped before any rule runs.
export const MIN_PRINTABLE_RATIO = 0.9;

// A base64 run of 11+ characters (8+ bytes), continued across line breaks when
// the line before it ended at the end of the run (`base64` and `openssl base64`
// wrap at 64 or 76 columns). A continuation line must be base64 to its end. A
// run can hold several padded values, one per line; each is decoded on its own.
const BASE64_RUN = /[A-Za-z0-9+/]{11,}={0,2}(?:\r?\n[A-Za-z0-9+/]{2,}={0,2}(?=\r?$))*/gm;
// A plain hex run (`xxd -p`, a hex-encoded value) of 16+ digits, continued
// across full-line breaks the same way.
const HEX_RUN = /[0-9a-fA-F]{16,}(?:\r?\n[0-9a-fA-F]{2,}(?=\r?$))*/gm;
// The offset column of an `xxd` line ("00000010: ") or a `hexdump -C` line
// ("00000010  "). The rest of the line is parsed by hand, below.
const DUMP_OFFSET = /^[0-9a-fA-F]{7,16}(?::[ ]| {2})/;
// Cheap gates: text with no line shaped like a dump line has nothing to parse.
const DUMP_GATE =
  /^(?:[0-9a-fA-F]{7,16}(?::[ ]| {2})|[ \t]*(?:[0-9a-fA-F]{7,8}[ \t]+)?[0-9a-fA-F]{2}(?:[0-9a-fA-F]{2})?[ \t]+[0-9a-fA-F]{2})/m;

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_VALUES = new Int8Array(128).fill(-1);
for (let index = 0; index < BASE64_ALPHABET.length; index++) {
  BASE64_VALUES[BASE64_ALPHABET.charCodeAt(index)] = index;
}

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  return -1;
}

/** A run that owns its arrays, which the dump parser pushes into. */
interface OwnedRun {
  bytes: number[];
  starts: number[];
  ends: number[];
}

/** Decoded bytes, each with the source span of the characters that encode it:
 * owned arrays (dumps, which accumulate across lines) or the shared scratch
 * typed buffers (the streaming base64 and hex decoders, which consume one run
 * at a time). Only the first `count` bytes of the run are meaningful.
 */
type ByteRun = OwnedRun | { bytes: Uint8Array; starts: Int32Array; ends: Int32Array };

// Reused decode buffers for the two streaming decoders (base64 and hex), so a
// run costs no allocation until it is accepted. A run is decoded into these
// and judged (see toSegment) before the next decode overwrites them, which
// holds because every producer decodes and immediately accepts or refuses —
// see addBase64Value and hexRunSegments; the dump parser below keeps its own
// arrays because it accumulates across lines. Sized for the largest run the
// search window can hold: a base64 run is three-quarters of its length in
// bytes, a hex run one-half.
const DECODE_BYTES = new Uint8Array(MAX_ENCODED_SEARCH_CHARS);
const DECODE_STARTS = new Int32Array(MAX_ENCODED_SEARCH_CHARS);
const DECODE_ENDS = new Int32Array(MAX_ENCODED_SEARCH_CHARS);
const SCRATCH_RUN: ByteRun = { bytes: DECODE_BYTES, starts: DECODE_STARTS, ends: DECODE_ENDS };

// ASCII bytes that decode to printable characters — the ASCII half of
// isPrintableCodePoint as a table, so the acceptance pass below answers a
// one-byte code point with a lookup instead of a call. Indexed only below
// 0x80; multi-byte sequences still go through utf8At.
const ASCII_PRINTABLE = new Uint8Array(0x80);
for (let b = 0x20; b < 0x7f; b++) ASCII_PRINTABLE[b] = 1;
ASCII_PRINTABLE[0x09] = 1;
ASCII_PRINTABLE[0x0a] = 1;
ASCII_PRINTABLE[0x0d] = 1;

function isPrintableCodePoint(cp: number): boolean {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return true;
  return cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp < 0xa0) && cp !== 0xfffd;
}

// The length of the UTF-8 sequence starting at `i` and its code point, or
// undefined for an invalid, truncated or overlong sequence. `limit` is the
// end of the valid bytes: a sequence crossing it is truncated, not garbage
// read past the run (the byte buffer can be a shared scratch larger than the
// run it currently holds).
function utf8At(
  bytes: Uint8Array | readonly number[],
  i: number,
  limit: number,
): { cp: number; len: number } | undefined {
  const lead = bytes[i] ?? 0;
  if (lead < 0x80) return { cp: lead, len: 1 };
  const len = lead >= 0xf0 && lead < 0xf8 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 0;
  if (len === 0 || i + len > limit) return undefined;
  let cp = lead & (0x7f >> len);
  for (let k = 1; k < len; k++) {
    const next = bytes[i + k] ?? 0;
    if ((next & 0xc0) !== 0x80) return undefined;
    cp = (cp << 6) | (next & 0x3f);
  }
  const min = len === 2 ? 0x80 : len === 3 ? 0x800 : 0x10000;
  if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return undefined;
  return { cp, len };
}

// Judges a decoded run and, when accepted, builds its segment. Two passes over
// the bytes, and the split is the point: pass one computes the acceptance
// decision — which depends only on the code points, their printable ratio and
// where the first non-printable one sits, never on the source spans — without
// allocating anything. Pass two builds the text and the per-unit span arrays
// only for a run that was accepted. Adversarial text is dense in long runs of
// base64/hex-alphabet characters that decode to garbage (a run of `0`s is both
// a hex run and a base64 run, and the probe battery's own corpora are made of
// them), and every scan() of a secret rule walks all of them: materializing
// the text and span arrays for runs that were about to be refused dominated
// that walk's cost, in allocations and the GC pressure they cause.
function toSegment(run: ByteRun, count: number): DecodedSegment | undefined {
  if (count < MIN_DECODED_BYTES) return undefined;
  // Pass one: the decision. No text, no arrays, no strings. One-byte code
  // points (every ASCII byte) answer from the table; only a lead byte of a
  // multi-byte sequence pays the full utf8At call, so a run of ASCII garbage
  // — the adversarial case, where every byte is a base64/hex-alphabet
  // character — is judged at table-lookup speed.
  let codePoints = 0;
  let printable = 0;
  let firstNonPrintable = -1;
  for (let i = 0; i < count;) {
    const byte = run.bytes[i] ?? 0;
    if (byte < 0x80) {
      if (ASCII_PRINTABLE[byte] === 1) printable++;
      else if (firstNonPrintable < 0) firstNonPrintable = codePoints;
      codePoints++;
      i++;
    } else {
      const decoded = utf8At(run.bytes, i, count);
      const len = decoded?.len ?? 1;
      if (decoded === undefined || !isPrintableCodePoint(decoded.cp)) {
        if (firstNonPrintable < 0) firstNonPrintable = codePoints;
      } else {
        printable++;
      }
      codePoints++;
      i += len;
    }
  }
  let end = codePoints;
  if (firstNonPrintable >= 0) {
    const tail = codePoints - firstNonPrintable;
    if (firstNonPrintable >= MIN_DECODED_BYTES && tail <= Math.max(8, codePoints >> 3)) {
      // The garbage sits at the end of an otherwise-text run: keep the text.
      end = firstNonPrintable;
    } else if (printable / codePoints < MIN_PRINTABLE_RATIO) {
      return undefined;
    }
  }
  if (end < MIN_DECODED_BYTES) return undefined;
  // Pass two, accepted runs only: the text and the span tables. A trailing run
  // of non-printable units was TRIMMED above when it is short relative to the
  // whole (at most max(8, an eighth of the run) units) and what precedes it is
  // long enough to scan: an encoded value glued onto a following word —
  // `base64 of the secret` with `success` typed right after it — decodes to the
  // value plus a few bytes of the word's bits, and without the trim the whole
  // segment failed the ratio and was dropped, secret and all. The same trim
  // keeps a wrong grid's replacement characters out of the value a rule
  // reports, so the finding's identity matches the plain secret's. Random data
  // and dumps of binary fail as before: their first non-printable unit arrives
  // within a few bytes of the start, the trim never applies, and the ratio
  // drops them.
  let text = '';
  const unitStarts: number[] = [];
  const unitEnds: number[] = [];
  for (let i = 0; i < count;) {
    const decoded = utf8At(run.bytes, i, count);
    const cp = decoded?.cp ?? 0xfffd;
    const len = decoded?.len ?? 1;
    const start = run.starts[i] ?? 0;
    let lastEnd = 0;
    for (let k = i; k < i + len; k++) lastEnd = Math.max(lastEnd, run.ends[k] ?? 0);
    const char = String.fromCodePoint(cp);
    // One entry per UTF-16 unit: two for a code point outside the BMP.
    const units = cp > 0xffff ? 2 : 1;
    for (let unit = 0; unit < units; unit++) {
      unitStarts.push(start);
      unitEnds.push(lastEnd);
    }
    text += char;
    i += len;
  }
  if (end === codePoints)
    return { text, starts: Int32Array.from(unitStarts), ends: Int32Array.from(unitEnds) };
  return {
    text: text.slice(0, end),
    starts: Int32Array.from(unitStarts.slice(0, end)),
    ends: Int32Array.from(unitEnds.slice(0, end)),
  };
}

/** Accepts decoded runs into the output while the decoded budget lasts. */
class Collector {
  readonly segments: DecodedSegment[] = [];
  private left: number;
  unscannedChars = 0;
  truncated = false;

  constructor(maxDecodedChars: number) {
    this.left = maxDecodedChars;
  }

  get exhausted(): boolean {
    return this.left <= 0;
  }

  add(run: ByteRun, count: number): void {
    if (this.left <= 0) {
      // The budget was spent exactly (no refusal raised the flag yet): what
      // follows is not scanned, and the report must say so.
      this.truncated = true;
      return;
    }
    const segment = toSegment(run, count);
    if (segment === undefined) return;
    if (segment.text.length > this.left) {
      // Refuse whole rather than scan a truncated prefix: a sliced decode
      // lets a rule match a partial value (`CANARY-7` of a longer secret)
      // and the redaction then masks only that group. Refusing leaves the
      // rest of the budget for the segments that follow it.
      this.unscannedChars += segment.text.length;
      this.truncated = true;
      return;
    }
    this.left -= segment.text.length;
    this.segments.push(segment);
  }

  /**
   * Admits every segment of one encoded run against a single reservation: the
   * run's alignment offers decode the SAME source characters, so the run is
   * charged its longest view once — not once per offer — and one large dump
   * cannot starve the segments that follow it through its own re-decodings.
   * Refused whole (never sliced) when the reservation does not fit.
   */
  addRun(segments: DecodedSegment[], reserve: number): void {
    if (segments.length === 0) return;
    if (this.left <= 0) {
      this.truncated = true;
      return;
    }
    if (reserve > this.left) {
      for (const segment of segments) this.unscannedChars += segment.text.length;
      this.truncated = true;
      return;
    }
    this.left -= reserve;
    this.segments.push(...segments);
  }
}

// Decodes base64 characters at `positions` (source offsets, line breaks
// already skipped), starting `skip` characters in, into the shared scratch
// run, and returns how many bytes it decoded. The scratch is safe to reuse
// because the caller consumes the run (accepts it into a segment, or drops
// it) before the next decode.
function decodeBase64Into(text: string, positions: readonly number[], skip: number): number {
  let buffer = 0;
  let bits = 0;
  let count = 0;
  for (let k = skip; k < positions.length; k++) {
    const position = positions[k] ?? 0;
    const value = BASE64_VALUES[text.charCodeAt(position)] ?? -1;
    buffer = ((buffer << 6) | value) & 0xfff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      DECODE_BYTES[count] = (buffer >> bits) & 0xff;
      // A byte is spread over the character before this one and this one.
      DECODE_STARTS[count] = positions[k - 1] ?? position;
      DECODE_ENDS[count] = position + 1;
      count++;
    }
  }
  return count;
}

// Every 4-character grid of one base64 value is decoded and offered: a value
// glued onto a preceding word can sit on any of them, and a wrong grid that
// happens to decode to printable text must not hide the right one. Only the
// right grid carries a secret intact, so offering the others costs decoding
// budget, not false findings — and the run is CHARGED once (its longest view,
// by addRun), so the offers cannot multiply their way through the budget and
// starve whatever follows.
function addBase64Value(text: string, positions: readonly number[], out: Collector): void {
  if (positions.length < 11) return;
  const segments: DecodedSegment[] = [];
  for (let skip = 0; skip < 4; skip++) {
    const segment = toSegment(SCRATCH_RUN, decodeBase64Into(text, positions, skip));
    if (segment !== undefined) segments.push(segment);
  }
  let reserve = 0;
  for (const segment of segments) {
    if (segment.text.length > reserve) reserve = segment.text.length;
  }
  out.addRun(segments, reserve);
}

function base64Segments(text: string, out: Collector): void {
  for (const match of text.matchAll(BASE64_RUN)) {
    const run = match[0];
    const base = match.index;
    let positions: number[] = [];
    for (let i = 0; i < run.length; i++) {
      const code = run.charCodeAt(i);
      if (code === 0x3d) {
        // Padding ends one value; the next line may start another.
        if (positions.length > 0) addBase64Value(text, positions, out);
        positions = [];
      } else if (code !== 0x0a && code !== 0x0d) {
        positions.push(base + i);
      }
    }
    if (positions.length > 0) addBase64Value(text, positions, out);
  }
}

function hexRunSegments(text: string, out: Collector): void {
  for (const match of text.matchAll(HEX_RUN)) {
    const run = match[0];
    const base = match.index;
    let high = -1;
    let highAt = 0;
    let count = 0;
    for (let i = 0; i < run.length; i++) {
      const value = hexValue(run.charCodeAt(i));
      if (value < 0) continue;
      if (high < 0) {
        high = value;
        highAt = base + i;
      } else {
        DECODE_BYTES[count] = (high << 4) | value;
        DECODE_STARTS[count] = highAt;
        DECODE_ENDS[count] = base + i + 1;
        count++;
        high = -1;
      }
    }
    out.add(SCRATCH_RUN, count);
  }
}

// Parses one `xxd` or `hexdump -C` line starting at `lineStart` in the source.
// Each byte maps from its two hex digits to its character in the ASCII column
// when the column is present and as long as the byte count, so masking a range
// of bytes covers both renderings of them.
function parseColumnDumpLine(line: string, lineStart: number): ByteRun | undefined {
  const offset = DUMP_OFFSET.exec(line);
  if (offset === null) return undefined;
  const xxd = offset[0].includes(':');
  const bytes: number[] = [];
  const hexAt: number[] = [];
  let i = offset[0].length;
  let asciiAt = -1;
  while (i < line.length) {
    const high = hexValue(line.charCodeAt(i));
    const low = hexValue(line.charCodeAt(i + 1));
    if (high >= 0 && low >= 0) {
      bytes.push((high << 4) | low);
      hexAt.push(i);
      i += 2;
      continue;
    }
    if (line[i] !== ' ') break;
    let j = i;
    while (line[j] === ' ') j++;
    if (!xxd && line[j] === '|') {
      asciiAt = j + 1;
      break;
    }
    if (xxd && j - i >= 2) {
      asciiAt = j;
      break;
    }
    if (j - i > 2) break;
    i = j;
  }
  if (bytes.length === 0) return undefined;
  const asciiFits = asciiAt >= 0 && line.length - asciiAt >= bytes.length;
  return {
    bytes,
    starts: hexAt.map((at) => lineStart + at),
    ends: hexAt.map((at, k) => lineStart + (asciiFits ? asciiAt + k + 1 : at + 2)),
  };
}

// Parses one line of space-separated hex tokens: `od -tx1` / `od -An -tx1`
// (one byte per token) or plain `hexdump` / `od -x` (16-bit little-endian
// words), with or without a leading offset column. Every token must have the
// same width.
function parseTokenDumpLine(line: string, lineStart: number): ByteRun | undefined {
  const tokens: { at: number; text: string }[] = [];
  for (const match of line.matchAll(/\S+/g)) tokens.push({ at: match.index, text: match[0] });
  if (tokens.length === 0) return undefined;
  for (const token of tokens) {
    for (let k = 0; k < token.text.length; k++) {
      if (hexValue(token.text.charCodeAt(k)) < 0) return undefined;
    }
  }
  const first = tokens[0];
  if (first !== undefined && first.text.length >= 6 && tokens.length > 1) tokens.shift();
  const width = tokens[0]?.text.length ?? 0;
  if ((width !== 2 && width !== 4) || tokens.some((t) => t.text.length !== width)) {
    return undefined;
  }
  const run: OwnedRun = { bytes: [], starts: [], ends: [] };
  const byteAt = (at: number): void => {
    run.bytes.push((hexValue(line.charCodeAt(at)) << 4) | hexValue(line.charCodeAt(at + 1)));
    run.starts.push(lineStart + at);
    run.ends.push(lineStart + at + 2);
  };
  for (const token of tokens) {
    if (width === 2) {
      byteAt(token.at);
    } else {
      byteAt(token.at + 2);
      byteAt(token.at);
    }
  }
  return run;
}

function dumpSegments(text: string, out: Collector): void {
  if (!DUMP_GATE.test(text)) return;
  let current: OwnedRun = { bytes: [], starts: [], ends: [] };
  const flush = (): void => {
    if (current.bytes.length > 0) out.add(current, current.bytes.length);
    current = { bytes: [], starts: [], ends: [] };
  };
  let lineStart = 0;
  while (lineStart <= text.length) {
    let lineEnd = text.indexOf('\n', lineStart);
    if (lineEnd < 0) lineEnd = text.length;
    const raw = text.slice(lineStart, lineEnd);
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const parsed = parseColumnDumpLine(line, lineStart) ?? parseTokenDumpLine(line, lineStart);
    if (parsed === undefined) {
      flush();
    } else {
      current.bytes.push(...parsed.bytes);
      current.starts.push(...parsed.starts);
      current.ends.push(...parsed.ends);
    }
    lineStart = lineEnd + 1;
  }
  flush();
}

// The last default-limits call's input and result. The isolated scan worker
// calls `scan()` once per rule over the same text when it attributes time to
// rules, and the decode is the same for every one of those calls.
let memo: { text: string; coverage: DecodedCoverage } | undefined;

/**
 * Every decodable base64 run and hex dump in `text` that decodes to readable
 * text, within the bounds above, together with what could not be covered:
 * segments refused at the decoded budget or cut by the search window are not
 * returned, and `truncated`/`unscannedChars` say so.
 */
export function decodeEncodedWithCoverage(text: string, limits?: DecodeLimits): DecodedCoverage {
  if (limits === undefined && memo?.text === text) return memo.coverage;
  const maxSearch = limits?.maxSearchChars ?? MAX_ENCODED_SEARCH_CHARS;
  const window = text.length > maxSearch ? text.slice(0, maxSearch) : text;
  const out = new Collector(limits?.maxDecodedChars ?? MAX_DECODED_CHARS);
  dumpSegments(window, out);
  hexRunSegments(window, out);
  base64Segments(window, out);
  let { segments, unscannedChars, truncated } = out;
  if (text.length > window.length) {
    // Source characters past the window were never searched at all, and a
    // segment whose encoded span touches the cut edge may be a value whose
    // continuation lies past it; scanning its truncated decode would report a
    // partial value. Refuse such a segment and say coverage stopped.
    const edge = window.length;
    const whole: DecodedSegment[] = [];
    for (const segment of segments) {
      if (segment.ends[segment.ends.length - 1] === edge) {
        unscannedChars += segment.text.length;
      } else {
        whole.push(segment);
      }
    }
    unscannedChars += text.length - edge;
    segments = whole;
    truncated = true;
  }
  const coverage: DecodedCoverage = { segments, unscannedChars, truncated };
  if (limits === undefined) memo = { text, coverage };
  return coverage;
}

/**
 * Every decodable base64 run and hex dump in `text` that decodes to readable
 * text, within the bounds above. Empty for text with no such run.
 */
export function decodeEncodedSegments(text: string, limits?: DecodeLimits): DecodedSegment[] {
  return decodeEncodedWithCoverage(text, limits).segments;
}

/**
 * The source span covering decoded characters [start, end) of `segment`: from
 * the first encoded character of the first unit to the last encoded character
 * of the last unit.
 */
export function sourceSpanOf(
  segment: DecodedSegment,
  start: number,
  end: number,
): { start: number; end: number } {
  let from = Number.POSITIVE_INFINITY;
  let to = 0;
  for (let k = start; k < end; k++) {
    from = Math.min(from, segment.starts[k] ?? from);
    to = Math.max(to, segment.ends[k] ?? to);
  }
  return { start: from, end: to };
}

// This decode path is OURS and is deliberately NOT pre-tiered at module load.
//
// Tiering it early would move V8's lazy-compilation charge (~25ms of CPU for one
// 10KB probe of repeated `0`, the probe battery's own corpora) off the first big
// scan, and that is why it looks tempting. It was tried and measured, and the
// trade is the wrong way round: a warm-up that walks enough interpreted volume
// to tier the path costs ~95ms of module-load time in this file, and module-load
// time is paid by EVERY process that imports @akasecurity/detections — the hooks
// import it on every call, whether or not any text holds an encoded run. Paying
// a per-process ~95ms to save ~25ms on one scan of base64-dense text is a
// regression on the path that runs most often. `packages/detections/test/
// security/redos.test.ts` passes either way (275 cases), so the warm-up bought
// nothing the gate needs.
