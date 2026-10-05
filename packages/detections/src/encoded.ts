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
// held to MAX_DECODED_CHARS (the segment that crosses it is truncated). Every
// pattern here is linear (single character classes separated by mandatory line
// breaks, with no nested quantifier that can match the same character two
// ways); dump lines are parsed by hand. Decoding is one level deep: a decoded
// segment is never itself searched for encodings.

/** One decoded run, as text, with a source span for every UTF-16 unit. */
export interface DecodedSegment {
  text: string;
  /** Source offset of the first encoded character behind each unit. */
  starts: Int32Array;
  /** Source offset just past the last encoded character behind each unit. */
  ends: Int32Array;
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

/** Decoded bytes, each with the source span of the characters that encode it. */
interface ByteRun {
  bytes: number[];
  starts: number[];
  ends: number[];
}

const emptyRun = (): ByteRun => ({ bytes: [], starts: [], ends: [] });

function isPrintableCodePoint(cp: number): boolean {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return true;
  return cp >= 0x20 && cp !== 0x7f && !(cp >= 0x80 && cp < 0xa0) && cp !== 0xfffd;
}

// The length of the UTF-8 sequence starting at `i` and its code point, or
// undefined for an invalid, truncated or overlong sequence.
function utf8At(bytes: readonly number[], i: number): { cp: number; len: number } | undefined {
  const lead = bytes[i] ?? 0;
  if (lead < 0x80) return { cp: lead, len: 1 };
  const len = lead >= 0xf0 && lead < 0xf8 ? 4 : lead >= 0xe0 ? 3 : lead >= 0xc0 ? 2 : 0;
  if (len === 0 || i + len > bytes.length) return undefined;
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

// Decodes a byte run as UTF-8 into a segment, or undefined when it is too
// short or not text. An invalid byte becomes U+FFFD and counts against the
// printable ratio.
function toSegment(run: ByteRun): DecodedSegment | undefined {
  const { bytes, starts, ends } = run;
  if (bytes.length < MIN_DECODED_BYTES) return undefined;
  let text = '';
  const unitStarts: number[] = [];
  const unitEnds: number[] = [];
  let codePoints = 0;
  let printable = 0;
  for (let i = 0; i < bytes.length;) {
    const decoded = utf8At(bytes, i);
    const cp = decoded?.cp ?? 0xfffd;
    const len = decoded?.len ?? 1;
    codePoints++;
    if (decoded !== undefined && isPrintableCodePoint(cp)) printable++;
    const start = starts[i] ?? 0;
    let end = 0;
    for (let k = i; k < i + len; k++) end = Math.max(end, ends[k] ?? 0);
    const char = String.fromCodePoint(cp);
    // One entry per UTF-16 unit: two for a code point outside the BMP.
    const units = cp > 0xffff ? 2 : 1;
    for (let unit = 0; unit < units; unit++) {
      unitStarts.push(start);
      unitEnds.push(end);
    }
    text += char;
    i += len;
  }
  if (printable / codePoints < MIN_PRINTABLE_RATIO) return undefined;
  return { text, starts: Int32Array.from(unitStarts), ends: Int32Array.from(unitEnds) };
}

/** Accepts decoded runs into the output while the decoded budget lasts. */
class Collector {
  readonly segments: DecodedSegment[] = [];
  private left: number;

  constructor(maxDecodedChars: number) {
    this.left = maxDecodedChars;
  }

  get exhausted(): boolean {
    return this.left <= 0;
  }

  add(run: ByteRun): void {
    if (this.left <= 0) return;
    const segment = toSegment(run);
    if (segment === undefined) return;
    if (segment.text.length > this.left) {
      let keep = this.left;
      // Never end on half of a surrogate pair.
      const last = segment.text.charCodeAt(keep - 1);
      if (last >= 0xd800 && last <= 0xdbff) keep -= 1;
      this.left = 0;
      if (keep <= 0) return;
      this.segments.push({
        text: segment.text.slice(0, keep),
        starts: segment.starts.slice(0, keep),
        ends: segment.ends.slice(0, keep),
      });
      return;
    }
    this.left -= segment.text.length;
    this.segments.push(segment);
  }
}

// Decodes base64 characters at `positions` (source offsets, line breaks
// already skipped), starting `skip` characters in.
function decodeBase64At(text: string, positions: readonly number[], skip: number): ByteRun {
  const run = emptyRun();
  let buffer = 0;
  let bits = 0;
  for (let k = skip; k < positions.length; k++) {
    const position = positions[k] ?? 0;
    const value = BASE64_VALUES[text.charCodeAt(position)] ?? -1;
    buffer = ((buffer << 6) | value) & 0xfff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      run.bytes.push((buffer >> bits) & 0xff);
      // A byte is spread over the character before this one and this one.
      run.starts.push(positions[k - 1] ?? position);
      run.ends.push(position + 1);
    }
  }
  return run;
}

// Every 4-character grid of one base64 value is decoded and offered: a value
// glued onto a preceding word can sit on any of them, and a wrong grid that
// happens to decode to printable text must not hide the right one. Only the
// right grid carries a secret intact, so offering the others costs decoding
// budget, not false findings.
function addBase64Value(text: string, positions: readonly number[], out: Collector): void {
  if (positions.length < 11) return;
  for (let skip = 0; skip < 4 && !out.exhausted; skip++) {
    out.add(decodeBase64At(text, positions, skip));
  }
}

function base64Segments(text: string, out: Collector): void {
  for (const match of text.matchAll(BASE64_RUN)) {
    if (out.exhausted) return;
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
    if (out.exhausted) return;
    const run = match[0];
    const base = match.index;
    const decoded = emptyRun();
    let high = -1;
    let highAt = 0;
    for (let i = 0; i < run.length; i++) {
      const value = hexValue(run.charCodeAt(i));
      if (value < 0) continue;
      if (high < 0) {
        high = value;
        highAt = base + i;
      } else {
        decoded.bytes.push((high << 4) | value);
        decoded.starts.push(highAt);
        decoded.ends.push(base + i + 1);
        high = -1;
      }
    }
    out.add(decoded);
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
  const run = emptyRun();
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
  let current = emptyRun();
  const flush = (): void => {
    if (current.bytes.length > 0) out.add(current);
    current = emptyRun();
  };
  let lineStart = 0;
  while (lineStart <= text.length && !out.exhausted) {
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
let memo: { text: string; segments: DecodedSegment[] } | undefined;

/**
 * Every decodable base64 run and hex dump in `text` that decodes to readable
 * text, within the bounds above. Empty for text with no such run.
 */
export function decodeEncodedSegments(text: string, limits?: DecodeLimits): DecodedSegment[] {
  if (limits === undefined && memo?.text === text) return memo.segments;
  const maxSearch = limits?.maxSearchChars ?? MAX_ENCODED_SEARCH_CHARS;
  const window = text.length > maxSearch ? text.slice(0, maxSearch) : text;
  const out = new Collector(limits?.maxDecodedChars ?? MAX_DECODED_CHARS);
  dumpSegments(window, out);
  hexRunSegments(window, out);
  base64Segments(window, out);
  if (limits === undefined) memo = { text, segments: out.segments };
  return out.segments;
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
