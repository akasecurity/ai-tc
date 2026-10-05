// Encoded-secret discovery: base64 runs and hex dumps (xxd, xxd -p, hexdump -C)
// decoded back to text so the secret rules can read what they encode.
//
// A rule matches characters, so `base64 < .env` or `xxd -p .env` hands it a
// stream in which no secret appears. This module finds bounded candidate runs,
// decodes them, and keeps a per-byte map back to the encoded characters. The
// engine scans each decoded segment and maps every finding onto the encoded
// span that produced it, so a redaction masks the encoding itself.
//
// Cost is bounded by the text, not by the number of runs: only the first
// MAX_ENCODED_SEARCH_CHARS characters are searched, the decoded total is capped
// at MAX_DECODED_CHARS, and every pattern here is linear (single character
// classes separated by mandatory line breaks, with no nested quantifier that can
// match the same character two ways). Decoding is one level deep: a decoded
// segment is never itself searched for encodings.

/** One decoded run: `text` holds one UTF-16 unit per decoded byte. */
export interface DecodedSegment {
  text: string;
  /** Source offset of the first encoded character of each byte. */
  starts: Int32Array;
  /** Source offset just past the last encoded character of each byte. */
  ends: Int32Array;
}

// The search window matches the regex matcher's own input bound, so an encoded
// secret is found over exactly the range a plain one would be.
export const MAX_ENCODED_SEARCH_CHARS = 200_000;
// Total decoded characters handed to the rules per scan.
export const MAX_DECODED_CHARS = 200_000;
// A run must decode to at least this many bytes to be worth scanning: shorter
// than any credential the secret rules describe.
export const MIN_DECODED_BYTES = 12;
// Share of decoded bytes that must be printable ASCII (or tab/CR/LF). Random
// bytes, compressed data, hashes and identifiers that merely use the base64
// alphabet decode far below this, so they are dropped before any rule runs.
export const MIN_PRINTABLE_RATIO = 0.9;

// A base64 run of 16+ characters, continued across line breaks when the line
// before it ended at the end of the run (`base64` and `openssl base64` wrap at
// 64 or 76 columns). A continuation line must be base64 to its end.
const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}(?:\r?\n[A-Za-z0-9+/]{4,}={0,2}(?=\r?$))*/gm;
// A plain hex run (`xxd -p`, `od -An -tx1` without spaces, hex-encoded values)
// of 24+ digits, continued across full-line breaks the same way.
const HEX_RUN = /[0-9a-fA-F]{24,}(?:\r?\n[0-9a-fA-F]{2,}(?=\r?$))*/gm;
// The offset column of an `xxd` line ("00000010: ") or a `hexdump -C` line
// ("00000010  "). The rest of the line is parsed by hand, below.
const DUMP_OFFSET = /^[0-9a-fA-F]{7,16}(?::[ ]| {2})/;

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_VALUES = new Int8Array(128).fill(-1);
for (let index = 0; index < BASE64_ALPHABET.length; index++) {
  BASE64_VALUES[BASE64_ALPHABET.charCodeAt(index)] = index;
}

function isPrintableByte(byte: number): boolean {
  return (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  return -1;
}

// Builds a segment from decoded bytes and their source spans, or undefined when
// the bytes are too few or not text.
function toSegment(bytes: number[], starts: number[], ends: number[]): DecodedSegment | undefined {
  if (bytes.length < MIN_DECODED_BYTES) return undefined;
  let printable = 0;
  for (const byte of bytes) if (isPrintableByte(byte)) printable++;
  if (printable / bytes.length < MIN_PRINTABLE_RATIO) return undefined;
  let text = '';
  for (const byte of bytes) text += isPrintableByte(byte) ? String.fromCharCode(byte) : '�';
  return { text, starts: Int32Array.from(starts), ends: Int32Array.from(ends) };
}

// Decodes base64 characters at `positions` (source offsets, line breaks
// already skipped), starting `skip` characters in so a run glued onto a
// preceding word can still be read on its real 4-character grid.
function decodeBase64At(
  text: string,
  positions: readonly number[],
  skip: number,
): DecodedSegment | undefined {
  const bytes: number[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let k = skip; k < positions.length; k++) {
    const position = positions[k] ?? 0;
    const value = BASE64_VALUES[text.charCodeAt(position)] ?? -1;
    if (value < 0) break;
    buffer = ((buffer << 6) | value) & 0xfff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      // A byte is spread over the character before this one and this one.
      starts.push(positions[k - 1] ?? position);
      ends.push(position + 1);
    }
  }
  return toSegment(bytes, starts, ends);
}

function base64Segments(text: string, budget: { left: number }, out: DecodedSegment[]): void {
  for (const match of text.matchAll(BASE64_RUN)) {
    if (budget.left <= 0) return;
    const run = match[0];
    const base = match.index;
    const positions: number[] = [];
    for (let i = 0; i < run.length; i++) {
      const code = run.charCodeAt(i);
      if (code === 0x3d) break;
      if (code !== 0x0a && code !== 0x0d) positions.push(base + i);
    }
    for (let skip = 0; skip < 4; skip++) {
      const segment = decodeBase64At(text, positions, skip);
      if (segment === undefined) continue;
      budget.left -= segment.text.length;
      out.push(segment);
      break;
    }
  }
}

function hexRunSegments(text: string, budget: { left: number }, out: DecodedSegment[]): void {
  for (const match of text.matchAll(HEX_RUN)) {
    if (budget.left <= 0) return;
    const run = match[0];
    const base = match.index;
    const bytes: number[] = [];
    const starts: number[] = [];
    const ends: number[] = [];
    let high = -1;
    let highAt = 0;
    for (let i = 0; i < run.length; i++) {
      const value = hexValue(run.charCodeAt(i));
      if (value < 0) continue;
      if (high < 0) {
        high = value;
        highAt = base + i;
      } else {
        bytes.push((high << 4) | value);
        starts.push(highAt);
        ends.push(base + i + 1);
        high = -1;
      }
    }
    const segment = toSegment(bytes, starts, ends);
    if (segment === undefined) continue;
    budget.left -= segment.text.length;
    out.push(segment);
  }
}

interface DumpLine {
  bytes: number[];
  starts: number[];
  ends: number[];
}

// Parses one `xxd` or `hexdump -C` line starting at `lineStart` in the source.
// Each byte maps from its two hex digits to its character in the ASCII column
// when the column is present and as long as the byte count, so masking a range
// of bytes covers both renderings of them.
function parseDumpLine(line: string, lineStart: number): DumpLine | undefined {
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
  const starts = hexAt.map((at) => lineStart + at);
  const ends = hexAt.map((at, k) => lineStart + (asciiFits ? asciiAt + k + 1 : at + 2));
  return { bytes, starts, ends };
}

function dumpSegments(text: string, budget: { left: number }, out: DecodedSegment[]): void {
  // Cheap gate: a dump line always carries an offset column, so text with no
  // line that opens with one has nothing to parse.
  if (!/^[0-9a-fA-F]{7,16}(?::[ ]| {2})/m.test(text)) return;
  let bytes: number[] = [];
  let starts: number[] = [];
  let ends: number[] = [];
  const flush = (): void => {
    if (budget.left > 0) {
      const segment = toSegment(bytes, starts, ends);
      if (segment !== undefined) {
        budget.left -= segment.text.length;
        out.push(segment);
      }
    }
    bytes = [];
    starts = [];
    ends = [];
  };
  let lineStart = 0;
  while (lineStart <= text.length) {
    let lineEnd = text.indexOf('\n', lineStart);
    if (lineEnd < 0) lineEnd = text.length;
    const raw = text.slice(lineStart, lineEnd);
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const parsed = parseDumpLine(line, lineStart);
    if (parsed === undefined) {
      if (bytes.length > 0) flush();
    } else {
      bytes.push(...parsed.bytes);
      starts.push(...parsed.starts);
      ends.push(...parsed.ends);
    }
    lineStart = lineEnd + 1;
  }
  if (bytes.length > 0) flush();
}

// The last call's input and result. The isolated scan worker calls `scan()`
// once per rule over the same text when it attributes time to rules, and the
// decode is the same for every one of those calls.
let memo: { text: string; segments: DecodedSegment[] } | undefined;

/**
 * Every decodable base64 run and hex dump in `text` that decodes to readable
 * text, within the bounds above. Empty for text with no such run.
 */
export function decodeEncodedSegments(text: string): DecodedSegment[] {
  if (memo?.text === text) return memo.segments;
  const window =
    text.length > MAX_ENCODED_SEARCH_CHARS ? text.slice(0, MAX_ENCODED_SEARCH_CHARS) : text;
  const segments: DecodedSegment[] = [];
  const budget = { left: MAX_DECODED_CHARS };
  dumpSegments(window, budget, segments);
  hexRunSegments(window, budget, segments);
  base64Segments(window, budget, segments);
  memo = { text, segments };
  return segments;
}

/**
 * The source span covering decoded characters [start, end) of `segment`: from
 * the first encoded character of the first byte to the last encoded character
 * of the last byte.
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
