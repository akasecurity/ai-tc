// Where a finding sits in the text it was detected in, and the masked lines
// around it, built while the raw text is still in memory. The store keeps only
// what this returns; nothing downstream reads the event's text to rebuild it.
//
// Node-API free on purpose: `mask.ts` (the package's `./browser` export) calls
// into it.
import type { MatchResult } from '@akasecurity/detections';
import { lineIndexAt, lineStartOffsets, ruleEvidence, scan } from '@akasecurity/detections';
import type {
  DetectionCategory,
  FindingContext,
  FindingContextBasis,
  FindingLocation,
  Rule,
  RuleEvidence,
} from '@akasecurity/schema';

import { assertRawFree } from './raw-egress.ts';

// Lines shown either side of a code finding's matched line. A value finding
// (a secret, an email) gets its matched line only: some secret rules match
// just the first line of a multi-line secret (a PGP block's header), so a
// neighbouring line can be the secret itself, unmarked by any rule.
export const CONTEXT_RADIUS = 2;
// Characters kept per line, centred on the match's column.
export const CONTEXT_LINE_MAX = 240;
// Characters either side of each kept segment the backstop re-scan also reads,
// so a secret the segment edge cuts through is still recognised whole.
const BACKSTOP_MARGIN = 256;
// Excerpts built per scanned text. Each costs a bounded re-scan, so a file
// carrying thousands of hits (a minified bundle puts them on one line) would
// otherwise pay thousands of them; past this, findings keep their line and
// column and store no excerpt.
export const CONTEXT_MAX_PER_TEXT = 200;
const ELLIPSIS = '…';

/** One hit of the scan that produced the findings, raw match included. */
export type FindingContextHit = Pick<MatchResult, 'ruleId' | 'category' | 'span' | 'rawMatch'>;

export interface FindingLocatorInput {
  text: string;
  basis: FindingContextBasis;
  // Every hit the scan produced over `text`, not only the ones being recorded:
  // each value hit in a window is redacted whether or not it is a finding.
  hits: readonly FindingContextHit[];
  evidenceOf: (ruleId: string) => RuleEvidence;
  // The bundled rules the backstop re-scans each window with, or null when they
  // could not be loaded — then no excerpt is built at all.
  backstopRules: readonly Rule[] | null;
  // Hits whose own resolved action masked them in the stored text. Each is
  // redacted in the excerpt too, whatever its rule's evidence, so the excerpt
  // never shows what the at-rest copy was told to strip.
  enforcedHits?: ReadonlySet<FindingContextHit> | undefined;
}

export type FindingLocator = (hit: FindingContextHit) => FindingLocation;

/** An `evidenceOf` over a ruleset: a rule's own field, else the bundled map. */
export function evidenceLookup(rules: readonly Rule[]): (ruleId: string) => RuleEvidence {
  const byId = new Map(rules.map((rule) => [rule.id, rule]));
  return (ruleId) => ruleEvidence(byId.get(ruleId) ?? { id: ruleId });
}

/**
 * Build a locator over one scanned text. Line starts and the sorted hit list
 * are computed once, so locating every finding of a large file stays linear in
 * its size plus a bounded amount of work per finding.
 */
export function createFindingLocator(input: FindingLocatorInput): FindingLocator {
  // Built on the first finding located, so a capture with none pays nothing.
  let prepared: Prepared | undefined;
  let built = 0;

  return (hit) => {
    prepared ??= prepare(input);
    const { starts } = prepared;
    const lineIndex = lineIndexAt(starts, hit.span.start);
    const lineStart = starts[lineIndex] ?? 0;
    let context: FindingContext | null = null;
    if (input.backstopRules !== null && built < CONTEXT_MAX_PER_TEXT) {
      built += 1;
      try {
        context = buildContext(input, prepared, hit, lineIndex);
      } catch {
        // Fail closed: a masking fault stores no excerpt, never an unmasked one.
        context = null;
      }
    }
    return { line: lineIndex + 1, col: hit.span.start - lineStart + 1, context };
  };
}

// Everything a locator computes once per text rather than once per finding.
interface Prepared {
  starts: number[];
  sorted: FindingContextHit[];
  longest: number;
  // Hits a value whatever their rule says: the enforced ones.
  isValue: (hit: FindingContextHit) => boolean;
  backstopRules: Rule[];
  backstopEvidence: Map<string, RuleEvidence>;
}

function prepare(input: FindingLocatorInput): Prepared {
  const sorted = [...input.hits].sort((a, b) => a.span.start - b.span.start);
  const enforced = input.enforcedHits;
  const backstopRules = [...(input.backstopRules ?? [])];
  return {
    starts: lineStartOffsets(input.text),
    sorted,
    longest: sorted.reduce((max, h) => Math.max(max, h.span.end - h.span.start), 0),
    isValue: (hit) => enforced?.has(hit) === true || input.evidenceOf(hit.ruleId) !== 'code',
    backstopRules,
    backstopEvidence: new Map(backstopRules.map((rule) => [rule.id, ruleEvidence(rule)])),
  };
}

interface Segment {
  lineIndex: number;
  // Absolute offsets into the text: the kept slice, and the whole line.
  start: number;
  end: number;
  lineStart: number;
  lineEnd: number;
}

interface Region {
  start: number;
  end: number;
  category: DetectionCategory;
}

function buildContext(
  input: FindingLocatorInput,
  prepared: Prepared,
  hit: FindingContextHit,
  lineIndex: number,
): FindingContext {
  const { text } = input;
  const { starts, sorted, longest, isValue } = prepared;
  const isCode = !isValue(hit);
  const radius = isCode ? CONTEXT_RADIUS : 0;
  const hitColumn = hit.span.start - (starts[lineIndex] ?? 0);

  const segments: Segment[] = [];
  const firstIndex = Math.max(0, lineIndex - radius);
  const lastIndex = Math.min(starts.length - 1, lineIndex + radius);
  for (let index = firstIndex; index <= lastIndex; index += 1) {
    const lineStart = starts[index] ?? 0;
    // A text ending in a newline has an empty line after it; it is not a line
    // anyone wrote, so it is never shown below the match.
    if (index > lineIndex && lineStart >= text.length) break;
    const next = starts[index + 1];
    let lineEnd = next === undefined ? text.length : next - 1;
    if (lineEnd > lineStart && text.charCodeAt(lineEnd - 1) === 13) lineEnd -= 1;
    const length = lineEnd - lineStart;
    const offset = Math.min(
      Math.max(0, hitColumn - Math.floor(CONTEXT_LINE_MAX / 2)),
      Math.max(0, length - CONTEXT_LINE_MAX),
    );
    const start = lineStart + offset;
    segments.push({
      lineIndex: index,
      start,
      end: Math.min(lineEnd, start + CONTEXT_LINE_MAX),
      lineStart,
      lineEnd,
    });
  }

  const regions: Region[] = [];
  const rawValues: string[] = [];
  const windowStart = segments[0]?.start ?? hit.span.start;
  const windowEnd = segments[segments.length - 1]?.end ?? hit.span.end;
  for (const other of overlapping(sorted, longest, windowStart, windowEnd)) {
    if (!isValue(other)) continue;
    regions.push({ start: other.span.start, end: other.span.end, category: other.category });
    rawValues.push(other.rawMatch);
  }
  for (const found of backstop(text, segments, prepared)) {
    regions.push(found.region);
    rawValues.push(found.rawMatch);
  }
  const merged = mergeRegions(regions);

  const lines: string[] = [];
  let match: FindingContext['match'] = null;
  for (const segment of segments) {
    const rendered = renderSegment(text, segment, merged);
    lines.push(rendered.text);
    if (isCode && segment.lineIndex === lineIndex) {
      const matchEnd = Math.min(hit.span.end, segment.end);
      const start = rendered.position(hit.span.start, 'start');
      const end = rendered.position(matchEnd, 'end');
      match = end > start ? { line: lineIndex + 1, start, end } : null;
    }
  }

  // The last line of defence: no run of any redacted value may survive.
  assertRawFree(lines.join('\n'), rawValues);
  return {
    basis: input.basis,
    firstLine: (segments[0]?.lineIndex ?? lineIndex) + 1,
    lines,
    match,
  };
}

// Hits whose span overlaps [start, end), from a list sorted by span start.
function overlapping(
  sorted: readonly FindingContextHit[],
  longest: number,
  start: number,
  end: number,
): FindingContextHit[] {
  // First hit that could reach `start`: nothing starting earlier than
  // `start - longest` can.
  let low = 0;
  let high = sorted.length;
  const floor = start - longest;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if ((sorted[mid]?.span.start ?? 0) < floor) low = mid + 1;
    else high = mid;
  }
  const out: FindingContextHit[] = [];
  for (let i = low; i < sorted.length; i += 1) {
    const hit = sorted[i];
    if (hit === undefined || hit.span.start >= end) break;
    if (hit.span.end > start) out.push(hit);
  }
  return out;
}

// Re-scan each kept segment, widened by a margin, with the bundled rules, and
// return every value hit that overlaps a segment. Catches a secret the original
// scan did not report (a disabled pack, a corroboration the window lacks).
function backstop(
  text: string,
  segments: readonly Segment[],
  prepared: Prepared,
): { region: Region; rawMatch: string }[] {
  const { backstopRules: rules, backstopEvidence: evidence } = prepared;
  if (rules.length === 0) return [];
  // One scan over the windows joined by newlines, so a finding costs one pass.
  const pieces: { from: number; to: number; at: number }[] = [];
  let joined = '';
  for (const segment of segments) {
    const from = Math.max(segment.lineStart, segment.start - BACKSTOP_MARGIN);
    const to = Math.min(segment.lineEnd, segment.end + BACKSTOP_MARGIN);
    if (joined.length > 0) joined += '\n';
    pieces.push({ from, to, at: joined.length });
    joined += text.slice(from, to);
  }
  const out: { region: Region; rawMatch: string }[] = [];
  for (const found of scan(joined, rules)) {
    if ((evidence.get(found.ruleId) ?? 'value') === 'code') continue;
    for (const piece of pieces) {
      const length = piece.to - piece.from;
      const start = Math.max(found.span.start, piece.at);
      const end = Math.min(found.span.end, piece.at + length);
      if (end <= start) continue;
      out.push({
        region: {
          start: piece.from + (start - piece.at),
          end: piece.from + (end - piece.at),
          category: found.category,
        },
        rawMatch: found.rawMatch,
      });
    }
  }
  return out;
}

function mergeRegions(regions: readonly Region[]): Region[] {
  const sorted = [...regions].sort((a, b) => a.start - b.start || a.end - b.end);
  const out: Region[] = [];
  for (const region of sorted) {
    const open = out[out.length - 1];
    if (open && region.start < open.end) open.end = Math.max(open.end, region.end);
    else out.push({ ...region });
  }
  return out;
}

interface Piece {
  from: number;
  to: number;
  outFrom: number;
  outTo: number;
  redacted: boolean;
}

// One kept segment with every overlapping region replaced by its placeholder,
// plus a map from an absolute offset to its position in the rendered string.
function renderSegment(
  text: string,
  segment: Segment,
  regions: readonly Region[],
): { text: string; position: (offset: number, side: 'start' | 'end') => number } {
  const pieces: Piece[] = [];
  let out = segment.start > segment.lineStart ? ELLIPSIS : '';
  let cursor = segment.start;
  const emit = (to: number, replacement: string | null): void => {
    const piece = replacement ?? text.slice(cursor, to);
    pieces.push({
      from: cursor,
      to,
      outFrom: out.length,
      outTo: out.length + piece.length,
      redacted: replacement !== null,
    });
    out += piece;
    cursor = to;
  };
  for (const region of regions) {
    if (region.end <= segment.start || region.start >= segment.end) continue;
    const start = Math.max(region.start, segment.start);
    if (start > cursor) emit(start, null);
    emit(Math.min(region.end, segment.end), `[REDACTED:${region.category.toUpperCase()}]`);
  }
  if (cursor < segment.end) emit(segment.end, null);
  const body = out.length;
  if (segment.end < segment.lineEnd) out += ELLIPSIS;

  const position = (offset: number, side: 'start' | 'end'): number => {
    for (const piece of pieces) {
      if (offset < piece.from || offset > piece.to) continue;
      if (piece.redacted) {
        // A match starting where a redaction ends starts after its placeholder.
        if (side === 'start' && offset === piece.to) continue;
        return side === 'start' ? piece.outFrom : piece.outTo;
      }
      return piece.outFrom + (offset - piece.from);
    }
    return offset <= segment.start ? (pieces[0]?.outFrom ?? 0) : body;
  };
  return { text: out, position };
}
