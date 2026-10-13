import type { Span } from '@akasecurity/schema';

import type { MatchResult } from './types.ts';

const MAX_NAME_LENGTH = 128;
const LOOKBEHIND_CHARS = MAX_NAME_LENGTH + 32;

// The text immediately left of a value that is the right-hand side of an
// assignment on the same line: `NAME=`, `export NAME = "`, `name: '`,
// `"name": "`, `obj.NAME := `. Group 1 is the name.
const ASSIGNMENT_TAIL =
  /(?:^|[\s;{,(.])(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_-]*)["']?[ \t]*(?::=|=|:)[ \t]*["']?$/d;

// A character outside every class above, standing in for the start of a
// window that was cut mid-line so the cut cannot read as a line start.
const CUT_MARK = '#';

function nameSpanBefore(text: string, valueStart: number): Span | undefined {
  const windowStart = Math.max(0, valueStart - LOOKBEHIND_CHARS);
  const window = text.slice(windowStart, valueStart);
  const lineBreak = Math.max(window.lastIndexOf('\n'), window.lastIndexOf('\r'));
  const lineStartsInWindow = lineBreak >= 0 || windowStart === 0;
  const line = window.slice(lineBreak + 1);
  const offset = windowStart + lineBreak + 1;
  const subject = lineStartsInWindow ? line : CUT_MARK + line;
  const shift = lineStartsInWindow ? offset : offset - CUT_MARK.length;
  const indices = ASSIGNMENT_TAIL.exec(subject)?.indices?.[1];
  if (indices === undefined) return undefined;
  const [start, end] = indices;
  if (end - start > MAX_NAME_LENGTH) return undefined;
  return { start: start + shift, end: end + shift };
}

// Answers "does any of these spans overlap [start, end)?" in O(log n): spans
// sorted by start, with the running maximum end, so every span starting before
// `end` is summarised by one value.
function overlapIndex(spans: Span[]): (span: Span) => boolean {
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const starts = sorted.map((s) => s.start);
  const maxEnds: number[] = [];
  let running = -1;
  for (const s of sorted) {
    running = Math.max(running, s.end);
    maxEnds.push(running);
  }
  return ({ start, end }) => {
    let lo = 0;
    let hi = starts.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if ((starts[mid] ?? 0) < end) lo = mid + 1;
      else hi = mid;
    }
    return lo > 0 && (maxEnds[lo - 1] ?? -1) > start;
  };
}

/**
 * Sets `variableName` on each secret finding whose value is the right-hand
 * side of an assignment on its line. A name that is itself covered by a secret
 * finding is not recorded, so a name can never carry a detected value.
 */
export function withVariableNames(findings: MatchResult[], text: string): MatchResult[] {
  const secretSpans = findings.filter((f) => f.category === 'secret').map((f) => f.span);
  if (secretSpans.length === 0) return findings;
  const coveredByDetection = overlapIndex(secretSpans);
  return findings.map((finding) => {
    if (finding.category !== 'secret') return finding;
    const nameSpan = nameSpanBefore(text, finding.span.start);
    if (nameSpan === undefined || coveredByDetection(nameSpan)) return finding;
    return { ...finding, variableName: text.slice(nameSpan.start, nameSpan.end) };
  });
}
