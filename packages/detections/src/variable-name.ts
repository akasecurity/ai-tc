import type { Span } from '@akasecurity/schema';
import { MAX_VARIABLE_NAME_LENGTH } from '@akasecurity/schema';

import type { MatchResult } from './types.ts';

// How far left of a value its name is looked for.
export const VARIABLE_NAME_LOOKBEHIND = MAX_VARIABLE_NAME_LENGTH + 64;

const NAME = '([A-Za-z_][A-Za-z0-9_-]*)';
const TYPE = '[A-Za-z_*\\[][\\w.*\\[\\]<>?|]*';
const OPEN_QUOTE = '["\'`]';
const DECLARATION = '(?:(?:export|const|let|var|val|final|readonly)[ \\t]+)*';

// Each pattern matches the text immediately left of a value on the same line,
// and every capture group in it is the name. A quoted name is accepted only
// where it is a key, so a string literal elsewhere on the line is never read
// as one.
const NAME_PATTERNS: readonly RegExp[] = [
  // `var name string = "`.
  new RegExp(
    `(?:^|[\\s;{(])(?:var|const)[ \\t]+${NAME}[ \\t]+${TYPE}[ \\t]*=[ \\t]*${OPEN_QUOTE}?$`,
    'd',
  ),
  // `NAME=`, `export NAME = "`, `obj.NAME := `, `name: string = "`.
  new RegExp(
    `(?:^|[\\s;{,(.])${DECLARATION}${NAME}(?:[ \\t]*:[ \\t]*${TYPE})?[ \\t]*:?=[ \\t]*${OPEN_QUOTE}?$`,
    'd',
  ),
  // A key at the start of a line (YAML, also as a list item): `name: `,
  // `"name": "`. The separator is followed by whitespace or a quote, so a
  // `user:pass` pair is not a key.
  new RegExp(
    `^[ \\t]*(?:-[ \\t]+)?(?:"${NAME}"|'${NAME}'|${NAME})[ \\t]*:(?:[ \\t]+${OPEN_QUOTE}?|${OPEN_QUOTE})$`,
    'd',
  ),
  // A key after `{` or `,`: `{"name": "`, `, name: "`. An unquoted key here
  // needs a quoted value, which separates `{ apiKey: "` from prose after a
  // comma.
  new RegExp(
    `[{,][ \\t]*(?:"${NAME}"[ \\t]*:[ \\t]*${OPEN_QUOTE}?|'${NAME}'[ \\t]*:[ \\t]*${OPEN_QUOTE}?|${NAME}[ \\t]*:[ \\t]*${OPEN_QUOTE})$`,
    'd',
  ),
];

// A character outside every class above, standing in for the start of a
// window that was cut mid-line so the cut cannot read as a line start.
const CUT_MARK = '#';

// A line that is a `//` or `#` comment.
const COMMENT_LINE = /^[ \t]*(?:\/\/|#)/;

// The name is the false branch of a ternary (`a ? NAME = `, `a ? b : NAME = `).
function inTernary(beforeName: string): boolean {
  const before = beforeName.trimEnd();
  if (before.endsWith('?')) return true;
  return before.endsWith(':') && /\s$/.test(before.slice(0, -1));
}

function nameIndicesIn(subject: string): [number, number] | undefined {
  for (const pattern of NAME_PATTERNS) {
    const groups = pattern.exec(subject)?.indices;
    if (groups === undefined) continue;
    for (let i = 1; i < groups.length; i++) {
      const indices = groups[i];
      if (indices !== undefined)
        return inTernary(subject.slice(0, indices[0])) ? undefined : indices;
    }
  }
  return undefined;
}

function nameSpanBefore(text: string, valueStart: number): Span | undefined {
  const windowStart = Math.max(0, valueStart - VARIABLE_NAME_LOOKBEHIND);
  const window = text.slice(windowStart, valueStart);
  const lineBreak = Math.max(window.lastIndexOf('\n'), window.lastIndexOf('\r'));
  const lineStartsInWindow = lineBreak >= 0 || windowStart === 0;
  const line = window.slice(lineBreak + 1);
  const offset = windowStart + lineBreak + 1;
  if (lineStartsInWindow && COMMENT_LINE.test(line)) return undefined;
  const subject = lineStartsInWindow ? line : CUT_MARK + line;
  const shift = lineStartsInWindow ? offset : offset - CUT_MARK.length;
  const indices = nameIndicesIn(subject);
  if (indices === undefined) return undefined;
  const [start, end] = indices;
  if (end - start > MAX_VARIABLE_NAME_LENGTH) return undefined;
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
 * side of an assignment, or the value of a key, on its line. `text` is the
 * text the findings were scanned from. A name that overlaps any finding, of
 * any category, is not recorded, so a name never carries a detected value.
 *
 * The heuristic reads the line, not the language's syntax. It skips a line
 * that starts as a `//` or `#` comment, but still reads an assignment inside a
 * trailing comment (`x = 1 # NAME=`). It misses a bracketed or quoted target
 * (`process.env["KEY"] = `), a query-string parameter (`?api_key=`), a type
 * annotation containing `,` or `{` (`Record<string, string>`,
 * `{ a: string }`) and a non-ASCII identifier.
 */
export function withVariableNames(findings: MatchResult[], text: string): MatchResult[] {
  if (!findings.some((f) => f.category === 'secret')) return findings;
  const coveredByDetection = overlapIndex(findings.map((f) => f.span));
  return findings.map((finding) => {
    if (finding.category !== 'secret') return finding;
    const nameSpan = nameSpanBefore(text, finding.span.start);
    if (nameSpan === undefined || coveredByDetection(nameSpan)) return finding;
    return { ...finding, variableName: text.slice(nameSpan.start, nameSpan.end) };
  });
}
