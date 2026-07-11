// Glyph-bar geometry, ported from the plugin's transcript layout kit
// (plugins/claude-code/src/present.ts). The plugin emits these as plain
// strings; here each run is rendered as its own coloured <Text>, so the
// functions return run descriptors (glyph + length + colour) rather than a
// pre-joined string. No ANSI is involved in the maths, so visible width is just
// `.length`.

export function padEnd(text: string, width: number): string {
  const pad = width - text.length;
  return pad > 0 ? text + ' '.repeat(pad) : text;
}

export function padStart(text: string, width: number): string {
  const pad = width - text.length;
  return pad > 0 ? ' '.repeat(pad) + text : text;
}

// A proportional gauge: how many of `width` cells are filled by `value/max`.
// The caller draws `filled` solid blocks then `empty` faint-track blocks.
export function gaugeFill(
  value: number,
  max: number,
  width: number,
): { filled: number; empty: number } {
  const raw = max <= 0 ? 0 : Math.round((value / max) * width);
  const filled = Math.max(0, Math.min(width, raw));
  return { filled, empty: width - filled };
}

export interface StackSegment {
  value: number;
  glyph: string;
  color: string;
}

export interface StackRun {
  glyph: string;
  len: number;
  color: string;
}

// A horizontal stacked bar: each segment gets a run of its glyph sized by its
// share of `total`, and the whole run's length scales `total` against `max` so a
// quieter day draws a shorter bar. Largest-remainder allocation (floor every
// segment, hand the leftover cells to the biggest fractional remainders) keeps
// the runs from leaving holes — exactly the algorithm from present.ts.stackedBar.
// `blank` is the unfilled remainder to `width`, drawn as spaces (not a track) so
// the trailing count still aligns.
export function stackedBar(
  segments: StackSegment[],
  total: number,
  max: number,
  width: number,
): { runs: StackRun[]; blank: number } {
  const filled = max <= 0 ? 0 : Math.max(0, Math.min(width, Math.round((total / max) * width)));
  const parts = segments.map((seg) => {
    const exact = total <= 0 ? 0 : (Math.max(0, seg.value) / total) * filled;
    const len = Math.floor(exact);
    return { glyph: seg.glyph, color: seg.color, len, frac: exact - len };
  });
  const floored = parts.reduce((sum, p) => sum + p.len, 0);
  const target = Math.min(filled, Math.round(parts.reduce((sum, p) => sum + p.len + p.frac, 0)));
  let remainder = target - floored;
  for (const p of [...parts].sort((a, b) => b.frac - a.frac)) {
    if (remainder <= 0) break;
    p.len += 1;
    remainder -= 1;
  }
  const placed = parts.reduce((sum, p) => sum + p.len, 0);
  return {
    runs: parts.map(({ glyph, len, color }) => ({ glyph, len, color })),
    blank: Math.max(0, width - placed),
  };
}

// Greedy word-wrap to `width` columns; always returns at least one line.
export function wrapText(text: string, width: number): string[] {
  const lines: string[] = [];
  let current = '';
  for (const word of text.split(' ')) {
    if (current === '') current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== '') lines.push(current);
  return lines.length > 0 ? lines : [''];
}
