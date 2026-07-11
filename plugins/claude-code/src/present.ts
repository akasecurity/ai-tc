// Tiny zero-dependency terminal layout kit for the read surfaces. The
// hook/command scripts ship self-contained (no node_modules on the user's
// machine), so we can't pull in picocolors/cli-table — plain text and a few
// box-drawing / shade characters give the mockup's look with nothing to bundle.
//
// NO COLOR on the read surfaces. They are echoed verbatim into the Claude Code
// transcript inside a monospace code block, where ANSI escape codes are NOT
// interpreted — they'd show as literal `\x1b[…m` garbage. So meaning is carried
// by glyph texture (shade blocks), spacing and labels, never by hue. All helpers
// are pure (data → string); the entry scripts do the single process.stdout.write.
//
// The ONE exception is the status line (renderStatusLine → scripts/statusline.js):
// Claude Code's statusLine DOES interpret ANSI, so the `paint` palette below is
// for that surface only. Never route a read-surface string through it.
// visibleLength strips ANSI, so even if a colored span flows through, padding
// math is unaffected.

// Shade glyphs, lightest → darkest. The whole UI grammar: heavier fill = more
// severe / more intense. Used for severity cells, the unreviewed tallies and the
// stacked /health chart, so every surface reads the same way in plain monochrome.
export const SHADE = {
  light: '░',
  medium: '▒',
  dark: '▓',
  full: '█',
} as const;

// Visible width. With no ANSI emitted this is just the length, but we still strip
// any stray escape so padding/box math can never be thrown off by one.
// eslint-disable-next-line no-control-regex -- matching the ANSI CSI escape
const ANSI_RE = /\x1b\[[0-9;]*m/g;

export function visibleLength(text: string): number {
  return text.replace(ANSI_RE, '').length;
}

// ANSI palette for the STATUS LINE ONLY (see header). Colours are the exact
// design tokens from packages/ui-kit/src/styles/theme.css, emitted as 24-bit
// truecolor so the status line matches the dashboard. Needs a truecolor terminal
// (iTerm2 / VS Code / WezTerm / Kitty / modern Terminals); the read surfaces stay
// monochrome regardless. Kept dependency-free — the hooks bundle with no node_modules.
const fg =
  (hex: string) =>
  (text: string): string => {
    const r = Number.parseInt(hex.slice(1, 3), 16);
    const g = Number.parseInt(hex.slice(3, 5), 16);
    const b = Number.parseInt(hex.slice(5, 7), 16);
    return `\x1b[38;2;${String(r)};${String(g)};${String(b)}m${text}\x1b[0m`;
  };

export const paint = {
  brand: fg('#33e6c6'), // --color-brand        · ▸▸ AKA wordmark (accent text)
  dim: fg('#838995'), // --color-text-3      · separators · "/100" · the "unreviewed" label
  bold: (text: string): string => `\x1b[1m${text}\x1b[0m`, // the health score number
  ok: fg('#0db15f'), // --color-ok          · healthy ● dot
  critical: fg('#e63448'), // --color-sev-critical · ■ and the open-findings flag
  high: fg('#e97a0a'), // --color-sev-high     · ■ and the mid-health dot
  medium: fg('#f7bd00'), // --color-sev-medium   · ■
  low: fg('#0581d4'), // --color-sev-low      · ■ (azure blue, not purple)
} as const;

export function padEnd(text: string, width: number): string {
  const pad = width - visibleLength(text);
  return pad > 0 ? text + ' '.repeat(pad) : text;
}

export function padStart(text: string, width: number): string {
  const pad = width - visibleLength(text);
  return pad > 0 ? ' '.repeat(pad) + text : text;
}

// A proportional bar of solid blocks, padded to `width` with a faint track — the
// gauge bars from the mockup. `max` of 0 renders an empty track. Length alone
// carries the value, so it reads with no color.
export function bar(value: number, max: number, width = 24): string {
  const filled = max <= 0 ? 0 : Math.round((value / max) * width);
  const clamped = Math.max(0, Math.min(width, filled));
  return SHADE.full.repeat(clamped) + SHADE.light.repeat(width - clamped);
}

// A horizontal stacked bar: each segment contributes a run of its own shade
// glyph, sized by its share of `total`; the whole run's length scales `total`
// against `max`, so a day with fewer requests draws a shorter bar. The remainder
// to `width` is blank (not a track) so the bar simply ends and the trailing count
// still aligns. This is the per-day /health chart (passed / redacted / warned /
// blocked runs), with the shade telling the segments apart in place of color.
export interface BarSegment {
  value: number;
  glyph: string;
}

export function stackedBar(segments: BarSegment[], total: number, max: number, width = 24): string {
  const filled = max <= 0 ? 0 : Math.max(0, Math.min(width, Math.round((total / max) * width)));
  // Largest-remainder allocation. Rounding each segment independently with
  // Math.round() can make the lengths sum to less than `filled`, leaving blank
  // holes inside the bar. Instead floor every segment, then hand the leftover
  // characters to the largest fractional remainders so the segments fill exactly
  // their share — precisely `filled` characters when the values sum to `total`.
  const parts = segments.map((seg) => {
    const exact = total <= 0 ? 0 : (Math.max(0, seg.value) / total) * filled;
    const len = Math.floor(exact);
    return { glyph: seg.glyph, len, frac: exact - len };
  });
  const floored = parts.reduce((sum, p) => sum + p.len, 0);
  // Round the segments' exact total to know how many chars they should cover
  // (== filled when the values sum to total), capped at filled so we never overflow.
  const target = Math.min(filled, Math.round(parts.reduce((sum, p) => sum + p.len + p.frac, 0)));
  let remainder = target - floored;
  for (const p of [...parts].sort((a, b) => b.frac - a.frac)) {
    if (remainder <= 0) break;
    p.len += 1;
    remainder -= 1;
  }
  const out = parts.map((p) => p.glyph.repeat(p.len)).join('');
  const placed = parts.reduce((sum, p) => sum + p.len, 0);
  return out + ' '.repeat(Math.max(0, width - placed));
}

// Greedy word-wrap to `width` columns. Always returns at least one (possibly
// empty) line so callers can index [0] safely.
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

// A definition list: labels in a fixed-width column, values trailing — the
// "Repository / Version / Adds" block from the setup mock. Labels are padded to
// the widest so the value column lines up. `gap` is the space between columns.
export function defList(rows: [string, string][], gap = 4): string {
  const labelWidth = Math.max(0, ...rows.map(([label]) => visibleLength(label)));
  return rows
    .map(([label, value]) => `${padEnd(label, labelWidth)}${' '.repeat(gap)}${value}`)
    .join('\n');
}

// Left-pad every line of a (possibly multi-line) block by `spaces`, so a heading
// can sit at column 0 with its body indented under it.
export function indent(text: string, spaces = 2): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((line) => pad + line)
    .join('\n');
}

// A left-aligned column table with UPPERCASE headers and a configurable column
// gap — the read-surface table style. `rowSep` draws a full-width rule under the
// header and between every data row, so each row reads as its own banded entry
// (the /findings look); without it the header gets the lighter per-column rule
// and rows sit flush (the /audit look).
export function table(
  headers: string[],
  rows: string[][],
  opts: { gap?: number; rowSep?: boolean } = {},
): string {
  const gap = opts.gap ?? 3;
  const widths = headers.map((h, i) =>
    Math.max(visibleLength(h), ...rows.map((r) => visibleLength(r[i] ?? ''))),
  );
  const sep = ' '.repeat(gap);
  const fmt = (cells: string[]): string =>
    cells.map((cell, i) => padEnd(cell, widths[i] ?? 0)).join(sep);
  const headerLine = fmt(headers.map((h) => h.toUpperCase()));

  if (opts.rowSep === true) {
    const fullWidth = widths.reduce((n, w) => n + w, 0) + gap * Math.max(0, widths.length - 1);
    const rule = '─'.repeat(fullWidth);
    const body: string[] = [];
    rows.forEach((row, i) => {
      if (i > 0) body.push(rule);
      body.push(fmt(row));
    });
    return [headerLine, rule, ...body].join('\n');
  }

  const ruleLine = widths.map((w) => '─'.repeat(w)).join(sep);
  return [headerLine, ruleLine, ...rows.map(fmt)].join('\n');
}

// Wrap a rendered surface in a Markdown code fence. The read surfaces are
// space-aligned monospace and ONLY render correctly inside a fenced block —
// outside one, Markdown collapses the indentation and turns line-start `1.`/`●`
// into lists/bullets. Emitting the fence here (rather than trusting whatever
// displays the output to add one) makes each surface self-contained: anything
// that shows the script's stdout verbatim gets correct monospace.
//
// The fence is widened to one backtick longer than the longest backtick run in
// the body: CommonMark closes a fenced block on the first line of >= as many
// backticks, so a body that ever contains ``` (e.g. a masked match) would
// otherwise break out of the block and mis-render everything after it.
export function fenced(body: string): string {
  const longestRun = Math.max(0, ...[...body.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return [fence, body, fence].join('\n');
}
