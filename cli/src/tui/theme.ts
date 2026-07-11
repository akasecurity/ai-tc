// Colour + glyph grammar for the Ink TUI, shared by every view.
//
// This is the COLOUR twin of the plugin's transcript surfaces. The slash-command
// screens (plugins/claude-code/src/render.ts) render the exact same layout in
// MONOCHROME — ANSI doesn't render in the Claude Code transcript, so severity is
// carried by shade texture (░▒▓█) alone. Here in a real terminal Ink emits
// truecolor, so we keep that same glyph grammar and layer the design tokens on
// top: the severity squares, gauges and the 7-day chart now read in colour as
// well as texture. Hex values are the tokens from packages/ui-kit theme.css —
// the same palette the plugin's `paint` status line uses.

export const COLOR = {
  brand: '#33e6c6', // --color-brand        · ▸▸ AKA wordmark
  dim: '#838995', // --color-text-3      · separators, labels, tracks
  ok: '#0db15f', // --color-ok          · healthy / allowed
  critical: '#e63448', // --color-sev-critical
  high: '#e97a0a', // --color-sev-high
  medium: '#f7bd00', // --color-sev-medium
  low: '#0581d4', // --color-sev-low      (azure, not purple)
} as const;

// Shade glyphs, lightest → darkest — heavier fill = more severe / more intense.
export const SHADE = {
  light: '░',
  medium: '▒',
  dark: '▓',
  full: '█',
} as const;

// Severity → shade glyph (texture) and colour (hue). Both encode the same order
// so the severity column reads even if colour is stripped.
const SEVERITY_GLYPH: Record<string, string> = {
  critical: SHADE.full,
  high: SHADE.dark,
  medium: SHADE.medium,
  low: SHADE.light,
};
const SEVERITY_COLOR: Record<string, string> = {
  critical: COLOR.critical,
  high: COLOR.high,
  medium: COLOR.medium,
  low: COLOR.low,
};

export function severityGlyph(severity: string): string {
  return SEVERITY_GLYPH[severity] ?? SHADE.light;
}

export function severityColor(severity: string): string {
  return SEVERITY_COLOR[severity] ?? COLOR.dim;
}

// Enforcement action → colour. Reads green→red as allow→block, matching the
// /health chart legend and used for the action column on /findings and /audit.
const ACTION_COLOR: Record<string, string> = {
  allow: COLOR.ok,
  log: COLOR.dim,
  warn: COLOR.medium,
  redact: COLOR.low,
  block: COLOR.critical,
};

export function actionColor(action: string): string {
  return ACTION_COLOR[action] ?? COLOR.dim;
}

// Health score → dot / gauge band colour (matches the status line's dot logic:
// green ≥80, amber ≥50, red below).
export function scoreColor(score: number): string {
  return score >= 80 ? COLOR.ok : score >= 50 ? COLOR.high : COLOR.critical;
}
