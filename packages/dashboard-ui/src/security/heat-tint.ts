// The heat-map shading for the severity x status matrix.
//
// A cell is painted with its row's severity hue at an alpha that scales with the
// cell's share of the largest cell, over the card surface, with `text-text` on top.
// The alpha cap is what keeps that text legible, and it is pinned against the theme
// tokens in `heat-tint-contrast.test.ts` rather than asserted here.

/** The alpha, in percent, of the largest cell. Text stays at 4.5:1 or better at this cap. */
export const MAX_TINT_PERCENT = 40;

// A non-zero cell never rounds down to an invisible tint, or it would read as emptier
// than a zero cell (which keeps the neutral background).
export const MIN_TINT_PERCENT = 6;

/** The background for a cell of `count`, given the largest cell `max`; none for zero. */
export function tint(color: string, count: number, max: number): string | undefined {
  if (count <= 0 || max <= 0) return undefined;
  const pct = String(Math.max(MIN_TINT_PERCENT, Math.round((count / max) * MAX_TINT_PERCENT)));
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}
