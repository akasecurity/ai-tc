/**
 * The non-colour channel a chart series is identified by, shared between the
 * line that carries it and every chip that stands for that line.
 *
 * It lives apart from both so the chart primitive does not have to import the
 * legend component to draw a swatch.
 */

/**
 * A `stroke-dasharray` rewritten as a CSS mask, so a chip carries the same
 * pattern as the line it stands for — without which the dash on the line says
 * only that two series DIFFER, never which one is which. An odd-length array is
 * repeated to an even one exactly as SVG does, so `'5'` means five on, five off
 * in both places.
 *
 * Returns `undefined` for anything that cannot be drawn, which the callers
 * render as a solid chip.
 */
export function dashMask(dash: string): string | undefined {
  const lengths = dash
    .split(/[\s,]+/)
    .filter((token) => token !== '')
    .map(Number);
  // A pattern this cannot parse falls back to a solid chip rather than an empty
  // mask, which would hide the chip altogether.
  if (lengths.length === 0 || lengths.some((n) => !Number.isFinite(n) || n < 0)) return undefined;
  // An all-zero array is the same rejection by a different route. CSS renders a
  // repeating gradient whose stops are zero apart as a solid of its LAST stop,
  // which here is `transparent` — so it would hide the chip exactly as an empty
  // mask does, while SVG ignores the dasharray and draws the line solid.
  if (lengths.reduce((sum, n) => sum + n, 0) === 0) return undefined;
  const cycle = lengths.length % 2 === 0 ? lengths : [...lengths, ...lengths];
  let at = 0;
  const stops = cycle.map((length, i) => {
    const from = at;
    at += length;
    return `${i % 2 === 0 ? '#000' : 'transparent'} ${String(from)}px ${String(at)}px`;
  });
  return `repeating-linear-gradient(90deg, ${stops.join(', ')})`;
}
