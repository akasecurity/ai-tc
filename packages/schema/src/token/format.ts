// Pure USD/cost-label formatters shared by every token read surface — the
// plugin's `/aka:tokens`, the OSS Activity page, and the CLI `aka stats` block +
// TUI — so the same figure AND the same qualifier convention print everywhere
// (the whole point of the cost-model move to `@akasecurity/schema`). No
// Node deps. Cost is a read-time ESTIMATE derived from the price map, never
// stored — the `≥` lower-bound marker carries that when pricing is unknown.

// One compact-number formatter shared by every magnitude surface — token
// totals, KPI tiles, connected-tool prompt counts — so the same value prints
// identically everywhere. Rolls up to K · M · B · T with up to one decimal and
// a dropped trailing ".0" ("1M", not "1.0M"); exact integers under 1000 print
// in full. Negative-safe.
const COMPACT = new Intl.NumberFormat('en-US', {
  notation: 'compact',
  maximumFractionDigits: 1,
});

/** Compact magnitude with K/M/B/T roll-up: `999` · `1.1K` · `45.2K` · `318M` · `4.5B` · `1.5T`. */
export function compactNumber(n: number): string {
  return COMPACT.format(n);
}

/**
 * Compact token magnitude — {@link compactNumber} applied to a raw token count
 * (`12.3K`, `4.5M`, `4.5B`), so token totals print the same K/M/B/T figures as
 * every other magnitude on the dashboard.
 */
export function formatTokenCount(n: number): string {
  return compactNumber(n);
}

/**
 * USD with adaptive precision: a clean total reads at 2 dp, a sub-10¢ estimate
 * needs 4 so it isn't rounded to $0.00.
 */
export function formatUsd(value: number): string {
  return value > 0 && value < 0.1 ? `$${value.toFixed(4)}` : `$${value.toFixed(2)}`;
}

/**
 * Grand-total cost label: `≥ $X` when ANY call had unknown pricing (the total is
 * then a lower bound, never a silently-understated figure), else `$X`.
 */
export function formatCostTotal(estimatedCostUsd: number, costIsPartial: boolean): string {
  return costIsPartial ? `≥ ${formatUsd(estimatedCostUsd)}` : formatUsd(estimatedCostUsd);
}
