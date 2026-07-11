// Pure USD/cost-label formatters shared by every token read surface — the
// plugin's `/aka:tokens`, the OSS Activity page, and the CLI `aka stats` block +
// TUI — so the same figure AND the same qualifier convention print everywhere
// (the whole point of the cost-model move to `@akasecurity/schema`). No
// Node deps. Cost is a read-time ESTIMATE derived from the price map, never
// stored — the `≥` lower-bound marker carries that when pricing is unknown.

/**
 * Compact token magnitude with SI-style roll-up: `12.3k`, `4.5M`, `1.2B` — 1000k
 * rolls to 1M, 1000M to 1B (rather than the old always-`k` form that printed an
 * unreadable "4464193.1k"). Under 1000 prints the exact integer. Negative-safe.
 */
export function formatTokenCount(n: number): string {
  const abs = Math.abs(n);
  if (abs < 1_000) return String(n);
  if (abs < 1_000_000) return `${(n / 1_000).toFixed(1)}k`;
  if (abs < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${(n / 1_000_000_000).toFixed(1)}B`;
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
