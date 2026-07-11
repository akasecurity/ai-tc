// Pure USD/cost-label formatters shared by every token read surface — the
// plugin's `/aka:tokens`, the OSS Activity page, and the CLI `aka stats` block +
// TUI — so the same figure AND the same qualifier convention print everywhere
// (the whole point of the cost-model move to `@akasecurity/schema`). No
// Node deps. Cost is a read-time ESTIMATE derived from the price map, never
// stored — the `≥` lower-bound marker carries that when pricing is unknown.

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
