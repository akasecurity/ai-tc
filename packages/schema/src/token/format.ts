import type { CostBasis, UsageChannel } from '../zod/meta.ts';

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

const USAGE_CHANNEL_LABEL: Record<UsageChannel, string> = {
  api_key: 'API key',
  subscription: 'Subscription',
  cloud: 'Cloud',
  gateway: 'Gateway',
  unknown: 'Unknown',
};

/** How a usage row was paid for, as a column value. */
export function usageChannelLabel(channel: UsageChannel): string {
  return USAGE_CHANNEL_LABEL[channel];
}

/** The note every surface prints beside an API-equivalent figure. */
export const API_EQUIVALENT_NOTE =
  'API-equivalent is subscription usage priced at API list rates. A plan is billed as a flat fee, so it is not spend.';

/** A model row's cost: `—` when unpriced, and marked `API-eq.` when it is subscription value. */
export function formatModelCost(costUsd: number | null, costBasis: CostBasis | null): string {
  if (costUsd === null) return '—';
  return costBasis === 'api_equivalent' ? `${formatUsd(costUsd)} API-eq.` : formatUsd(costUsd);
}

/** True when any row of a token summary is subscription usage priced at list rates. */
export function hasApiEquivalent(models: readonly { costBasis: CostBasis | null }[]): boolean {
  return models.some((m) => m.costBasis === 'api_equivalent');
}

/** The note for a spend total that an unpriced per-token row leaves a lower bound. */
export const SPEND_LOWER_BOUND_NOTE =
  '— = unknown pricing (a local or non-Anthropic model); the spend total is a lower bound.';

/** The note for an API-equivalent total that an unpriced subscription row leaves a lower bound. */
export const API_EQUIVALENT_LOWER_BOUND_NOTE =
  '— on a subscription row = unknown pricing; the API-equivalent total is a lower bound.';

/** The notes a token summary prints below its rows, in order. */
export function tokenCostNotes(summary: {
  readonly costIsPartial: boolean;
  readonly apiEquivalentIsPartial: boolean;
  readonly models: readonly { costBasis: CostBasis | null }[];
}): string[] {
  return [
    ...(summary.costIsPartial ? [SPEND_LOWER_BOUND_NOTE] : []),
    ...(summary.apiEquivalentIsPartial ? [API_EQUIVALENT_LOWER_BOUND_NOTE] : []),
    ...(hasApiEquivalent(summary.models) ? [API_EQUIVALENT_NOTE] : []),
  ];
}
