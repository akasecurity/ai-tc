// The single price table, read by `token/cost-model.ts`. Prices live here and
// nowhere else, so a rate is edited in one place.
//
// Two rules this module enforces structurally rather than by comment:
//
//   1. An unverified price is `null`, never a number. A missing entry resolves
//      to "cost unknown" at the call site; it never falls back to a lookalike
//      model's rate, and it never silently becomes 0.
//   2. Only a vendor's FIRST-PARTY platform may carry the vendor's published
//      rates. A reseller bills at its own rates — verified: Bedrock served
//      Claude 3.5 Sonnet v2 at $6/$30 against Anthropic's own $3/$15, exactly
//      2x — so a reseller entry stays unpriced until someone reads that
//      platform's own price page.
import * as z from 'zod';

import type { CostUsage } from '../token/cost-usage.ts';

/**
 * A second rate band that applies once a request's INPUT crosses `thresholdInputTokens`.
 * The input counted is the whole prompt, cached tokens included.
 *
 * The band applies to the whole request, not just the tokens above the line:
 * "For GPT-5.6, prompts with more than 272,000 input tokens use long-context
 * pricing for the full request, not only for tokens beyond the threshold."
 * Anthropic (Haiku 5.5, at 100K), Google and xAI (at 200K) tier the same way.
 *
 * Every rate is per column. `input`/`output` are nullable because a vendor can
 * publish the THRESHOLD without publishing the rate above it; the cache columns
 * are optional as well as nullable. Absent, the vendor publishes no band rate
 * for that column and the base rate applies; null, the band re-prices it at a
 * rate that was not read, so a request that bills against that column is
 * unknown. "Unknown above this size" is a very different statement from "same
 * price", and the difference is a bill.
 */
export const LongContextTier = z.object({
  thresholdInputTokens: z.number().int().positive(),
  input: z.number().nonnegative().nullable(),
  output: z.number().nonnegative().nullable(),
  cacheRead: z.number().nonnegative().nullable().optional(),
  cacheWrite5m: z.number().nonnegative().nullable().optional(),
  cacheWrite1h: z.number().nonnegative().nullable().optional(),
});
export type LongContextTier = z.infer<typeof LongContextTier>;

export const ModelPrice = z.object({
  /** USD per 1M uncached input tokens, at or below any long-context threshold. */
  input: z.number().nonnegative(),
  /** USD per 1M output tokens, at or below any long-context threshold. */
  output: z.number().nonnegative(),
  /**
   * Rate band above a size threshold, or `null` when the model is flat-rated.
   * OpenAI, Google, xAI and some Anthropic models (Haiku 5.5) band; most
   * Claude models are flat across their window.
   */
  longContext: LongContextTier.nullable(),
  /** USD per 1M tokens written to a 5-minute ephemeral cache, or null if unpriced. */
  cacheWrite5m: z.number().nonnegative().nullable(),
  /** USD per 1M tokens written to a 1-hour ephemeral cache, or null if unpriced. */
  cacheWrite1h: z.number().nonnegative().nullable(),
  /** USD per 1M tokens read from cache, or null if unpriced. */
  cacheRead: z.number().nonnegative().nullable(),
  /** USD per single server-side web-search request, or null if the platform has none. */
  webSearch: z.number().nonnegative().nullable(),
});
export type ModelPrice = z.infer<typeof ModelPrice>;

/** $10 per 1,000 web-search requests = $0.01 per request. */
export const WEB_SEARCH_PER_REQUEST = 0.01;

/**
 * An Anthropic-shaped price. `cacheRead` is a REQUIRED argument, not a derived
 * column: see the note on `ModelPrice.cacheRead`. Cache writes remain derived
 * (5m = 1.25x input, 1h = 2x input), which is still uniform across the family
 * and is re-verified on each price update. `longContext` is the model's band,
 * built with `anthropicBand`, for the Claude models that price by prompt length.
 */
export function anthropicPrice(
  input: number,
  output: number,
  cacheRead: number,
  longContext: LongContextTier | null = null,
): ModelPrice {
  return Object.freeze({
    input,
    output,
    longContext: longContext === null ? null : Object.freeze(longContext),
    cacheWrite5m: input * 1.25,
    cacheWrite1h: input * 2,
    cacheRead,
    webSearch: WEB_SEARCH_PER_REQUEST,
  });
}

/** An Anthropic long-context band, with cache writes derived the same way as the base rate. */
export function anthropicBand(
  thresholdInputTokens: number,
  input: number,
  output: number,
  cacheRead: number,
): LongContextTier {
  return {
    thresholdInputTokens,
    input,
    output,
    cacheRead,
    cacheWrite5m: input * 1.25,
    cacheWrite1h: input * 2,
  };
}

/**
 * A band that scales the base rates by the vendor's published multipliers, for
 * vendors that publish the band as a ratio of the base (OpenAI: 2x input and
 * cache reads, 1.5x output; xAI: 2x every column). A cache rate is carried into
 * the band only when the base has one.
 */
export function scaledBand(
  thresholdInputTokens: number,
  base: { input: number; output: number; cacheRead?: number },
  scale: { input: number; output: number; cacheRead: number },
): LongContextTier {
  return {
    thresholdInputTokens,
    input: base.input * scale.input,
    output: base.output * scale.output,
    ...(base.cacheRead === undefined ? {} : { cacheRead: base.cacheRead * scale.cacheRead }),
  };
}

/**
 * A plain input/output price for a vendor with no cache-pricing tiers we have
 * verified. The cache columns are `null` (unknown), not 0 — a zero would read
 * as "cached tokens are free", which is a price claim of its own.
 */
export function tokenPrice(
  input: number,
  output: number,
  options: { cacheRead?: number; longContext?: LongContextTier } = {},
): ModelPrice {
  return Object.freeze({
    input,
    output,
    longContext: options.longContext === undefined ? null : Object.freeze(options.longContext),
    cacheWrite5m: null,
    cacheWrite1h: null,
    cacheRead: options.cacheRead ?? null,
    webSearch: null,
  });
}

/**
 * Self-hosted inference: every column is a known 0. Distinct from an absent
 * entry, which means "unknown" — running Llama on your own GPU genuinely costs
 * the vendor relationship nothing, and reporting that as unknown would be as
 * wrong as inventing a rate.
 */
export const ZERO_PRICE: ModelPrice = Object.freeze({
  input: 0,
  output: 0,
  longContext: null,
  cacheWrite5m: 0,
  cacheWrite1h: 0,
  cacheRead: 0,
  webSearch: 0,
});

/** Service-tier multipliers applied to the whole per-call token cost. */
const SERVICE_TIER_MULTIPLIERS: ReadonlyMap<string, number> = new Map([
  ['standard', 1],
  ['batch', 0.5],
  ['priority', 1.5],
]);

/** The multiplier for a service tier; unknown and absent tiers are 1x. */
export function serviceTierMultiplier(tier: string | undefined): number {
  if (tier === undefined) return 1;
  return SERVICE_TIER_MULTIPLIERS.get(tier) ?? 1;
}

/** The prompt size that selects a long-context band (see `CostUsage.promptTokens`). */
export function promptTokensOf(usage: CostUsage): number {
  return (
    usage.promptTokens ??
    (usage.inputTokens ?? 0) +
      (usage.cacheReadTokens ?? 0) +
      (usage.cacheWrite1hTokens ?? 0) +
      (usage.cacheWrite5mTokens ?? 0)
  );
}

/**
 * The rate a band column bills at: the base rate where the band names none
 * (`undefined`), else the band's own rate, which is `null` when it was not read.
 */
function bandRate(column: number | null | undefined, base: number | null): number | null {
  return column === undefined ? base : column;
}

/**
 * Cost in USD for a usage bag at a given price, or `null` when the price
 * carries no verified rate for a column the usage actually bills against.
 *
 * A `null` column is an UNREAD rate, not a free one. Tokens billed against one
 * cannot be priced, so the whole call is unknown rather than silently
 * undercounted — a partial sum reported as a total is a number nobody checked.
 * A column the usage does not touch contributes nothing either way.
 */
export function costOf(price: ModelPrice, usage: CostUsage): number | null {
  // Above the threshold the band rate applies to the WHOLE request, not just
  // the tokens past it, so every column the band names is re-priced rather
  // than split. The threshold is on the whole prompt, so cached tokens count
  // toward it.
  const band =
    price.longContext !== null && promptTokensOf(usage) > price.longContext.thresholdInputTokens
      ? price.longContext
      : null;

  const metered: readonly (readonly [number, number | null])[] = [
    [usage.inputTokens ?? 0, bandRate(band?.input, price.input)],
    [usage.outputTokens ?? 0, bandRate(band?.output, price.output)],
    [usage.cacheWrite1hTokens ?? 0, bandRate(band?.cacheWrite1h, price.cacheWrite1h)],
    [usage.cacheWrite5mTokens ?? 0, bandRate(band?.cacheWrite5m, price.cacheWrite5m)],
    [usage.cacheReadTokens ?? 0, bandRate(band?.cacheRead, price.cacheRead)],
  ];

  let tokenCost = 0;
  for (const [tokens, rate] of metered) {
    if (tokens === 0) continue;
    if (rate === null) return null;
    tokenCost += tokens * rate;
  }

  // Token prices are per MILLION tokens; divide once at the end.
  const tokenUsd = (tokenCost / 1_000_000) * serviceTierMultiplier(usage.serviceTier);

  // Web search bills per request, not per token, and is not tier-scaled.
  const searches = usage.webSearchRequests ?? 0;
  if (searches > 0 && price.webSearch === null) return null;

  return tokenUsd + searches * (price.webSearch ?? 0);
}
