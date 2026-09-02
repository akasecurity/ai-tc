// The token-usage bag a cost is derived from. Its own module because both the
// price table (`model/pricing.ts`) and the cost model consume it, and either
// owning it would make the two import each other.
/**
 * The token-usage bag a cost is derived from. Every field is optional: non-
 * Anthropic providers return only a subset (the Anthropic-specific cache/web
 * fields simply come back absent), so a missing field contributes nothing to the
 * cost rather than failing the whole computation.
 */
export interface CostUsage {
  /** Uncached input tokens billed at the model's full input rate. */
  inputTokens?: number;
  /** Output (completion) tokens. */
  outputTokens?: number;
  /** Tokens written to the 1-hour ephemeral cache (`cache_creation.ephemeral_1h_input_tokens`). */
  cacheWrite1hTokens?: number;
  /** Tokens written to the 5-minute ephemeral cache (`cache_creation.ephemeral_5m_input_tokens`). */
  cacheWrite5mTokens?: number;
  /** Tokens read from cache (`cache_read_input_tokens`) — priced far below input. */
  cacheReadTokens?: number;
  /** Server-side web-search requests (`server_tool_use.web_search_requests`) — billed per request. */
  webSearchRequests?: number;
  /**
   * Service tier (`usage.service_tier`): standard/batch/priority. Selects a
   * price multiplier (e.g. batch is discounted). Unknown tiers fall back to 1×.
   */
  serviceTier?: string;
}
