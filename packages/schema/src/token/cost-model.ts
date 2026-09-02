// CostModel — a pure, read-time seam for deriving an estimated USD cost from a
// token-usage bag. The transcript never carries a cost field (verified), so cost
// is DERIVED at read time from a price map keyed by `(provider, model)`; tokens
// are the stored truth. This file holds the plugin-local default implementation
// plus a reference price map. It is intentionally pure: no I/O, no `process.env`,
// no `fetch`, no Node-API deps — so it lives in `@akasecurity/schema` (the
// shared core) and is imported by every read/report surface: the plugin's
// `/aka:tokens`, the Activity page (via `@akasecurity/persistence`), and the
// CLI/TUI. `@akasecurity/plugin-sdk` re-exports it for back-compat.
//
// Design notes:
//   - Unknown `(provider, model)` → `null` ("unknown"); we never guess a figure.
//   - Local providers (ollama) map to a zero-cost entry, so a local model is $0,
//     not "unknown".
//   - `normalizeModelId` *canonicalizes the model id only*; it does NOT rewrite
//     the provider. A Bedrock/Vertex/gateway usage bag therefore asks the catalog
//     for that platform's own price, which is carried only where that platform's
//     published rate was read. Non-direct rates differ from first-party ones in
//     reality, so an unread one stays `null` rather than being assumed equal.
//   - The `CostModel` interface is the swap point for an alternative price
//     source; the catalog below is the permanent fallback.
//
// Prices come from `../model/catalog.ts` and are declared nowhere else. They are
// a REFERENCE snapshot, not authoritative billing — a derived number is an
// estimate, and subscription usage burns rate-limit budget rather than dollar
// credits.
import { MODEL_INDEX } from '../model/catalog.ts';
import type { ModelPrice } from '../model/pricing.ts';
import { costOf, ZERO_PRICE } from '../model/pricing.ts';
import { ModelPlatform } from '../model/providers.ts';
import { resolveModel } from '../model/resolve.ts';

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

/**
 * The read-time cost seam. Implementations turn a token-usage bag for a given
 * `(provider, model)` into an estimated USD cost, or `null` when the pair is
 * unknown (so the caller can render "unknown" rather than a wrong number).
 */
export interface CostModel {
  /**
   * @returns estimated USD cost, or `null` when `(provider, model)` is not in
   *   the price map. A known-but-local entry (e.g. ollama) returns `0`, never
   *   `null` — local inference is free, not unknown.
   */
  costFor(input: { provider: string; model: string; usage: CostUsage }): number | null;

  /**
   * Fold a gateway/Bedrock/Vertex-specific `(provider, model)` onto the canonical
   * key used by the price map. Exposed so callers/tests can inspect the mapping.
   */
  normalizeModelId(provider: string, model: string): { provider: string; model: string };
}

/**
 * Map a stored provider string onto a catalog platform. Unrecognised providers
 * stay unmapped, which resolves to an unknown price rather than a guessed one.
 */
function platformFor(provider: string): ModelPlatform | null {
  const parsed = ModelPlatform.safeParse(provider.trim().toLowerCase());
  return parsed.success ? parsed.data : null;
}

/** True when a platform runs on the caller's own hardware. */
function isLocalProvider(provider: string): boolean {
  const p = provider.trim().toLowerCase();
  return p === 'ollama' || p === 'local';
}

/**
 * The price for a `(provider, model)` pair, or `null` when the catalog carries
 * no verified rate for that platform.
 */
function priceFor(provider: string, model: string): ModelPrice | null {
  if (isLocalProvider(provider)) return ZERO_PRICE;

  const resolved = resolveModel(model, MODEL_INDEX);
  if (resolved.entry === null) return null;

  const platform = platformFor(provider);
  if (platform === null) return null;

  return resolved.entry.platforms.get(platform)?.price ?? null;
}

const defaultCostModel: CostModel = {
  normalizeModelId(provider, model) {
    const p = provider.trim().toLowerCase();
    // Local providers: collapse any model onto the wildcard zero-cost key.
    if (isLocalProvider(p)) {
      return { provider: p, model: '*' };
    }
    // Everything else: canonicalize the model id, preserving the provider. An
    // id the catalog does not carry is returned unchanged — decorations are
    // stripped to attempt a match, never to rewrite an unrecognised id.
    const resolved = resolveModel(model, MODEL_INDEX);
    return { provider: p, model: resolved.entry?.id ?? model };
  },

  costFor({ provider, model, usage }) {
    const price = priceFor(provider, model);
    if (price === null) return null; // unknown (provider, model) — never guess
    return costOf(price, usage);
  },
};

export { defaultCostModel };
