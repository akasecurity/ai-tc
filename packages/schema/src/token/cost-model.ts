// CostModel — a pure, read-time seam for deriving an estimated USD cost from a
// token-usage bag. The transcript never carries a cost field (verified), so cost
// is DERIVED at read time from a price map keyed by `(provider, model)`; tokens
// are the stored truth. This file holds the plugin-local default implementation
// plus a reference price map. It is intentionally pure: no I/O, no `process.env`,
// no `fetch`, no Node-API deps — so it lives in `@akasecurity/schema` (the
// tenant-free core) and is imported by every read/report surface: the plugin's
// `/aka:tokens`, the OSS Activity page (via `@akasecurity/persistence`), and the
// CLI/TUI. `@akasecurity/plugin-sdk` re-exports it for back-compat.
//
// Design notes:
//   - Unknown `(provider, model)` → `null` ("unknown"); we never guess a figure.
//   - Local providers (ollama) map to a zero-cost entry, so a local model is $0,
//     not "unknown".
//   - `normalizeModelId` *canonicalizes the model id only* (strips Bedrock
//     region/version suffixes and the `anthropic/` gateway prefix for grouping/
//     display); it does NOT rewrite the provider. A Bedrock/Vertex/gateway usage
//     bag therefore looks up `(bedrock|vertex|gateway, canonical-model)`, which is
//     NOT in PRICE_MAP (only `anthropic` is) → `null`. We never price non-direct
//     providers at Anthropic-direct rates (those rates differ in reality, and the
//     never-guess rule forbids assuming they match).
//   - The `CostModel` interface is the swap point for an alternative price
//     map; the compiled-in map below is the permanent fallback.
//
// ⚠️ Prices below are a REFERENCE snapshot of current public Anthropic list
// pricing (per million tokens). They are NOT authoritative billing — our derived
// number is an estimate (subscription usage burns rate-limit budget, not dollar
// credits). Keep them updated.

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

/** Per-(provider, model) prices. Token prices are USD per MILLION tokens. */
export interface ModelPrice {
  /** USD per 1M uncached input tokens. */
  input: number;
  /** USD per 1M output tokens. */
  output: number;
  /** USD per 1M tokens written to the 1h ephemeral cache (Anthropic: 2× input). */
  cacheWrite1h: number;
  /** USD per 1M tokens written to the 5m ephemeral cache (Anthropic: 1.25× input). */
  cacheWrite5m: number;
  /** USD per 1M tokens read from cache (Anthropic: 0.1× input). */
  cacheRead: number;
  /** USD per single web-search request (per-request, not per-token). */
  webSearch: number;
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

// Per-MTok multipliers Anthropic applies to the base input rate. Used to derive
// the cache columns from `input` so a single rate edit stays internally
// consistent. (5m write = 1.25×, 1h write = 2×, read = 0.1×.)
const CACHE_WRITE_5M_MULT = 1.25;
const CACHE_WRITE_1H_MULT = 2;
const CACHE_READ_MULT = 0.1;

// $10 per 1,000 web-search requests = $0.01 per request (current public price).
const WEB_SEARCH_PER_REQUEST = 0.01;

/** Build an Anthropic-shaped price entry from base input/output rates. */
function anthropicPrice(input: number, output: number): ModelPrice {
  return {
    input,
    output,
    cacheWrite5m: input * CACHE_WRITE_5M_MULT,
    cacheWrite1h: input * CACHE_WRITE_1H_MULT,
    cacheRead: input * CACHE_READ_MULT,
    webSearch: WEB_SEARCH_PER_REQUEST,
  };
}

// A zero-cost entry for local/self-hosted inference — every column is 0 so a
// local model resolves to $0 (a known price), not `null` (unknown).
const ZERO_PRICE: ModelPrice = {
  input: 0,
  output: 0,
  cacheWrite5m: 0,
  cacheWrite1h: 0,
  cacheRead: 0,
  webSearch: 0,
};

// Per-million-token reference prices — current public Anthropic list pricing.
// Source: https://platform.claude.com/docs/en/pricing (a.k.a. claude.com/pricing).
// prices as of 2026-06-29 — re-verify on update.
//   Opus 4.8/4.7/4.6/4.5: $5 in / $25 out
//   Sonnet 4.6/4.5:       $3 in / $15 out
//   Haiku 4.5:            $1 in / $5 out
// NOTE for the next updater: the Opus/Sonnet input prices being this close ($5 vs
// $3) is EXPECTED for this generation — current Opus is $5/$25, NOT the historical
// Opus-3 $15/$75. Don't "fix" the Opus numbers up to match an old mental model;
// they are correct as written. Cache columns are derived from `input` via the
// multipliers above (5m write = 1.25×, 1h write = 2×, read = 0.1×). These are a
// REFERENCE to be updated — do not treat them as
// authoritative billing.
const ANTHROPIC_PRICES: Record<string, ModelPrice> = {
  'claude-fable-5': anthropicPrice(10, 50),
  'claude-opus-4-8': anthropicPrice(5, 25),
  'claude-opus-4-7': anthropicPrice(5, 25),
  'claude-opus-4-6': anthropicPrice(5, 25),
  'claude-opus-4-5': anthropicPrice(5, 25),
  'claude-sonnet-5': anthropicPrice(3, 15),
  'claude-sonnet-4-6': anthropicPrice(3, 15),
  'claude-sonnet-4-5': anthropicPrice(3, 15),
  'claude-haiku-4-5': anthropicPrice(1, 5),
};

// The price map, keyed `"<provider>/<model>"` (NOT model alone — the same model
// id costs differently per provider). `normalizeModelId` canonicalizes the *model
// id* before lookup but preserves the original provider. Bedrock/Vertex/gateway
// prices differ from Anthropic-direct in reality, so only `anthropic/*` direct
// keys + the local zero-cost wildcards are populated here; a `bedrock/...`,
// `vertex/...`, or other-gateway pair is absent and resolves to `null` (cost
// unknown), never silently priced at Anthropic-direct rates.
const PRICE_MAP: Record<string, ModelPrice> = {
  ...Object.fromEntries(
    Object.entries(ANTHROPIC_PRICES).map(([model, price]) => [`anthropic/${model}`, price]),
  ),
  // Local providers: known and free.
  'ollama/*': ZERO_PRICE,
  'local/*': ZERO_PRICE,
};

// Service-tier price multipliers. `batch` is half price; `priority` is a premium;
// `standard` (and anything unrecognized) is 1×. The multiplier is applied to the
// FULL per-call token cost — input, output, AND cache read/write — because the
// batch discount is a flat 50% on the whole request (every token type), not just
// fresh input/output. See `costFor` where `serviceTierMultiplier` scales the
// summed `tokenCost`. (Web-search is per-request, not per-token, so it is left
// out of the tier scaling.)
const SERVICE_TIER_MULTIPLIERS: Record<string, number> = {
  standard: 1,
  batch: 0.5,
  priority: 1.5,
};

function serviceTierMultiplier(tier: string | undefined): number {
  if (tier === undefined) return 1;
  return SERVICE_TIER_MULTIPLIERS[tier] ?? 1;
}

// Canonical Anthropic model ids the gateway/Bedrock/Vertex variants canonicalize
// onto. Kept as a list so the longest match wins (`claude-3-5-sonnet` before a
// bare `sonnet` heuristic would, etc.) — but for our current families
// exact-substring matching is sufficient.
const CANONICAL_ANTHROPIC_MODELS = Object.keys(ANTHROPIC_PRICES);

// Canonicalize a raw (possibly gateway/Bedrock/Vertex) *model id* onto a canonical
// Anthropic id when we can recognize it; otherwise return it unchanged. This only
// touches the model string — the provider is preserved by the caller. Canonicalizes:
//   anthropic/claude-3.5-sonnet            (gateway, dotted)   → claude-sonnet-4-6 is NOT assumed
//   anthropic.claude-opus-4-8              (Bedrock prefix)    → claude-opus-4-8
//   us.anthropic.claude-opus-4-8-v1:0      (Bedrock region+ver)→ claude-opus-4-8
//   claude-opus-4-8@20260101               (Vertex @version)   → claude-opus-4-8
//   claude-opus-4-8                        (direct)            → claude-opus-4-8 (unchanged)
function canonicalizeAnthropicModel(model: string): string {
  // Strip a Bedrock region prefix (`us.`, `eu.`, `apac.`) and the `anthropic.`
  // provider prefix, a Bedrock version suffix (`-v1:0`, `:0`), and a Vertex
  // `@version` suffix, then look for a known canonical id as a substring.
  const stripped = model
    .replace(/^(us|eu|apac|global)\./, '')
    .replace(/^anthropic[./]/, '')
    .replace(/@[\w-]+$/, '') // Vertex @version
    .replace(/-v\d+:\d+$/, '') // Bedrock -vN:M
    .replace(/:\d+$/, '') // Bedrock :M
    .replace(/-\d{8}$/, ''); // dated id suffix, e.g. claude-haiku-4-5-20251001 → claude-haiku-4-5

  for (const canonical of CANONICAL_ANTHROPIC_MODELS) {
    if (stripped === canonical) return canonical;
  }
  // Also tolerate gateway dotted forms like `claude-3.5-sonnet` only when they
  // exactly match a canonical id after removing dots — none of our current
  // canonical ids contain dots, so this is a no-op today but keeps the contract
  // explicit: we never *guess* a family, we only fold exact aliases.
  return stripped;
}

const defaultCostModel: CostModel = {
  normalizeModelId(provider, model) {
    const p = provider.trim().toLowerCase();
    // Local providers: collapse any model onto the wildcard zero-cost key.
    if (p === 'ollama' || p === 'local') {
      return { provider: p, model: '*' };
    }
    // Anthropic-direct, Bedrock, and Vertex: canonicalize the *model id* (strip
    // Bedrock region/version suffixes, Vertex `@version`, the `anthropic.` prefix)
    // but PRESERVE the original provider. Only `anthropic` is in PRICE_MAP, so a
    // bedrock/vertex pair resolves to `null` (cost unknown) — we never price a
    // non-direct provider at Anthropic-direct rates.
    if (p === 'anthropic' || p === 'bedrock' || p === 'vertex') {
      return { provider: p, model: canonicalizeAnthropicModel(model) };
    }
    // Gateway providers: an embedded `anthropic/<model>` form (e.g. LiteLLM /
    // OpenRouter exposing an Anthropic model) has its model id canonicalized (the
    // `anthropic/` prefix is a display alias, not a billing provider), but the
    // gateway provider is PRESERVED — so it too resolves to `null` (Anthropic-via-
    // gateway pricing differs from direct, and we never guess it). A non-Anthropic
    // embedded namespace (`meta-llama/llama-3-70b`) is left fully untouched.
    const anthropicGateway = /^anthropic\/(.+)$/.exec(model);
    if (anthropicGateway?.[1] !== undefined) {
      return { provider: p, model: canonicalizeAnthropicModel(anthropicGateway[1]) };
    }
    return { provider: p, model };
  },

  costFor({ provider, model, usage }) {
    const key = this.normalizeModelId(provider, model);
    const price = PRICE_MAP[`${key.provider}/${key.model}`];
    if (price === undefined) return null; // unknown (provider, model) — never guess

    const tokenCost =
      (usage.inputTokens ?? 0) * price.input +
      (usage.outputTokens ?? 0) * price.output +
      (usage.cacheWrite1hTokens ?? 0) * price.cacheWrite1h +
      (usage.cacheWrite5mTokens ?? 0) * price.cacheWrite5m +
      (usage.cacheReadTokens ?? 0) * price.cacheRead;

    // Token prices are per MILLION tokens; divide once at the end.
    const tokenUsd = (tokenCost / 1_000_000) * serviceTierMultiplier(usage.serviceTier);

    // Web-search is billed per request, not per token, and not tier-scaled.
    const webSearchUsd = (usage.webSearchRequests ?? 0) * price.webSearch;

    return tokenUsd + webSearchUsd;
  },
};

export { defaultCostModel };
