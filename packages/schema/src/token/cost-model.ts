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
import type { ModelPlatform } from '../model/providers.ts';
import { hostingFor } from '../model/providers.ts';
import { resolveModel } from '../model/resolve.ts';
import type { CostUsage } from './cost-usage.ts';

export type { CostUsage };

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
 * The provider strings the capture path actually stores, mapped onto catalog
 * platforms.
 *
 * The two vocabularies are NOT spelled alike and must not be assumed to be:
 * the resolvers record `'google'` where the catalog's first-party Google
 * platform is `'google-ai'`, and `'gateway'` names no single platform at all.
 * A provider with no entry here resolves to no platform, so its cost is
 * unknown rather than priced against a lookalike.
 *
 * A plain Map rather than a schema parse: this runs once per priced leaf on the
 * read path, and a lookup allocates nothing where a parse allocates a result
 * object and, on the miss path, an issue array.
 */
const PROVIDER_PLATFORM: ReadonlyMap<string, ModelPlatform> = new Map([
  ['anthropic', 'anthropic'],
  ['openai', 'openai'],
  // The resolvers' spelling for Google's first-party API.
  ['google', 'google-ai'],
  ['google-ai', 'google-ai'],
  ['bedrock', 'bedrock'],
  ['vertex', 'vertex'],
  ['azure', 'azure'],
  ['foundry', 'foundry'],
  ['mistral', 'mistral'],
  ['deepseek', 'deepseek'],
  ['xai', 'xai'],
  ['cohere', 'cohere'],
  ['together', 'together'],
  ['fireworks', 'fireworks'],
  ['groq', 'groq'],
  ['openrouter', 'openrouter'],
  ['ollama', 'ollama'],
  ['local', 'local'],
]);

/**
 * Providers deliberately carried as unpriceable rather than mapped.
 *
 * `gateway` names a class of hosts, not one of them, so it cannot select a
 * price; `unknown` is the resolver's own miss. Listed explicitly so a test can
 * assert every stored provider is either mapped or knowingly here, and a
 * resolver inventing a fourth spelling is caught rather than silently unpriced.
 */
export const UNPRICEABLE_PROVIDERS: readonly string[] = Object.freeze([
  'gateway',
  'unknown',
  'cli',
  'api',
]);

/**
 * The catalog platform a stored provider string names, or `null`.
 *
 * Exported so a test can assert that every provider the resolvers can record
 * is either mapped here or listed in `UNPRICEABLE_PROVIDERS` — the seam that
 * decides whether any of the catalog's prices are reachable at all.
 */
export function platformForProvider(provider: string): ModelPlatform | null {
  return PROVIDER_PLATFORM.get(provider.trim().toLowerCase()) ?? null;
}

/**
 * True when a provider runs on the caller's own hardware.
 *
 * Asks `providers.ts` rather than matching literals, so the platform → hosting
 * band table stays the one place that decides this. A third local platform
 * added there is local here too, instead of the builder and the cost model
 * disagreeing with no test able to see it.
 */
function isLocalProvider(provider: string): boolean {
  const platform = platformForProvider(provider);
  return platform !== null && hostingFor(platform) === 'local';
}

/**
 * The price for a `(provider, model)` pair, or `null` when the catalog carries
 * no verified rate for that platform.
 *
 * When the model ID ITSELF names a platform, that wins over the provider
 * string. A Bedrock-shaped id (`us.anthropic.claude-opus-5`) says where the
 * call was served no matter what the session's provider snapshot claims, and
 * pricing it at Anthropic-direct rates because the snapshot said `'anthropic'`
 * is the substitution this module exists to prevent — the one Bedrock pair
 * anyone has checked bills at 2x first-party.
 */
function priceFor(provider: string, model: string): ModelPrice | null {
  if (isLocalProvider(provider)) return ZERO_PRICE;

  const resolved = resolveModel(model, MODEL_INDEX);
  if (resolved.entry === null) return null;

  const platform = resolved.platform ?? platformForProvider(provider);
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
