// Model provenance vocabulary — WHO made a model (`ModelVendor`) versus WHICH
// endpoint served the call (`ModelPlatform`). These are two independent axes.
// A model's identity travels across platforms: Claude Opus 5 is an Anthropic
// model whether it arrives via the Anthropic API, AWS Bedrock or Google Vertex,
// with the same weights and the same context window. Its PRICE and its
// RETENTION posture do not travel — both are properties of the serving
// contract. `pricing.ts` holds that separation.
//
// Pure data + pure functions: no I/O, no `process.env`, no `fetch`, no Node-API
// deps, no Drizzle — this module sits on the emitted import graph from the
// package entry (see `test/entry-graph.test.ts`).
import { z } from 'zod';

/**
 * The organisation that trained the model. `unknown` is the honest answer for a
 * model string we do not recognise — never a guess, and never silently folded
 * onto a lookalike vendor.
 */
export const ModelVendor = z.enum([
  'anthropic',
  'openai',
  'google',
  'meta',
  'mistral',
  'deepseek',
  'alibaba',
  'xai',
  'amazon',
  'cohere',
  'unknown',
]);
export type ModelVendor = z.infer<typeof ModelVendor>;

/**
 * The endpoint that actually served the call. Split into four bands because
 * each band has different pricing, different data-retention terms, and a
 * different id spelling for the same weights:
 *
 *   - first-party: the vendor's own API. Prices and retention terms are the
 *     vendor's published ones.
 *   - cloud resellers: the model runs under the cloud provider's contract.
 *     Prices differ from first-party (verified: Bedrock billed Claude 3.5
 *     Sonnet v2 at $6/$30 against Anthropic's own $3/$15 — 2x), and retention
 *     is governed by the customer's AWS/GCP/Azure agreement, not the vendor's.
 *   - open-weight hosts: third parties serving open weights at their own rates.
 *   - self-hosted: the weights run on the customer's own hardware. No vendor
 *     billing relationship and no vendor data flow, so cost is a known 0 rather
 *     than an unknown.
 */
export const ModelPlatform = z.enum([
  // first-party
  'anthropic',
  'openai',
  'google-ai',
  'mistral',
  'deepseek',
  'xai',
  'cohere',
  // cloud resellers
  'bedrock',
  'vertex',
  'azure',
  'foundry',
  // open-weight hosts
  'together',
  'fireworks',
  'groq',
  'openrouter',
  // self-hosted
  'ollama',
  'local',
]);
export type ModelPlatform = z.infer<typeof ModelPlatform>;

/**
 * How the served model reaches the caller, as rendered on the governance
 * surface. Narrower than `ModelPlatform` on purpose: it answers "does this
 * leave the building, and through whose door", which is the question a
 * data-governance reviewer is actually asking.
 */
export const ModelHosting = z.enum(['api', 'gateway', 'local']);
export type ModelHosting = z.infer<typeof ModelHosting>;

/** Which band each platform belongs to — the source for `hostingFor` below. */
const PLATFORM_HOSTING: ReadonlyMap<ModelPlatform, ModelHosting> = new Map([
  ['anthropic', 'api'],
  ['openai', 'api'],
  ['google-ai', 'api'],
  ['mistral', 'api'],
  ['deepseek', 'api'],
  ['xai', 'api'],
  ['cohere', 'api'],
  ['bedrock', 'api'],
  ['vertex', 'api'],
  ['azure', 'api'],
  ['foundry', 'api'],
  ['together', 'gateway'],
  ['fireworks', 'gateway'],
  ['groq', 'gateway'],
  ['openrouter', 'gateway'],
  ['ollama', 'local'],
  ['local', 'local'],
]);

/** The hosting band a platform serves under. Total over `ModelPlatform`. */
export function hostingFor(platform: ModelPlatform): ModelHosting {
  // `PLATFORM_HOSTING` covers every member of the enum (pinned by a test), so
  // the fallback is unreachable — kept rather than a non-null assertion so a
  // future platform added without a band degrades to the most conservative
  // answer instead of throwing at import time.
  return PLATFORM_HOSTING.get(platform) ?? 'api';
}

/**
 * Whether a platform is the vendor's own first-party endpoint. Load-bearing for
 * pricing and retention: only a first-party platform may inherit the vendor's
 * published rates and its retention posture (see `pricing.ts`).
 */
const FIRST_PARTY: ReadonlyMap<ModelVendor, ModelPlatform> = new Map([
  ['anthropic', 'anthropic'],
  ['openai', 'openai'],
  ['google', 'google-ai'],
  ['mistral', 'mistral'],
  ['deepseek', 'deepseek'],
  ['xai', 'xai'],
  ['cohere', 'cohere'],
]);

/**
 * The vendor's own endpoint, or `null` for a vendor that publishes weights
 * without running a first-party inference API (Meta, Alibaba) or whose models
 * are served only through its cloud (Amazon Nova → Bedrock).
 */
export function firstPartyPlatformFor(vendor: ModelVendor): ModelPlatform | null {
  return FIRST_PARTY.get(vendor) ?? null;
}

/** True when `platform` is `vendor`'s own first-party endpoint. */
export function isFirstParty(vendor: ModelVendor, platform: ModelPlatform): boolean {
  return FIRST_PARTY.get(vendor) === platform;
}

/**
 * Namespace prefixes a platform prepends to a model id. Read-side only: the
 * resolver strips these to recover the canonical id (see `resolve.ts`). We do
 * NOT reconstruct platform ids from the canonical form — the spellings vary by
 * vendor AND by model generation (current Claude on Bedrock is
 * `anthropic.claude-opus-5` with no version suffix, while Nova is
 * `amazon.nova-2-lite-v1:0`), so generating them would be guessing.
 */
export const PLATFORM_NAMESPACES: readonly string[] = Object.freeze([
  'anthropic',
  'amazon',
  'meta',
  'mistral',
  'deepseek',
  'qwen',
  'cohere',
  'ai21',
  'writer',
  'luma',
  'stability',
]);

/**
 * Geographic routing prefixes AWS Bedrock prepends for cross-region and global
 * inference profiles (`us.anthropic.claude-opus-5`, `global.amazon.nova-2-lite-v1:0`).
 *
 * The list is exhaustive over the geo prefixes Bedrock documents. A prefix
 * missing from it makes every id carrying it unresolvable, so the model reads
 * as unknown rather than as itself.
 */
export const GEO_PREFIXES: readonly string[] = Object.freeze([
  'us',
  'eu',
  'apac',
  'au',
  'jp',
  'global',
]);
