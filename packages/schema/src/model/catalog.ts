// The model catalog. One declaration per model; vendor defaults supply the rest.
//
// Curation rules, in force for every entry below:
//
//   - A field is stated only when it was read from the vendor's own published
//     documentation. Anything unread is omitted, which resolves to `null`
//     (unknown) rather than to a plausible-looking value.
//   - `price` is the vendor's FIRST-PARTY rate. Platforms listed in `on` carry
//     no price unless that platform's own rate was read.
//   - `ctx` is omitted rather than guessed. A wrong context window is read by
//     capacity and data-exposure reviews as though it were checked.
//
// Prices are USD per million tokens and are a REFERENCE snapshot, not billing.
// Re-verify against the cited page when updating.
import type { ModelEntry } from './builder.ts';
import { vendor } from './builder.ts';
import type { VendorTrainingPolicy } from './governance.ts';
import type { ModelPrice } from './pricing.ts';
import { anthropicBand, anthropicPrice, scaledBand, tokenPrice } from './pricing.ts';
import { buildModelIndex } from './resolve.ts';

// ─── Anthropic ───────────────────────────────────────────────────────────────
// Prices: the "Model pricing" table at platform.claude.com/docs/en/about-claude/pricing.
// Context: platform.claude.com/docs/en/models/overview. Cache reads are 0.1x
// input except Fable 5.1 and Mythos 5.1 (0.025x) and Opus 5.5 / Sonnet 5.5 (0.05x).
// Mythos 5 and 5.1 are on the pricing page at Fable's rates but are not declared:
// they are limited-availability models whose API ids were not published there.
// Training: privacy.claude.com — commercial products are not used for training
// by default; consumer tiers are opt-IN ("Model Improvement"), not opt-out.

const ANTHROPIC_TRAINING: VendorTrainingPolicy = {
  apiDefault: 'no',
  consumerDefault: 'no',
  consumerControl: 'opt-in',
  source: 'https://privacy.claude.com/en/articles/7996868-is-my-data-used-for-model-training',
};

const anthropic = vendor('anthropic', {
  family: { id: 'claude', name: 'Claude' },
  region: 'us',
  retention: 'zero_retention',
  training: ANTHROPIC_TRAINING,
});

const CLAUDE_RESELLERS = ['bedrock', 'vertex', 'foundry'] as const;

anthropic.model('claude-fable-5-1', {
  name: 'Claude Fable 5.1',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(10, 50, 0.25),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-fable-5', {
  name: 'Claude Fable 5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(10, 50, 1),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-5-5', {
  name: 'Claude Opus 5.5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(4, 20, 0.2),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-5', {
  name: 'Claude Opus 5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-8', {
  name: 'Claude Opus 4.8',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-7', {
  name: 'Claude Opus 4.7',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-6', {
  name: 'Claude Opus 4.6',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-5', {
  name: 'Claude Opus 4.5',
  ctx: 200_000,
  maxOut: 64_000,
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-1', {
  name: 'Claude Opus 4.1',
  capability: 'reasoning',
  price: anthropicPrice(15, 75, 1.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-sonnet-5-5', {
  name: 'Claude Sonnet 5.5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(2, 10, 0.1),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-sonnet-5', {
  name: 'Claude Sonnet 5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(2, 10, 0.2),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-sonnet-4-6', {
  name: 'Claude Sonnet 4.6',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: anthropicPrice(3, 15, 0.3),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-sonnet-4-5', {
  name: 'Claude Sonnet 4.5',
  ctx: 200_000,
  maxOut: 64_000,
  capability: 'reasoning',
  price: anthropicPrice(3, 15, 0.3),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-haiku-5-5', {
  name: 'Claude Haiku 5.5',
  ctx: 1_000_000,
  maxOut: 128_000,
  capability: null,
  // A prompt over 100,000 tokens, cache reads and writes included, bills the
  // whole request at the higher band.
  price: anthropicPrice(0.1, 0.5, 0.01, anthropicBand(100_000, 0.5, 2.5, 0.05)),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-haiku-4-5', {
  name: 'Claude Haiku 4.5',
  ctx: 200_000,
  maxOut: 64_000,
  // Reviewed: fast/cheap general-purpose tier, not a reasoning or code model.
  capability: null,
  price: anthropicPrice(1, 5, 0.1),
  // The vendor documents `claude-haiku-4-5-20251001` as the versioned id and
  // `claude-haiku-4-5` as its alias; both are reported in the wild.
  aliases: ['claude-haiku-4-5-20251001'],
  on: [...CLAUDE_RESELLERS],
});

// Retired but still reported. The pricing page no longer lists it, so its rate
// is unknown — which reads as $0 spend, flagged estimated, rather than as a
// wrong figure.
anthropic.model('claude-sonnet-3-7', {
  name: 'Claude Sonnet 3.7',
  on: [...CLAUDE_RESELLERS],
});

// ─── OpenAI ──────────────────────────────────────────────────────────────────
// Prices: developers.openai.com/api/docs/pricing. Context windows:
// developers.openai.com/api/docs/models.
// Above 272,000 input tokens the whole request bills at 2x input and cache
// reads and 1.5x output, on the models that window covers.
// GPT-5.6 and GPT-6 also publish a cache-WRITE rate; `ModelPrice` carries cache
// writes only in Anthropic's 5m/1h shape, so it is not modelled, and a write
// reported inside input tokens is billed at the input rate.
// Training: the API is not used for training by default (opt-in); ChatGPT
// consumer tiers are on by default with an opt-out under Data Controls.

const OPENAI_TRAINING: VendorTrainingPolicy = {
  apiDefault: 'no',
  consumerDefault: 'yes',
  consumerControl: 'opt-out',
  source: 'https://developers.openai.com/api/docs/guides/your-data',
};

/** A GPT price whose window crosses the 272K long-context threshold. */
function gptPrice(input: number, output: number, cacheRead?: number): ModelPrice {
  const base = { input, output, ...(cacheRead === undefined ? {} : { cacheRead }) };
  return tokenPrice(input, output, {
    ...base,
    longContext: scaledBand(272_000, base, { input: 2, output: 1.5, cacheRead: 2 }),
  });
}

const openai = vendor('openai', {
  family: { id: 'gpt', name: 'GPT' },
  region: 'us',
  retention: 'configurable',
  training: OPENAI_TRAINING,
});

const OPENAI_RESELLERS = ['azure', 'foundry'] as const;

openai.model('gpt-6-astra', {
  name: 'GPT-6 Astra',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(10, 50, 1),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-6.1-sol', {
  name: 'GPT-6.1 Sol',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(2, 10, 0.1),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-6-sol', {
  name: 'GPT-6 Sol',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(2, 10, 0.2),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-6-luna', {
  name: 'GPT-6 Luna',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: null,
  price: gptPrice(0.1, 0.5, 0.01),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.6-sol', {
  name: 'GPT-5.6 Sol',
  // Promotional rate, published as available at least through 2026-11-21.
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(4, 20, 0.4),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.6-terra', {
  name: 'GPT-5.6 Terra',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(2, 12, 0.2),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.6-luna', {
  name: 'GPT-5.6 Luna',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: null,
  price: gptPrice(0.2, 1.2, 0.02),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.5', {
  name: 'GPT-5.5',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(5, 30, 0.5),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.5-pro', {
  name: 'GPT-5.5 Pro',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(30, 180),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.4', {
  name: 'GPT-5.4',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: gptPrice(2.5, 15, 0.25),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.4-mini', {
  name: 'GPT-5.4 mini',
  ctx: 400_000,
  maxOut: 128_000,
  capability: null,
  price: tokenPrice(0.75, 4.5, { cacheRead: 0.075 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.4-nano', {
  name: 'GPT-5.4 nano',
  ctx: 400_000,
  maxOut: 128_000,
  capability: null,
  price: tokenPrice(0.2, 1.25, { cacheRead: 0.02 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.3-codex', {
  name: 'GPT-5.3 Codex',
  ctx: 400_000,
  maxOut: 128_000,
  capability: 'code',
  price: tokenPrice(1.75, 14, { cacheRead: 0.175 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.1', {
  name: 'GPT-5.1',
  ctx: 400_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(1.25, 10, { cacheRead: 0.125 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5', {
  name: 'GPT-5',
  ctx: 400_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(1.25, 10, { cacheRead: 0.125 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5-mini', {
  name: 'GPT-5 mini',
  ctx: 400_000,
  maxOut: 128_000,
  capability: null,
  price: tokenPrice(0.25, 2, { cacheRead: 0.025 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5-nano', {
  name: 'GPT-5 nano',
  ctx: 400_000,
  maxOut: 128_000,
  capability: null,
  price: tokenPrice(0.05, 0.4, { cacheRead: 0.005 }),
  on: [...OPENAI_RESELLERS],
});

// Prior-generation OpenAI models still reported by deployments. Kept so they
// resolve to a real vendor rather than the Unknown fallback.
openai.model('gpt-4.1', {
  name: 'GPT-4.1',
  ctx: 1_047_576,
  maxOut: 32_768,
  price: tokenPrice(2, 8, { cacheRead: 0.5 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-4o', {
  name: 'GPT-4o',
  ctx: 128_000,
  maxOut: 16_384,
  price: tokenPrice(2.5, 10, { cacheRead: 1.25 }),
  on: [...OPENAI_RESELLERS],
});

// The original GPT-4o snapshot is priced separately from `gpt-4o`, so it is its
// own entry rather than a dated spelling of it. The other dated snapshots
// (`gpt-4o-2024-08-06`, `gpt-4o-2024-11-20`) resolve to `gpt-4o` by the
// resolver's dated-suffix strip.
openai.model('gpt-4o-2024-05-13', {
  name: 'GPT-4o (2024-05-13)',
  price: tokenPrice(5, 15),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-4o-mini', {
  name: 'GPT-4o mini',
  price: tokenPrice(0.15, 0.6, { cacheRead: 0.075 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-4-turbo', {
  name: 'GPT-4 Turbo',
  // A legacy model reached by traffic, never deliberately onboarded.
  seen: 'discovered',
  price: tokenPrice(10, 30),
  aliases: ['gpt-4-turbo-2024-04-09'],
  on: [...OPENAI_RESELLERS],
});

openai.model('o3', {
  name: 'o3',
  ctx: 200_000,
  maxOut: 100_000,
  capability: 'reasoning',
  price: tokenPrice(2, 8, { cacheRead: 0.5 }),
  on: [...OPENAI_RESELLERS],
});

// Embedding models. The pricing page lists an input rate only: an embedding
// call returns vectors, not generated tokens, so output is priced at zero.
openai.model('text-embedding-3-small', {
  name: 'text-embedding-3-small',
  capability: 'embedding',
  price: tokenPrice(0.02, 0),
  on: [...OPENAI_RESELLERS],
});

openai.model('text-embedding-3-large', {
  name: 'text-embedding-3-large',
  capability: 'embedding',
  price: tokenPrice(0.13, 0),
  on: [...OPENAI_RESELLERS],
});

openai.model('text-embedding-ada-002', {
  name: 'text-embedding-ada-002',
  capability: 'embedding',
  price: tokenPrice(0.1, 0),
  on: [...OPENAI_RESELLERS],
});

// Open-weight OpenAI models, served only by third parties.
openai.model('gpt-oss-120b', {
  name: 'GPT-OSS 120B',
  openWeights: true,
  // Published weights; OpenAI's own API does not serve them.
  firstParty: false,
  retention: 'unknown',
  defaultHosting: 'local',
  on: ['together', 'fireworks', 'groq', 'openrouter', 'bedrock', 'ollama', 'local'],
});

openai.model('gpt-oss-20b', {
  name: 'GPT-OSS 20B',
  openWeights: true,
  // Published weights; OpenAI's own API does not serve them.
  firstParty: false,
  retention: 'unknown',
  defaultHosting: 'local',
  on: ['together', 'fireworks', 'groq', 'openrouter', 'ollama', 'local'],
});

// ─── Google ──────────────────────────────────────────────────────────────────
// Prices: ai.google.dev/gemini-api/docs/pricing. Context windows: the
// per-model pages under ai.google.dev/gemini-api/docs/models.
// Rates below are the TEXT input rate. Several models price audio, image or
// video input higher, and the usage bag carries no modality, so non-text input
// is under-reported.
// The 3.6 and 3.8 Flash rates are introductory through 2026-12-31; from
// 2027-01-01 they are 1.50 input, 7.50 output and 0.15 cache read.
// Training: the paid tier is not used to improve products; the free tier is.
// The only way off the free tier's default is to move to the paid tier.

const GOOGLE_TRAINING: VendorTrainingPolicy = {
  apiDefault: 'no',
  consumerDefault: 'yes',
  consumerControl: 'none',
  source: 'https://ai.google.dev/gemini-api/terms',
};

const google = vendor('google', {
  family: { id: 'gemini', name: 'Gemini' },
  region: 'us',
  retention: 'configurable',
  training: GOOGLE_TRAINING,
});

google.model('gemini-3.8-flash', {
  name: 'Gemini 3.8 Flash',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.75, 3.75, { cacheRead: 0.075 }),
  on: ['vertex'],
});

// Deprecated and off the pricing page; requests are routed to Gemini 3.8 Flash.
// The rate is the introductory one the changelog published for this model
// through 2026-12-31; its cache-read rate was not published.
google.model('gemini-3.7-flash', {
  name: 'Gemini 3.7 Flash',
  capability: null,
  price: tokenPrice(0.75, 3.75),
  on: ['vertex'],
});

google.model('gemini-3.6-flash', {
  name: 'Gemini 3.6 Flash',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.75, 3.75, { cacheRead: 0.075 }),
  on: ['vertex'],
});

// Deprecated and off the pricing page; requests are routed to Gemini 3.6 Flash.
// No current rate is published for this id, so its price is unknown.
google.model('gemini-3.5-flash', {
  name: 'Gemini 3.5 Flash',
  capability: null,
  on: ['vertex'],
});

google.model('gemini-3.5-flash-lite', {
  name: 'Gemini 3.5 Flash Lite',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.3, 2.5, { cacheRead: 0.03 }),
  on: ['vertex'],
});

google.model('gemini-3.1-flash-lite', {
  name: 'Gemini 3.1 Flash Lite',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.25, 1.5, { cacheRead: 0.025 }),
  on: ['vertex'],
});

google.model('gemini-3-flash-preview', {
  name: 'Gemini 3 Flash Preview',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.5, 3, { cacheRead: 0.05 }),
  on: ['vertex'],
});

google.model('gemini-3.1-pro-preview', {
  name: 'Gemini 3.1 Pro Preview',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: 'reasoning',
  price: tokenPrice(2, 12, {
    cacheRead: 0.2,
    longContext: { thresholdInputTokens: 200_000, input: 4, output: 18, cacheRead: 0.4 },
  }),
  aliases: ['gemini-3.1-pro-preview-customtools'],
  on: ['vertex'],
});

google.model('gemini-2.5-pro', {
  name: 'Gemini 2.5 Pro',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: 'reasoning',
  price: tokenPrice(1.25, 10, {
    cacheRead: 0.125,
    longContext: { thresholdInputTokens: 200_000, input: 2.5, output: 15, cacheRead: 0.25 },
  }),
  on: ['vertex'],
});

google.model('gemini-2.5-flash', {
  name: 'Gemini 2.5 Flash',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.3, 2.5, { cacheRead: 0.03 }),
  on: ['vertex'],
});

google.model('gemini-2.5-flash-lite', {
  name: 'Gemini 2.5 Flash Lite',
  ctx: 1_048_576,
  maxOut: 65_536,
  capability: null,
  price: tokenPrice(0.1, 0.4, { cacheRead: 0.01 }),
  on: ['vertex'],
});

// Text input rate; an embedding call generates no output tokens.
google.model('gemini-embedding-2', {
  name: 'Gemini Embedding 2',
  capability: 'embedding',
  price: tokenPrice(0.2, 0),
  on: ['vertex'],
});

// Off Google's current pricing page; identity resolves, rate is unknown.
google.model('gemini-1-5-pro', { name: 'Gemini 1.5 Pro', on: ['vertex'] });
google.model('gemini-1-5-flash', { name: 'Gemini 1.5 Flash', on: ['vertex'] });

// ─── xAI ─────────────────────────────────────────────────────────────────────
// Prices + context: docs.x.ai/docs/models. Every text model tiers at 200K input,
// cache reads included, and bills the whole request at the higher band.
// Training: docs.x.ai/developers/faq/security — API inputs and outputs are not
// trained on without explicit permission. The consumer tier default is not
// published and is recorded as unknown.

const xai = vendor('xai', {
  family: { id: 'grok', name: 'Grok' },
  region: 'us',
  retention: 'configurable',
  training: {
    apiDefault: 'no',
    consumerDefault: 'unknown',
    consumerControl: 'unknown',
    source: 'https://docs.x.ai/developers/faq/security',
  },
});

/** A Grok price: above 200K the whole request bills at 2x every column. */
function grokPrice(input: number, output: number, cacheRead: number): ModelPrice {
  const base = { input, output, cacheRead };
  return tokenPrice(input, output, {
    cacheRead,
    longContext: scaledBand(200_000, base, { input: 2, output: 2, cacheRead: 2 }),
  });
}

xai.model('grok-4.7', {
  name: 'Grok 4.7',
  ctx: 500_000,
  capability: 'reasoning',
  price: grokPrice(2, 6, 0.5),
});

xai.model('grok-4.6', {
  name: 'Grok 4.6',
  ctx: 500_000,
  capability: 'reasoning',
  price: grokPrice(2, 6, 0.5),
  on: ['bedrock'],
});

xai.model('grok-4.5', {
  name: 'Grok 4.5',
  ctx: 500_000,
  capability: 'reasoning',
  price: grokPrice(2, 6, 0.3),
});

xai.model('grok-4.3', {
  name: 'Grok 4.3',
  ctx: 1_000_000,
  capability: 'reasoning',
  price: grokPrice(1.25, 2.5, 0.2),
  on: ['bedrock'],
});

xai.model('grok-4.20-0309-reasoning', {
  name: 'Grok 4.20 Reasoning',
  capability: 'reasoning',
  ctx: 1_000_000,
  price: grokPrice(1.25, 2.5, 0.2),
});

xai.model('grok-4.20-0309-non-reasoning', {
  name: 'Grok 4.20',
  capability: null,
  ctx: 1_000_000,
  price: grokPrice(1.25, 2.5, 0.2),
});

xai.model('grok-4.20-multi-agent-0309', {
  name: 'Grok 4.20 Multi-Agent',
  capability: 'reasoning',
  ctx: 1_000_000,
  price: grokPrice(1.25, 2.5, 0.2),
});

xai.model('grok-build-0.1', {
  name: 'Grok Build 0.1',
  ctx: 256_000,
  capability: 'code',
  price: grokPrice(1, 2, 0.2),
});

// ─── DeepSeek ────────────────────────────────────────────────────────────────
// Prices + context: api-docs.deepseek.com/quick_start/pricing. Rates below are
// the PEAK band; off-peak (outside 01:00-04:00 and 06:00-10:00 UTC, Mon-Fri) is
// half. The price shape carries no time-of-day axis, so the peak rate is stated
// and an off-peak call costs less than reported.
// Training: the privacy policy states data is used to train and improve models,
// with an opt-out right. Data is processed and stored in the PRC.

const deepseek = vendor('deepseek', {
  family: { id: 'deepseek', name: 'DeepSeek' },
  region: 'cn',
  retention: 'configurable',
  training: {
    apiDefault: 'yes',
    consumerDefault: 'yes',
    consumerControl: 'opt-out',
    source: 'https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html',
  },
});

deepseek.model('deepseek-flash', {
  name: 'DeepSeek V4.1 Flash',
  ctx: 1_000_000,
  maxOut: 384_000,
  capability: null,
  price: tokenPrice(0.3, 1.2, { cacheRead: 0.006 }),
});

// Retired on DeepSeek's API: the id is still accepted, served by V4.1 Flash and
// billed at its rate. Third-party hosts serve the V4 weights under this id.
deepseek.model('deepseek-v4-flash', {
  name: 'DeepSeek V4 Flash',
  ctx: 1_000_000,
  maxOut: 384_000,
  capability: null,
  price: tokenPrice(0.3, 1.2, { cacheRead: 0.006 }),
  on: ['bedrock', 'together', 'fireworks', 'openrouter', 'ollama', 'local'],
});

deepseek.model('deepseek-v4-pro', {
  name: 'DeepSeek V4 Pro',
  ctx: 1_000_000,
  maxOut: 384_000,
  capability: 'reasoning',
  price: tokenPrice(1.32, 3.96, { cacheRead: 0.044 }),
  on: ['bedrock', 'together', 'fireworks', 'openrouter'],
});

// Off DeepSeek's current pricing page; served on third-party hosts.
deepseek.model('deepseek-r1', {
  name: 'DeepSeek R1',
  seen: 'discovered',
  capability: 'reasoning',
  openWeights: true,
  defaultHosting: 'local',
  on: ['bedrock', 'together', 'fireworks', 'openrouter', 'ollama', 'local'],
});

// ─── Cohere ──────────────────────────────────────────────────────────────────
// Context windows: docs.cohere.com/docs/models. Current-generation prices are
// not published (the reasoning tier is sales-priced), so they are unknown.
// Training: cohere.com/security documents an opt-out; the default is not stated.

const cohere = vendor('cohere', {
  family: { id: 'command', name: 'Command' },
  region: 'us',
  retention: 'configurable',
  training: {
    apiDefault: 'unknown',
    consumerDefault: 'unknown',
    consumerControl: 'opt-out',
    source: 'https://cohere.com/security',
  },
});

cohere.model('command-a-plus-05-2026', {
  name: 'Command A+',
  ctx: 128_000,
  maxOut: 64_000,
  on: ['bedrock'],
});

cohere.model('command-a-03-2025', {
  name: 'Command A',
  ctx: 256_000,
  maxOut: 8_000,
  on: ['bedrock'],
});

cohere.model('command-a-reasoning-08-2025', {
  name: 'Command A Reasoning',
  ctx: 256_000,
  maxOut: 32_000,
  capability: 'reasoning',
});

cohere.model('command-r-plus-08-2024', {
  name: 'Command R+',
  ctx: 128_000,
  maxOut: 4_000,
  price: tokenPrice(2.5, 10),
  on: ['bedrock'],
});

// Retired; the undated `command-r-plus` alias named this snapshot, not 08-2024.
cohere.model('command-r-plus-04-2024', {
  name: 'Command R+ (04-2024)',
  seen: 'discovered',
  ctx: 128_000,
  maxOut: 4_000,
  price: tokenPrice(3, 15),
  aliases: ['command-r-plus'],
  on: ['bedrock'],
});

// ─── Open-weight vendors ─────────────────────────────────────────────────────
// Meta and Alibaba publish weights without running a first-party inference API,
// so every offering is a third-party host or self-hosted. Host rates vary and
// are not carried; a self-hosted run is a known zero.

const meta = vendor('meta', {
  family: { id: 'llama', name: 'Llama' },
  openWeights: true,
  retention: 'unknown',
  // Curated: an id like `llama-3-1-70b` names no platform, and these weights
  // are most often run on the caller's own hardware in this context.
  defaultHosting: 'local',
});

const OPEN_WEIGHT_HOSTS = [
  'bedrock',
  'together',
  'fireworks',
  'groq',
  'openrouter',
  'ollama',
  'local',
] as const;

meta.model('llama-3-3-70b', {
  name: 'Llama 3.3 70B',
  ctx: 128_000,
  on: [...OPEN_WEIGHT_HOSTS],
});

meta.model('llama-3-1-70b', {
  name: 'Llama 3.1 70B',
  ctx: 128_000,
  on: [...OPEN_WEIGHT_HOSTS],
});

meta.model('llama-3-1-8b', {
  name: 'Llama 3.1 8B',
  ctx: 128_000,
  on: [...OPEN_WEIGHT_HOSTS],
});

const alibaba = vendor('alibaba', {
  family: { id: 'qwen', name: 'Qwen' },
  openWeights: true,
  retention: 'unknown',
  defaultHosting: 'local',
});

alibaba.model('qwen-3-235b', {
  name: 'Qwen 3 235B',
  on: [...OPEN_WEIGHT_HOSTS],
});

alibaba.model('qwen-3-coder-480b', {
  name: 'Qwen 3 Coder 480B',
  capability: 'code',
  on: [...OPEN_WEIGHT_HOSTS],
});

// Amazon serves Nova only through its own cloud, so it has no first-party
// platform entry. Bedrock pricing is JS-rendered and was not readable.
const amazon = vendor('amazon', {
  family: { id: 'nova', name: 'Nova' },
  retention: 'configurable',
});

amazon.model('nova-2-lite', {
  name: 'Nova 2 Lite',
  ctx: 1_000_000,
  maxOut: 64_000,
  aliases: ['nova-2-lite-v1:0'],
  on: ['bedrock'],
});

const mistral = vendor('mistral', {
  family: { id: 'mistral', name: 'Mistral' },
  openWeights: true,
  retention: 'unknown',
  defaultHosting: 'local',
});

// Prices: docs.mistral.ai/inference/pricing. Ids and context windows: the
// per-model pages under docs.mistral.ai/models. Max output is not published.
// The models below are served by Mistral's own API, so they take its hosting
// band rather than the vendor's self-hosted default.
const MISTRAL_API = { defaultHosting: 'api' } as const;

mistral.model('mistral-large-4', {
  ...MISTRAL_API,
  name: 'Mistral Large 4',
  ctx: 1_000_000,
  capability: null,
  // Public preview at a sale rate; the published original is 1.36 / 4.18 / 0.14.
  price: tokenPrice(0.68, 2.09, { cacheRead: 0.07 }),
});

mistral.model('mistral-large-2512', {
  ...MISTRAL_API,
  name: 'Mistral Large 3',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(0.5, 1.5, { cacheRead: 0.05 }),
});

mistral.model('mistral-medium-3-5', {
  ...MISTRAL_API,
  name: 'Mistral Medium 3.5',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(1.5, 7.5, { cacheRead: 0.15 }),
});

mistral.model('mistral-small-2603', {
  ...MISTRAL_API,
  name: 'Mistral Small 4',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(0.15, 0.6, { cacheRead: 0.015 }),
});

mistral.model('ministral-14b-2512', {
  ...MISTRAL_API,
  name: 'Ministral 3 14B',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(0.2, 0.2, { cacheRead: 0.02 }),
});

mistral.model('ministral-8b-2512', {
  ...MISTRAL_API,
  name: 'Ministral 3 8B',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(0.15, 0.15, { cacheRead: 0.015 }),
});

mistral.model('ministral-3b-2512', {
  ...MISTRAL_API,
  name: 'Ministral 3 3B',
  ctx: 256_000,
  capability: null,
  price: tokenPrice(0.1, 0.1, { cacheRead: 0.01 }),
});

mistral.model('codestral-2508', {
  ...MISTRAL_API,
  name: 'Codestral',
  ctx: 128_000,
  capability: 'code',
  openWeights: false,
  price: tokenPrice(0.3, 0.9, { cacheRead: 0.03 }),
});

// Absent from Mistral's current model list; survives on third-party hosts.
mistral.model('mixtral-8x7b', {
  name: 'Mixtral 8x7B',
  seen: 'discovered',
  on: [...OPEN_WEIGHT_HOSTS],
});

/** Every declared model, in vendor order. */
export const MODEL_ENTRIES: readonly ModelEntry[] = Object.freeze([
  ...anthropic.models(),
  ...openai.models(),
  ...google.models(),
  ...xai.models(),
  ...deepseek.models(),
  ...cohere.models(),
  ...mistral.models(),
  ...meta.models(),
  ...alibaba.models(),
  ...amazon.models(),
]);

/**
 * Every distinct long-context threshold any declared price carries, ascending.
 * A read that sums several requests before pricing them groups by which of
 * these each request's prompt crossed, so a sum never decides a band.
 */
export const LONG_CONTEXT_THRESHOLDS: readonly number[] = Object.freeze(
  [
    ...new Set(
      MODEL_ENTRIES.flatMap((entry) =>
        [...entry.platforms.values()].flatMap((offering) =>
          offering.price?.longContext ? [offering.price.longContext.thresholdInputTokens] : [],
        ),
      ),
    ),
  ].sort((a, b) => a - b),
);

/** The lookup index over `MODEL_ENTRIES`, keyed by canonical id and alias. */
export const MODEL_INDEX = buildModelIndex(MODEL_ENTRIES);
