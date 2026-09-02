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
import { anthropicPrice, tokenPrice } from './pricing.ts';
import { buildModelIndex } from './resolve.ts';

// ─── Anthropic ───────────────────────────────────────────────────────────────
// Prices + context: platform.claude.com/docs/en/about-claude/pricing and
// platform.claude.com/docs/en/models/overview.
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
  capability: 'reasoning',
  price: anthropicPrice(10, 50, 1),
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
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-7', {
  name: 'Claude Opus 4.7',
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-6', {
  name: 'Claude Opus 4.6',
  capability: 'reasoning',
  price: anthropicPrice(5, 25, 0.5),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-opus-4-5', {
  name: 'Claude Opus 4.5',
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
  capability: 'reasoning',
  price: anthropicPrice(3, 15, 0.3),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-sonnet-4-5', {
  name: 'Claude Sonnet 4.5',
  capability: 'reasoning',
  price: anthropicPrice(3, 15, 0.3),
  on: [...CLAUDE_RESELLERS],
});

anthropic.model('claude-haiku-4-5', {
  name: 'Claude Haiku 4.5',
  ctx: 200_000,
  maxOut: 64_000,
  // Reviewed: fast/cheap tier, no flagged reasoning or code specialisation.
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
// learn.microsoft.com/en-us/azure/ai-foundry/openai/concepts/models.
// Above 272,000 input tokens the long-context rate applies to the WHOLE request;
// that rate is not published on the pricing page, so it is recorded as unknown.
// Training: the API is not used for training by default (opt-in); ChatGPT
// consumer tiers are on by default with an opt-out under Data Controls.

const OPENAI_TRAINING: VendorTrainingPolicy = {
  apiDefault: 'no',
  consumerDefault: 'yes',
  consumerControl: 'opt-out',
  source: 'https://developers.openai.com/api/docs/guides/your-data',
};

const LONG_CONTEXT_272K = { thresholdInputTokens: 272_000, input: null, output: null };

const openai = vendor('openai', {
  family: { id: 'gpt', name: 'GPT' },
  region: 'us',
  retention: 'configurable',
  training: OPENAI_TRAINING,
});

const OPENAI_RESELLERS = ['azure', 'foundry'] as const;

openai.model('gpt-5.6-sol', {
  name: 'GPT-5.6 Sol',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(4, 20, { cacheRead: 0.4, longContext: LONG_CONTEXT_272K }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.6-terra', {
  name: 'GPT-5.6 Terra',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(2, 12, { cacheRead: 0.2, longContext: LONG_CONTEXT_272K }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.6-luna', {
  name: 'GPT-5.6 Luna',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: null,
  price: tokenPrice(0.2, 1.2, { cacheRead: 0.02, longContext: LONG_CONTEXT_272K }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.5', {
  name: 'GPT-5.5',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(5, 30, { cacheRead: 0.5, longContext: LONG_CONTEXT_272K }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-5.4', {
  name: 'GPT-5.4',
  ctx: 1_050_000,
  maxOut: 128_000,
  capability: 'reasoning',
  price: tokenPrice(2.5, 15, { cacheRead: 0.25, longContext: LONG_CONTEXT_272K }),
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
// resolve to a real vendor rather than the Unknown fallback; context windows
// are not on the pricing page and are recorded as unknown.
openai.model('gpt-4.1', {
  name: 'GPT-4.1',
  price: tokenPrice(2, 8, { cacheRead: 0.5 }),
  on: [...OPENAI_RESELLERS],
});

openai.model('gpt-4o', {
  name: 'GPT-4o',
  price: tokenPrice(2.5, 10, { cacheRead: 1.25 }),
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
  capability: 'reasoning',
  price: tokenPrice(2, 8, { cacheRead: 0.5 }),
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
// Prices: ai.google.dev/gemini-api/docs/pricing. Context windows are not
// published on the model-list page and are recorded as unknown.
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

google.model('gemini-3.7-flash', {
  name: 'Gemini 3.7 Flash',
  capability: null,
  // Promotional rate; the published post-promotion rate is 1.50 / 7.50.
  price: tokenPrice(0.75, 3.75),
  on: ['vertex'],
});

google.model('gemini-3.6-flash', {
  name: 'Gemini 3.6 Flash',
  capability: null,
  price: tokenPrice(0.75, 3.75),
  on: ['vertex'],
});

google.model('gemini-3.5-flash', {
  name: 'Gemini 3.5 Flash',
  capability: null,
  price: tokenPrice(1.5, 9),
  on: ['vertex'],
});

google.model('gemini-3.5-flash-lite', {
  name: 'Gemini 3.5 Flash Lite',
  capability: null,
  price: tokenPrice(0.3, 2.5),
  on: ['vertex'],
});

google.model('gemini-3.1-pro-preview', {
  name: 'Gemini 3.1 Pro Preview',
  capability: 'reasoning',
  price: tokenPrice(2, 12, {
    longContext: { thresholdInputTokens: 200_000, input: 4, output: 18 },
  }),
  on: ['vertex'],
});

google.model('gemini-2.5-pro', {
  name: 'Gemini 2.5 Pro',
  capability: 'reasoning',
  price: tokenPrice(1.25, 10, {
    longContext: { thresholdInputTokens: 200_000, input: 2.5, output: 15 },
  }),
  on: ['vertex'],
});

google.model('gemini-2.5-flash', {
  name: 'Gemini 2.5 Flash',
  capability: null,
  price: tokenPrice(0.3, 2.5),
  on: ['vertex'],
});

google.model('gemini-2.5-flash-lite', {
  name: 'Gemini 2.5 Flash Lite',
  capability: null,
  price: tokenPrice(0.1, 0.4),
  on: ['vertex'],
});

// Off Google's current pricing page; identity resolves, rate is unknown.
google.model('gemini-1-5-pro', { name: 'Gemini 1.5 Pro', on: ['vertex'] });
google.model('gemini-1-5-flash', { name: 'Gemini 1.5 Flash', on: ['vertex'] });

// ─── xAI ─────────────────────────────────────────────────────────────────────
// Prices + context: docs.x.ai/docs/models. Every text model tiers at 200K input.
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

xai.model('grok-4.6', {
  name: 'Grok 4.6',
  ctx: 500_000,
  capability: 'reasoning',
  price: tokenPrice(2, 6, {
    cacheRead: 0.5,
    longContext: { thresholdInputTokens: 200_000, input: 4, output: 12 },
  }),
  on: ['bedrock'],
});

xai.model('grok-4.5', {
  name: 'Grok 4.5',
  ctx: 500_000,
  capability: 'reasoning',
  price: tokenPrice(2, 6, {
    cacheRead: 0.3,
    longContext: { thresholdInputTokens: 200_000, input: 4, output: 12 },
  }),
});

xai.model('grok-4.3', {
  name: 'Grok 4.3',
  ctx: 1_000_000,
  capability: 'reasoning',
  price: tokenPrice(1.25, 2.5, {
    cacheRead: 0.2,
    longContext: { thresholdInputTokens: 200_000, input: 2.5, output: 5 },
  }),
  on: ['bedrock'],
});

xai.model('grok-build-0.1', {
  name: 'Grok Build 0.1',
  ctx: 256_000,
  capability: 'code',
  price: tokenPrice(1, 2, {
    cacheRead: 0.2,
    longContext: { thresholdInputTokens: 200_000, input: 2, output: 4 },
  }),
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

deepseek.model('deepseek-v4-flash', {
  name: 'DeepSeek V4 Flash',
  ctx: 1_000_000,
  capability: null,
  price: tokenPrice(0.44, 1.32, { cacheRead: 0.014 }),
  on: ['bedrock', 'together', 'fireworks', 'openrouter', 'ollama', 'local'],
});

deepseek.model('deepseek-v4-pro', {
  name: 'DeepSeek V4 Pro',
  ctx: 1_000_000,
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
  // The undated form is what deployments report; the live id carries the date.
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

// Absent from Mistral's current model list; survives on third-party hosts.
mistral.model('mixtral-8x7b', {
  name: 'Mixtral 8x7B',
  seen: 'discovered',
  on: [...OPEN_WEIGHT_HOSTS],
});

// The rest of Mistral's wire model ids are not published alongside its pricing (the pricing
// page uses display names and version tags), so no Mistral entries are declared
// rather than declaring ids that would not resolve.

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

/** The lookup index over `MODEL_ENTRIES`, keyed by canonical id and alias. */
export const MODEL_INDEX = buildModelIndex(MODEL_ENTRIES);
