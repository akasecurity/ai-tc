import { describe, expect, it } from 'vitest';

import {
  anthropicPrice,
  buildModelIndex,
  costOf,
  defaultCostModel,
  firstPartyPlatformFor,
  hostingFor,
  isFirstParty,
  LONG_CONTEXT_THRESHOLDS,
  MODEL_ENTRIES,
  MODEL_INDEX,
  ModelPlatform,
  ModelVendor,
  platformForProvider,
  resolveModel,
  resolveTrainsOnData,
  stripPlatformDecorations,
  tokenPrice,
  UNDECLARED_TRAINING,
  UNPRICEABLE_PROVIDERS,
  vendor,
  ZERO_PRICE,
} from '../../src/index.ts';

describe('platform vocabulary', () => {
  // `hostingFor` falls back to 'api' for a platform with no band, so the
  // fallback is only unreachable while this table covers the whole enum. Stated
  // as expected VALUES rather than as a not-undefined check: the latter is
  // satisfied by the fallback itself and would pass for a platform whose band
  // was never declared.
  const EXPECTED_HOSTING: Record<string, string> = {
    anthropic: 'api',
    openai: 'api',
    'google-ai': 'api',
    mistral: 'api',
    deepseek: 'api',
    xai: 'api',
    cohere: 'api',
    bedrock: 'api',
    vertex: 'api',
    azure: 'api',
    foundry: 'api',
    together: 'gateway',
    fireworks: 'gateway',
    groq: 'gateway',
    openrouter: 'gateway',
    ollama: 'local',
    local: 'local',
  };

  it('gives every platform its declared hosting band', () => {
    // Exact key set: a platform added without a band fails here rather than
    // silently taking the fallback.
    expect(Object.keys(EXPECTED_HOSTING).sort()).toEqual([...ModelPlatform.options].sort());
    for (const platform of ModelPlatform.options) {
      expect(hostingFor(platform), platform).toBe(EXPECTED_HOSTING[platform]);
    }
  });

  it('names only the vendor’s own endpoint as first-party', () => {
    expect(isFirstParty('anthropic', 'anthropic')).toBe(true);
    expect(isFirstParty('anthropic', 'bedrock')).toBe(false);
    expect(isFirstParty('anthropic', 'vertex')).toBe(false);
    // Meta publishes weights and runs no first-party API.
    expect(isFirstParty('meta', 'together')).toBe(false);
  });
});

describe('id resolution', () => {
  it('resolves every platform spelling of one model to the same entry', () => {
    const spellings = [
      'claude-opus-5',
      'anthropic.claude-opus-5',
      'us.anthropic.claude-opus-5',
      'eu.anthropic.claude-opus-5',
      'global.anthropic.claude-opus-5',
      'claude-opus-5@20251101',
      'anthropic/claude-opus-5',
    ];
    for (const raw of spellings) {
      const resolved = resolveModel(raw, MODEL_INDEX);
      expect(resolved.entry?.id, raw).toBe('claude-opus-5');
    }
  });

  it('resolves the geo prefixes an Anthropic-only canonicaliser omitted', () => {
    // `au.` and `jp.` are documented Bedrock inference-profile prefixes.
    expect(resolveModel('au.anthropic.claude-opus-5', MODEL_INDEX).entry?.id).toBe('claude-opus-5');
    expect(resolveModel('jp.amazon.nova-2-lite-v1:0', MODEL_INDEX).entry?.id).toBe('nova-2-lite');
  });

  it('infers the serving platform from the id shape', () => {
    expect(resolveModel('us.anthropic.claude-opus-5', MODEL_INDEX).platform).toBe('bedrock');
    expect(resolveModel('claude-haiku-4-5@20251001', MODEL_INDEX).platform).toBe('vertex');
    expect(resolveModel('claude-opus-5', MODEL_INDEX).platform).toBeNull();
  });

  it('prefers an exact id over a dated-suffix strip', () => {
    // A model whose canonical id itself ends in eight digits must match itself
    // before the shorter form is tried.
    const dated = resolveModel('claude-haiku-4-5-20251001', MODEL_INDEX);
    expect(dated.entry?.id).toBe('claude-haiku-4-5');
    expect(resolveModel('claude-haiku-4-5', MODEL_INDEX).entry?.id).toBe('claude-haiku-4-5');
  });

  it('resolves hyphen-dated OpenAI snapshot ids to their undated entry', () => {
    const cases: [string, string][] = [
      ['gpt-4o-2024-08-06', 'gpt-4o'],
      ['gpt-4o-2024-11-20', 'gpt-4o'],
      ['gpt-4o-mini-2024-07-18', 'gpt-4o-mini'],
      ['azure/gpt-4o-2024-08-06', 'gpt-4o'],
    ];
    for (const [raw, id] of cases) {
      const resolved = resolveModel(raw, MODEL_INDEX);
      expect(resolved.entry?.id, raw).toBe(id);
      expect(resolved.canonicalId, raw).toBe(id);
    }
  });

  it('resolves a separately priced snapshot to its own entry, not the undated one', () => {
    const resolved = resolveModel('gpt-4o-2024-05-13', MODEL_INDEX);
    expect(resolved.entry?.id).toBe('gpt-4o-2024-05-13');
    expect(resolved.entry?.familyId).toBe('gpt');
    const price = resolved.entry?.platforms.get('openai')?.price;
    expect(price?.input).toBe(5);
    expect(price?.output).toBe(15);
  });

  it('strips only a whole trailing date, never a partial one', () => {
    // A month-day suffix or a malformed date is not a snapshot date.
    for (const raw of [
      'gpt-4o-08-06',
      'gpt-4o-2024-0806',
      'gpt-4o-24-08-06',
      'gpt-4o-2024-08-06x',
    ]) {
      expect(resolveModel(raw, MODEL_INDEX).entry, raw).toBeNull();
    }
  });

  it('resolves the OpenAI embedding models with their input price and no output price', () => {
    const expected: [string, number][] = [
      ['text-embedding-3-small', 0.02],
      ['text-embedding-3-large', 0.13],
      ['text-embedding-ada-002', 0.1],
    ];
    for (const [id, input] of expected) {
      const entry = resolveModel(id, MODEL_INDEX).entry;
      expect(entry?.vendor, id).toBe('openai');
      expect(entry?.capability, id).toBe('embedding');
      const price = entry?.platforms.get('openai')?.price;
      expect(price?.input, id).toBe(input);
      expect(price?.output, id).toBe(0);
    }
  });

  it('prices an embedding call from input tokens alone', () => {
    const cost = defaultCostModel.costFor({
      provider: 'openai',
      model: 'text-embedding-3-small',
      usage: { inputTokens: 1_000_000, outputTokens: 0 },
    });
    expect(cost).toBeCloseTo(0.02, 10);
  });

  it('returns no entry for an unknown model rather than a lookalike', () => {
    const resolved = resolveModel('claude-nonexistent-9', MODEL_INDEX);
    expect(resolved.entry).toBeNull();
    expect(resolved.canonicalId).toBe('claude-nonexistent-9');
  });

  it('does not resolve Object.prototype keys', () => {
    // The index is a Map, so an inherited property cannot be reached through it.
    for (const hostile of ['toString', 'constructor', '__proto__', 'valueOf', 'hasOwnProperty']) {
      const resolved = resolveModel(hostile, MODEL_INDEX);
      expect(resolved.entry, hostile).toBeNull();
    }
  });

  it('strips decorations without inventing a platform', () => {
    expect(stripPlatformDecorations('meta-llama/llama-3-3-70b').id).toBe('llama-3-3-70b');
    expect(stripPlatformDecorations('meta-llama/llama-3-3-70b').platform).toBeNull();
  });
});

describe('builder', () => {
  const acme = vendor('anthropic', {
    family: { id: 'acme', name: 'Acme' },
    region: 'us',
    retention: 'zero_retention',
  });

  const model = acme.model('acme-1', {
    name: 'Acme 1',
    ctx: 1_000,
    price: anthropicPrice(10, 50, 1),
    on: ['bedrock', 'ollama'],
  });

  it('gives the first-party platform the declared price and retention', () => {
    const own = model.platforms.get('anthropic');
    expect(own?.firstParty).toBe(true);
    expect(own?.price?.input).toBe(10);
    expect(own?.retention).toBe('zero_retention');
  });

  it('gives a reseller the identity but neither the price nor the retention', () => {
    const bedrock = model.platforms.get('bedrock');
    expect(bedrock?.firstParty).toBe(false);
    expect(bedrock?.price).toBeNull();
    expect(bedrock?.retention).toBe('unknown');
  });

  it('prices a self-hosted platform at a known zero', () => {
    const ollama = model.platforms.get('ollama');
    expect(ollama?.price).toEqual(ZERO_PRICE);
    expect(ollama?.retention).toBe('on_infrastructure');
  });

  it('records an unstated context window as unknown rather than a default', () => {
    const undeclared = acme.model('acme-2', { name: 'Acme 2' });
    expect(undeclared.contextWindow).toBeNull();
    expect(undeclared.maxOutputTokens).toBeNull();
  });
});

describe('trainsOnData resolution', () => {
  const policy = {
    apiDefault: 'no',
    consumerDefault: 'yes',
    consumerControl: 'opt-out',
    source: null,
  } as const;

  it('is unknown until an operator declares the plan', () => {
    expect(
      resolveTrainsOnData({
        hosting: 'api',
        firstParty: true,
        policy,
        declaration: UNDECLARED_TRAINING,
      }),
    ).toBe('unknown');
  });

  it('uses the vendor policy once a tier is declared', () => {
    expect(
      resolveTrainsOnData({
        hosting: 'api',
        firstParty: true,
        policy,
        declaration: { tier: 'api', controlExercised: null },
      }),
    ).toBe('no');
    expect(
      resolveTrainsOnData({
        hosting: 'api',
        firstParty: true,
        policy,
        declaration: { tier: 'consumer', controlExercised: null },
      }),
    ).toBe('yes');
  });

  it('honours an exercised opt-out', () => {
    expect(
      resolveTrainsOnData({
        hosting: 'api',
        firstParty: true,
        policy,
        declaration: { tier: 'consumer', controlExercised: true },
      }),
    ).toBe('no');
  });

  it('never transfers the vendor posture to a reseller', () => {
    expect(
      resolveTrainsOnData({
        hosting: 'api',
        firstParty: false,
        policy,
        declaration: { tier: 'api', controlExercised: null },
      }),
    ).toBe('unknown');
  });

  it('answers no for self-hosted weights regardless of declaration', () => {
    expect(
      resolveTrainsOnData({
        hosting: 'local',
        firstParty: false,
        policy,
        declaration: UNDECLARED_TRAINING,
      }),
    ).toBe('no');
  });
});

describe('catalog data', () => {
  it('declares no duplicate ids', () => {
    const ids = MODEL_ENTRIES.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('never lets an alias shadow a declared model', () => {
    for (const entry of MODEL_ENTRIES) {
      for (const alias of entry.aliases) {
        const shadowed = MODEL_ENTRIES.find((e) => e.id === alias);
        if (shadowed !== undefined) {
          expect(MODEL_INDEX.byId.get(alias)).toBe(shadowed);
        }
      }
    }
  });

  it('names a vendor for every entry', () => {
    for (const entry of MODEL_ENTRIES) {
      expect(ModelVendor.options).toContain(entry.vendor);
    }
  });

  it('records the published Claude 5 context windows', () => {
    // These are 1M models; Haiku 4.5 is published at 200K.
    for (const id of [
      'claude-opus-5',
      'claude-opus-5-5',
      'claude-sonnet-5',
      'claude-sonnet-5-5',
      'claude-haiku-5-5',
      'claude-fable-5-1',
    ]) {
      expect(MODEL_INDEX.byId.get(id)?.contextWindow, id).toBe(1_000_000);
    }
    expect(MODEL_INDEX.byId.get('claude-haiku-4-5')?.contextWindow).toBe(200_000);
  });

  it('resolves the undated command-r-plus to the snapshot it names', () => {
    expect(resolveModel('command-r-plus', MODEL_INDEX).entry?.id).toBe('command-r-plus-04-2024');
    expect(resolveModel('command-r-plus-08-2024', MODEL_INDEX).entry?.id).toBe(
      'command-r-plus-08-2024',
    );
  });

  it('orders the Claude tiers by their published rates', () => {
    const rate = (id: string): number => {
      const price = MODEL_INDEX.byId.get(id)?.platforms.get('anthropic')?.price;
      if (price == null) throw new Error(`no first-party price for ${id}`);
      return price.input + price.output;
    };
    // Fable bills above Opus, which bills above Sonnet, which bills above Haiku,
    // within each generation.
    expect(rate('claude-fable-5-1')).toBeGreaterThan(rate('claude-opus-5'));
    expect(rate('claude-opus-5')).toBeGreaterThan(rate('claude-sonnet-5'));
    expect(rate('claude-sonnet-5')).toBeGreaterThan(rate('claude-haiku-4-5'));
    expect(rate('claude-fable-5-1')).toBeGreaterThan(rate('claude-opus-5-5'));
    expect(rate('claude-opus-5-5')).toBeGreaterThan(rate('claude-sonnet-5-5'));
    expect(rate('claude-sonnet-5-5')).toBeGreaterThan(rate('claude-haiku-5-5'));
    // The 5.5 generation is priced below the 5 generation it follows.
    expect(rate('claude-opus-5')).toBeGreaterThan(rate('claude-opus-5-5'));
    expect(rate('claude-haiku-4-5')).toBeGreaterThan(rate('claude-haiku-5-5'));
  });

  it('carries the non-uniform Anthropic cache-read rates', () => {
    // Fable 5.1 reads cache at 0.025x base input, Opus 5.5 and Sonnet 5.5 at
    // 0.05x, and the rest of the family at 0.1x.
    const cacheRead = (id: string) =>
      MODEL_INDEX.byId.get(id)?.platforms.get('anthropic')?.price?.cacheRead;
    expect(cacheRead('claude-fable-5-1')).toBe(0.25);
    expect(cacheRead('claude-opus-5-5')).toBe(0.2);
    expect(cacheRead('claude-sonnet-5-5')).toBe(0.1);
    expect(cacheRead('claude-fable-5')).toBe(1);
    expect(cacheRead('claude-opus-5')).toBe(0.5);
  });

  // Published figures, read from each vendor's own pricing and model pages. An
  // edit to any of these entries has to change this table too.
  it.each([
    ['gpt-6-astra', 1_050_000, 10, 50, 1],
    ['gpt-6.1-sol', 1_050_000, 2, 10, 0.1],
    ['gpt-6-sol', 1_050_000, 2, 10, 0.2],
    ['gpt-6-luna', 1_050_000, 0.1, 0.5, 0.01],
    ['gpt-5.6-sol', 1_050_000, 4, 20, 0.4],
    ['gpt-5.5-pro', 1_050_000, 30, 180, null],
    ['gemini-3.8-flash', 1_048_576, 0.75, 3.75, 0.075],
    ['gemini-3.1-flash-lite', 1_048_576, 0.25, 1.5, 0.025],
    ['gemini-3-flash-preview', 1_048_576, 0.5, 3, 0.05],
    ['gemini-embedding-2', null, 0.2, 0, null],
    ['grok-4.7', 500_000, 2, 6, 0.5],
    ['grok-4.20-0309-reasoning', 1_000_000, 1.25, 2.5, 0.2],
    ['grok-4.20-0309-non-reasoning', 1_000_000, 1.25, 2.5, 0.2],
    ['grok-4.20-multi-agent-0309', 1_000_000, 1.25, 2.5, 0.2],
    ['deepseek-flash', 1_000_000, 0.3, 1.2, 0.006],
    ['mistral-large-4', 1_000_000, 0.68, 2.09, 0.07],
    ['mistral-large-2512', 256_000, 0.5, 1.5, 0.05],
    ['mistral-medium-3-5', 256_000, 1.5, 7.5, 0.15],
    ['mistral-small-2603', 256_000, 0.15, 0.6, 0.015],
    ['ministral-14b-2512', 256_000, 0.2, 0.2, 0.02],
    ['ministral-8b-2512', 256_000, 0.15, 0.15, 0.015],
    ['ministral-3b-2512', 256_000, 0.1, 0.1, 0.01],
    ['codestral-2508', 128_000, 0.3, 0.9, 0.03],
  ] as const)('carries the published figures for %s', (id, ctx, input, output, cacheRead) => {
    const entry = MODEL_INDEX.byId.get(id);
    const price = entry?.platforms.get(firstPartyPlatformFor(entry.vendor) ?? 'local')?.price;
    expect(entry?.contextWindow ?? null).toBe(ctx);
    expect(price?.input).toBe(input);
    expect(price?.output).toBe(output);
    expect(price?.cacheRead).toBe(cacheRead);
  });

  it('derives every Grok band as 2x the base rate at 200K', () => {
    for (const entry of MODEL_ENTRIES.filter((e) => e.vendor === 'xai')) {
      const price = entry.platforms.get('xai')?.price;
      expect(price?.longContext, entry.id).toEqual({
        thresholdInputTokens: 200_000,
        input: (price?.input ?? 0) * 2,
        output: (price?.output ?? 0) * 2,
        cacheRead: (price?.cacheRead ?? 0) * 2,
      });
    }
  });

  it('leaves every reseller offering unpriced', () => {
    for (const entry of MODEL_ENTRIES) {
      for (const offering of entry.platforms.values()) {
        if (offering.firstParty || offering.hosting === 'local') continue;
        expect(offering.price, `${entry.id} on ${offering.platform}`).toBeNull();
      }
    }
  });

  it('builds an index that resolves every declared id', () => {
    const index = buildModelIndex(MODEL_ENTRIES);
    for (const entry of MODEL_ENTRIES) {
      expect(resolveModel(entry.id, index).entry?.id, entry.id).toBe(entry.id);
    }
  });
});

describe('the provider vocabulary the product actually stores', () => {
  // Every provider string a resolver can record, from the three resolver
  // vocabularies plus the miss values. These are what reach `costFor`, and they
  // are NOT spelled like `ModelPlatform` — `google` against `google-ai` is the
  // gap this case exists to hold closed.
  const STORED_PROVIDERS = [
    // provider.ts — Provider
    'anthropic',
    'bedrock',
    'vertex',
    'gateway',
    // provider-codex.ts — CodexProvider
    'openai',
    // provider-antigravity.ts — AntigravityProvider
    'google',
    // protocol.ts's WEB_SOURCE_TOOLS — written as llm_call.provider by the
    // browser extension's native host (never the vendor id)
    'chatgpt',
    'claude-ai',
    // resolver miss values
    'unknown',
  ];

  it.each(STORED_PROVIDERS)('maps %s onto a platform, or declares it unpriceable', (provider) => {
    // One or the other, never neither. A provider that is silently unmapped
    // leaves every model it serves unpriced while the catalog carries a rate —
    // which is exactly how `google` shipped unreachable.
    const mapped = platformForProvider(provider) !== null;
    const declaredUnpriceable = UNPRICEABLE_PROVIDERS.includes(provider);
    expect(mapped || declaredUnpriceable, provider).toBe(true);
  });

  it('never prices web-chat providers at API rates, so subscription traffic is never billed as API usage', () => {
    // The web-chat host stamps the web tool id (`chatgpt`/`claude-ai`), never
    // the vendor id, precisely so this stays null.
    expect(
      defaultCostModel.costFor({
        provider: 'chatgpt',
        model: 'gpt-4o',
        usage: { inputTokens: 1_000 },
      }),
    ).toBeNull();
    expect(
      defaultCostModel.costFor({
        provider: 'claude-ai',
        model: 'claude-opus-5',
        usage: { inputTokens: 1_000 },
      }),
    ).toBeNull();
    // Positive control: the SAME models, under the VENDOR id, price as real
    // numbers — proving the provider string, not the model, is what makes the
    // web-tool id null.
    expect(
      defaultCostModel.costFor({
        provider: 'openai',
        model: 'gpt-4o',
        usage: { inputTokens: 1_000 },
      }),
    ).toBeTypeOf('number');
    expect(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'claude-opus-5',
        usage: { inputTokens: 1_000 },
      }),
    ).toBeTypeOf('number');
  });

  it('prices a Gemini call from the provider string the resolver records', () => {
    // Regression: `google` is what gets stored; `google-ai` is the catalog's
    // spelling. Keying only off the catalog's left every Gemini rollup unpriced.
    expect(
      defaultCostModel.costFor({
        provider: 'google',
        model: 'gemini-2.5-pro',
        usage: { inputTokens: 1_000 },
      }),
    ).toBeCloseTo(0.00125, 10);
  });

  it('does not price a Bedrock-shaped id at first-party rates', () => {
    // The id names Bedrock whatever the session's provider snapshot claims,
    // and Bedrock's own rate is not carried.
    expect(
      defaultCostModel.costFor({
        provider: 'anthropic',
        model: 'us.anthropic.claude-opus-5',
        usage: { inputTokens: 1_000_000 },
      }),
    ).toBeNull();
  });
});

describe('long-context pricing', () => {
  it('re-prices the whole request at the band rate above the threshold', () => {
    // Gemini 2.5 Pro is $1.25/MTok at or below 200K and $2.50 above it, and the
    // band applies to the entire request rather than the excess.
    const under = defaultCostModel.costFor({
      provider: 'google',
      model: 'gemini-2.5-pro',
      usage: { inputTokens: 100_000 },
    });
    const over = defaultCostModel.costFor({
      provider: 'google',
      model: 'gemini-2.5-pro',
      usage: { inputTokens: 300_000 },
    });
    expect(under).toBeCloseTo(0.125, 10);
    expect(over).toBeCloseTo(0.75, 10);
  });

  it('returns unknown when the band rate itself is unpublished', () => {
    // A vendor can publish a threshold without the rate above it. A definite
    // figure there would be the sub-threshold price reported as the total.
    const unpublished = tokenPrice(1, 10, {
      longContext: { thresholdInputTokens: 200_000, input: null, output: null },
    });
    expect(costOf(unpublished, { inputTokens: 400_000 })).toBeNull();
    // Not vacuous: the same price resolves below the threshold.
    expect(costOf(unpublished, { inputTokens: 100_000 })).toBeCloseTo(0.1, 10);
  });

  it('holds an unread band input or output to the requests that bill against it', () => {
    const outputOnly = tokenPrice(1, 10, {
      cacheRead: 0.1,
      longContext: { thresholdInputTokens: 200_000, input: null, output: 20 },
    });
    // A fully cached 300K prompt bills no uncached input, so the unread input
    // rate does not touch it.
    expect(costOf(outputOnly, { cacheReadTokens: 300_000, outputTokens: 1_000 })).toBeCloseTo(
      0.05,
      10,
    );
    expect(costOf(outputOnly, { inputTokens: 1, cacheReadTokens: 300_000 })).toBeNull();
  });

  it('prices the whole OpenAI request at the published band above 272K', () => {
    // GPT-5.5: 5 / 30 below the line; 2x input and 1.5x output above it.
    expect(
      defaultCostModel.costFor({
        provider: 'openai',
        model: 'gpt-5.5',
        usage: { inputTokens: 400_000, outputTokens: 10_000 },
      }),
    ).toBeCloseTo(4.45, 10);
    expect(
      defaultCostModel.costFor({
        provider: 'openai',
        model: 'gpt-5.5',
        usage: { inputTokens: 100_000, outputTokens: 10_000 },
      }),
    ).toBeCloseTo(0.8, 10);
  });

  it('counts cached prompt tokens toward the band threshold', () => {
    // 15K uncached + 285K read from cache is a 300K prompt: over the 272K line,
    // so GPT-5.4 bills input at 5 and cache reads at 0.5.
    const usage = { inputTokens: 15_000, cacheReadTokens: 285_000 };
    expect(defaultCostModel.costFor({ provider: 'openai', model: 'gpt-5.4', usage })).toBeCloseTo(
      0.2175,
      10,
    );
    const banded = tokenPrice(1, 10, {
      cacheRead: 0.1,
      longContext: { thresholdInputTokens: 200_000, input: 2, output: 20 },
    });
    expect(costOf(banded, { inputTokens: 50_000, cacheReadTokens: 200_000 })).toBeCloseTo(0.12, 10);
    expect(costOf(banded, { inputTokens: 50_000, cacheReadTokens: 100_000 })).toBeCloseTo(0.06, 10);
    // Not vacuous: the same split under the line takes the base rates.
    expect(
      defaultCostModel.costFor({
        provider: 'openai',
        model: 'gpt-5.4',
        usage: { inputTokens: 15_000, cacheReadTokens: 200_000 },
      }),
    ).toBeCloseTo(0.0875, 10);
  });

  it('takes the band from promptTokens when a caller prices a sum of requests', () => {
    // Two 150K requests summed: 300K of input, but no single request crossed 272K.
    const summed = { inputTokens: 20_000, cacheReadTokens: 280_000 };
    expect(
      defaultCostModel.costFor({ provider: 'openai', model: 'gpt-5.4', usage: summed }),
    ).toBeCloseTo(0.24, 10);
    expect(
      defaultCostModel.costFor({
        provider: 'openai',
        model: 'gpt-5.4',
        usage: { ...summed, promptTokens: 150_000 },
      }),
    ).toBeCloseTo(0.12, 10);
  });

  it('re-prices a cache column only where the band names it', () => {
    const usage = { inputTokens: 250_000, cacheReadTokens: 100_000 };
    const base = { cacheRead: 0.1 };
    const unnamed = tokenPrice(1, 10, {
      ...base,
      longContext: { thresholdInputTokens: 200_000, input: 2, output: 20 },
    });
    const named = tokenPrice(1, 10, {
      ...base,
      longContext: { thresholdInputTokens: 200_000, input: 2, output: 20, cacheRead: 0.2 },
    });
    const unread = tokenPrice(1, 10, {
      ...base,
      longContext: { thresholdInputTokens: 200_000, input: 2, output: 20, cacheRead: null },
    });
    expect(costOf(unnamed, usage)).toBeCloseTo(0.51, 10);
    expect(costOf(named, usage)).toBeCloseTo(0.52, 10);
    expect(costOf(unread, usage)).toBeNull();
    // An unread band column only matters to a request that bills against it.
    expect(costOf(unread, { inputTokens: 250_000 })).toBeCloseTo(0.5, 10);
  });

  it('prices Claude Haiku 5.5 by prompt length, cache writes included', () => {
    const haiku = (usage: Parameters<typeof costOf>[1]) =>
      defaultCostModel.costFor({ provider: 'anthropic', model: 'claude-haiku-5-5', usage });
    // 80K uncached + 20K cache write = a 100K prompt: not OVER the line.
    expect(haiku({ inputTokens: 80_000, cacheWrite5mTokens: 20_000 })).toBeCloseTo(0.0105, 10);
    // One more token crosses it, and every column re-prices: 0.5 input,
    // 0.625 5m write, 0.05 cache read.
    expect(
      haiku({ inputTokens: 80_001, cacheWrite5mTokens: 20_000, cacheReadTokens: 0 }),
    ).toBeCloseTo((80_001 * 0.5 + 20_000 * 0.625) / 1_000_000, 10);
    expect(haiku({ inputTokens: 10_000, cacheReadTokens: 100_000 })).toBeCloseTo(0.01, 10);
  });

  it('lists every declared band threshold once, ascending', () => {
    const declared = new Set<number>();
    for (const entry of MODEL_ENTRIES) {
      for (const offering of entry.platforms.values()) {
        const band = offering.price?.longContext;
        if (band) declared.add(band.thresholdInputTokens);
      }
    }
    expect(declared.size).toBeGreaterThan(0);
    expect(LONG_CONTEXT_THRESHOLDS).toEqual([...declared].sort((a, b) => a - b));
  });
});
