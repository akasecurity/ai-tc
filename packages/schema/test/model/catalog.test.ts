import { describe, expect, it } from 'vitest';

import {
  anthropicPrice,
  buildModelIndex,
  hostingFor,
  isFirstParty,
  MODEL_ENTRIES,
  MODEL_INDEX,
  ModelPlatform,
  ModelVendor,
  resolveModel,
  resolveTrainsOnData,
  stripPlatformDecorations,
  UNDECLARED_TRAINING,
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
    // These are 1M models; the Claude 4.x figure is 200K and applies to Haiku.
    for (const id of ['claude-opus-5', 'claude-sonnet-5', 'claude-fable-5-1']) {
      expect(MODEL_INDEX.byId.get(id)?.contextWindow, id).toBe(1_000_000);
    }
    expect(MODEL_INDEX.byId.get('claude-haiku-4-5')?.contextWindow).toBe(200_000);
  });

  it('orders the Claude tiers by their published rates', () => {
    const rate = (id: string): number => {
      const price = MODEL_INDEX.byId.get(id)?.platforms.get('anthropic')?.price;
      if (price == null) throw new Error(`no first-party price for ${id}`);
      return price.input + price.output;
    };
    // Fable bills above Opus, which bills above Sonnet, which bills above Haiku.
    expect(rate('claude-fable-5-1')).toBeGreaterThan(rate('claude-opus-5'));
    expect(rate('claude-opus-5')).toBeGreaterThan(rate('claude-sonnet-5'));
    expect(rate('claude-sonnet-5')).toBeGreaterThan(rate('claude-haiku-4-5'));
  });

  it('carries the non-uniform Anthropic cache-read rates', () => {
    // Fable 5.1 reads cache at 0.025x base input; the rest of the family at 0.1x.
    expect(MODEL_INDEX.byId.get('claude-fable-5-1')?.platforms.get('anthropic')?.price?.cacheRead).toBe(
      0.25,
    );
    expect(MODEL_INDEX.byId.get('claude-fable-5')?.platforms.get('anthropic')?.price?.cacheRead).toBe(1);
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
