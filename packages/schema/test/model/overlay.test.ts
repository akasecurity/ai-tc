import { describe, expect, it } from 'vitest';

import type { CatalogOverlay, ModelEntry, ModelPrice, OverlayModel } from '../../src/index.ts';
import {
  anthropicBand,
  anthropicPrice,
  buildModelIndex,
  CatalogOverlay as CatalogOverlaySchema,
  createCostModel,
  defaultCostModel,
  longContextThresholdsOf,
  mergeCatalog,
  MODEL_ENTRIES,
  priceAt,
  tokenPrice,
  UnsupportedOverlayFormatError,
  vendor,
} from '../../src/index.ts';

const SOURCE = { source: 'https://example.com/pricing', readAt: '2026-11-20' };

function overlayOf(models: OverlayModel[], formatVersion = 1): CatalogOverlay {
  return { formatVersion, version: 1, publishedAt: '2026-11-25T00:00:00Z', models };
}

function bundled(): readonly ModelEntry[] {
  const anthropic = vendor('anthropic', {
    family: { id: 'claude', name: 'Claude' },
    region: 'us',
    retention: 'zero_retention',
  });
  anthropic.model('claude-test-1', {
    name: 'Claude Test 1',
    ctx: 200_000,
    maxOut: 64_000,
    capability: 'reasoning',
    price: anthropicPrice(3, 15, 0.3),
    on: ['vertex'],
  });
  return anthropic.models();
}

function byId(entries: readonly ModelEntry[], id: string): ModelEntry {
  const entry = entries.find((e) => e.id === id);
  if (entry === undefined) throw new Error(`no entry ${id}`);
  return entry;
}

describe('priceAt', () => {
  const testVendor = vendor('anthropic', {});
  const entry = testVendor.model('claude-dated', {
    name: 'Claude Dated',
    price: tokenPrice(3, 15),
    priceHistory: [{ from: '2026-12-01', price: tokenPrice(4, 20) }],
  });
  const offering = entry.platforms.get('anthropic');

  it('picks the latest row on or before the day', () => {
    expect(offering).toBeDefined();
    if (offering === undefined) return;
    expect(priceAt(offering, '2026-11-30')?.input).toBe(3);
    expect(priceAt(offering, '2026-12-01')?.input).toBe(4);
    expect(priceAt(offering, '2026-12-15')?.input).toBe(4);
  });

  it('keeps the undated row first and reports the last row as the current price', () => {
    expect(offering?.prices.map((row) => row.effectiveFrom)).toEqual([null, '2026-12-01']);
    expect(offering?.price?.input).toBe(4);
  });

  it('is null before the first dated row when there is no undated one', () => {
    const only = testVendor.model('claude-dated-only', {
      name: 'Claude Dated Only',
      priceHistory: [{ from: '2026-12-01', price: tokenPrice(4, 20) }],
    });
    const own = only.platforms.get('anthropic');
    expect(own).toBeDefined();
    if (own === undefined) return;
    expect(priceAt(own, '2026-11-30')).toBeNull();
    expect(priceAt(own, '2026-12-01')?.input).toBe(4);
  });
});

describe('mergeCatalog', () => {
  it('adds a new id as discovered with a first-party offering from vendor defaults', () => {
    const { entries, skipped } = mergeCatalog(
      bundled(),
      overlayOf([
        { id: 'claude-new', vendor: 'anthropic', name: 'Claude New', provenance: { name: SOURCE } },
      ]),
    );
    expect(skipped).toEqual([]);
    const added = byId(entries, 'claude-new');
    expect(added.seen).toBe('discovered');
    expect(added.displayName).toBe('Claude New');
    expect(added.familyId).toBe('claude');
    expect([...added.platforms.keys()]).toEqual(['anthropic']);
    const own = added.platforms.get('anthropic');
    expect(own?.firstParty).toBe(true);
    expect(own?.retention).toBe('zero_retention');
    expect(own?.region).toBe('us');
    expect(own?.prices).toEqual([]);
    expect(own?.price).toBeNull();
    expect(added.deprecatedAt).toBeNull();
    expect(Object.isFrozen(added)).toBe(true);
  });

  it('replaces a stated field and keeps an omitted one', () => {
    const { entries } = mergeCatalog(
      bundled(),
      overlayOf([
        {
          id: 'claude-test-1',
          vendor: 'anthropic',
          ctx: 1_000_000,
          provenance: { ctx: SOURCE },
        },
      ]),
    );
    const merged = byId(entries, 'claude-test-1');
    expect(merged.contextWindow).toBe(1_000_000);
    expect(merged.maxOutputTokens).toBe(64_000);
    expect(merged.displayName).toBe('Claude Test 1');
    expect(merged.seen).toBe('managed');
  });

  it('appends an overlay price row after the bundled one', () => {
    const { entries } = mergeCatalog(
      bundled(),
      overlayOf([
        {
          id: 'claude-test-1',
          vendor: 'anthropic',
          offerings: [
            {
              platform: 'anthropic',
              prices: [{ effectiveFrom: '2026-12-01', price: anthropicPrice(4, 20, 0.4) }],
            },
          ],
          provenance: { prices: SOURCE },
        },
      ]),
    );
    const own = byId(entries, 'claude-test-1').platforms.get('anthropic');
    expect(own?.prices.map((row) => [row.effectiveFrom, row.price.input])).toEqual([
      [null, 3],
      ['2026-12-01', 4],
    ]);
    expect(own?.price?.input).toBe(4);
    expect(own?.firstParty).toBe(true);
  });

  it('adds a reseller offering as non-first-party with unknown retention unless stated', () => {
    const offering = (retention?: 'no_storage'): CatalogOverlay =>
      overlayOf([
        {
          id: 'claude-test-1',
          vendor: 'anthropic',
          offerings: [{ platform: 'bedrock', ...(retention === undefined ? {} : { retention }) }],
          provenance: { offerings: SOURCE },
        },
      ]);

    const bedrock = byId(mergeCatalog(bundled(), offering()).entries, 'claude-test-1').platforms.get(
      'bedrock',
    );
    expect(bedrock).toMatchObject({
      platform: 'bedrock',
      hosting: 'api',
      firstParty: false,
      retention: 'unknown',
      region: null,
      price: null,
      prices: [],
    });

    const stated = byId(
      mergeCatalog(bundled(), offering('no_storage')).entries,
      'claude-test-1',
    ).platforms.get('bedrock');
    expect(stated?.retention).toBe('no_storage');
  });

  it('skips a model whose vendor or platform is unknown and applies the rest', () => {
    const { entries, skipped } = mergeCatalog(
      bundled(),
      overlayOf([
        { id: 'nonesuch-1', vendor: 'nonesuch', name: 'Nonesuch', provenance: { name: SOURCE } },
        {
          id: 'claude-test-1',
          vendor: 'anthropic',
          offerings: [{ platform: 'nowhere' }],
          provenance: { offerings: SOURCE },
        },
        { id: 'claude-kept', vendor: 'anthropic', provenance: {} },
      ]),
    );
    expect(skipped).toEqual(['nonesuch-1', 'claude-test-1']);
    expect(entries.map((e) => e.id)).toEqual(['claude-test-1', 'claude-kept']);
    expect([...byId(entries, 'claude-test-1').platforms.keys()]).toEqual(['anthropic', 'vertex']);
  });

  it('skips a model that names a different vendor than the bundled entry', () => {
    const { skipped } = mergeCatalog(
      bundled(),
      overlayOf([{ id: 'claude-test-1', vendor: 'openai', provenance: {} }]),
    );
    expect(skipped).toEqual(['claude-test-1']);
  });

  it('rejects an unsupported format version', () => {
    expect(() => mergeCatalog(bundled(), overlayOf([], 2))).toThrow(
      UnsupportedOverlayFormatError,
    );
  });

  it('is deterministic', () => {
    const overlay = overlayOf([
      {
        id: 'claude-test-1',
        vendor: 'anthropic',
        offerings: [
          {
            platform: 'anthropic',
            prices: [{ effectiveFrom: '2026-12-01', price: anthropicPrice(4, 20, 0.4) }],
          },
          { platform: 'bedrock' },
        ],
        provenance: { offerings: SOURCE },
      },
      { id: 'claude-new', vendor: 'anthropic', provenance: {} },
    ]);
    expect(mergeCatalog(bundled(), overlay)).toEqual(mergeCatalog(bundled(), overlay));
  });

  it('lands lifecycle dates on the entry', () => {
    const { entries } = mergeCatalog(
      bundled(),
      overlayOf([
        {
          id: 'claude-test-1',
          vendor: 'anthropic',
          lifecycle: {
            deprecatedAt: '2026-12-01',
            retiresAt: '2027-03-01',
            replacement: 'claude-new',
          },
          provenance: { lifecycle: SOURCE },
        },
      ]),
    );
    const merged = byId(entries, 'claude-test-1');
    expect(merged.deprecatedAt).toBe('2026-12-01');
    expect(merged.retiresAt).toBe('2027-03-01');
    expect(merged.replacement).toBe('claude-new');
  });

  it('unions aliases rather than dropping a bundled one', () => {
    const anthropic = vendor('anthropic', {});
    anthropic.model('claude-aliased', { name: 'A', aliases: ['claude-aliased-0'] });
    const { entries } = mergeCatalog(
      anthropic.models(),
      overlayOf([
        {
          id: 'claude-aliased',
          vendor: 'anthropic',
          aliases: ['claude-aliased-1', 'claude-aliased-0'],
          provenance: { aliases: SOURCE },
        },
      ]),
    );
    expect(byId(entries, 'claude-aliased').aliases).toEqual([
      'claude-aliased-0',
      'claude-aliased-1',
    ]);
  });
});

describe('CatalogOverlay', () => {
  it('requires provenance on every model', () => {
    const parsed = CatalogOverlaySchema.safeParse({
      formatVersion: 1,
      version: 1,
      publishedAt: '2026-11-25T00:00:00Z',
      models: [{ id: 'claude-x', vendor: 'anthropic', name: 'X' }],
    });
    expect(parsed.success).toBe(false);
  });

  it('keeps an unknown vendor and platform through parsing', () => {
    const parsed = CatalogOverlaySchema.safeParse(
      overlayOf([
        {
          id: 'x',
          vendor: 'nonesuch',
          offerings: [{ platform: 'nowhere' }],
          provenance: { name: SOURCE },
        },
      ]),
    );
    expect(parsed.success).toBe(true);
  });
});

describe('longContextThresholdsOf', () => {
  it('includes a threshold only an overlay price carries', () => {
    const banded: ModelPrice = anthropicPrice(3, 15, 0.3, anthropicBand(150_000, 6, 22.5, 0.6));
    const { entries } = mergeCatalog(
      MODEL_ENTRIES,
      overlayOf([
        {
          id: 'claude-opus-5',
          vendor: 'anthropic',
          offerings: [{ platform: 'anthropic', prices: [{ effectiveFrom: '2026-12-01', price: banded }] }],
          provenance: { prices: SOURCE },
        },
      ]),
    );
    expect(longContextThresholdsOf(MODEL_ENTRIES)).not.toContain(150_000);
    expect(longContextThresholdsOf(entries)).toContain(150_000);
  });
});

describe('cost model by day', () => {
  it('defaults to the current UTC day', () => {
    const usage = { inputTokens: 1_000_000 };
    expect(defaultCostModel.costFor({ provider: 'anthropic', model: 'claude-opus-5', usage })).toBe(
      5,
    );
  });

  it('prices a call at the rate in effect on its UTC day', () => {
    const testVendor = vendor('anthropic', {});
    testVendor.model('claude-dated', {
      name: 'Claude Dated',
      price: tokenPrice(3, 15),
      priceHistory: [{ from: '2026-12-01', price: tokenPrice(4, 20) }],
    });
    const costModel = createCostModel(buildModelIndex(testVendor.models()));
    const call = (at: string): number | null =>
      costModel.costFor({
        provider: 'anthropic',
        model: 'claude-dated',
        usage: { inputTokens: 1_000_000 },
        at,
      });
    expect(call('2026-11-30T23:59:59Z')).toBe(3);
    expect(call('2026-12-01T00:00:00Z')).toBe(4);
    expect(call('2026-12-01T03:00:00+05:00')).toBe(3);
    expect(call('2026-12-01')).toBe(4);
  });
});
