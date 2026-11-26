// A catalog overlay: model facts published after this release, merged over the
// bundled catalog by `mergeCatalog`. The merge only adds or replaces facts; it
// never removes a model, so every id the bundled catalog resolves keeps
// resolving.
//
// Provenance: every fact an overlay states names the page it was read from and
// the day it was read. Model-level fields are sourced in the model's
// `provenance` map, keyed by field name. An offering's own terms (`prices`,
// `retention`, `region`) are sourced in that offering's `provenance`, so two
// platforms' terms can cite two different pages.
//
// Price rows: an overlay row with the same `effectiveFrom` as a bundled row
// replaces it. Cost is computed when it is read, so a replaced row also changes
// the cost already reported for the days it covers; a corrected reference
// price wins.
import * as z from 'zod';

import type { ModelEntry, PlatformOffering, VendorDefaults } from './builder.ts';
import {
  buildModelEntry,
  declaredOffering,
  freezeModelEntry,
  platformOffering,
} from './builder.ts';
import { VENDOR_DEFAULTS } from './catalog.ts';
import { DataRetention, ModelCapability } from './governance.ts';
import type { PricePoint } from './pricing.ts';
import { ModelPrice } from './pricing.ts';
import { ModelPlatform, ModelVendor } from './providers.ts';

/** The overlay format major version this code reads. */
export const CATALOG_OVERLAY_FORMAT_VERSION = 1;

/** Where a fact was read, and on which day. */
export const OverlaySource = z.object({ source: z.url(), readAt: z.iso.date() });
export type OverlaySource = z.infer<typeof OverlaySource>;

/** One dated price row. */
export const OverlayPriceRow = z.object({
  effectiveFrom: z.iso.date(),
  price: ModelPrice,
});
export type OverlayPriceRow = z.infer<typeof OverlayPriceRow>;

const OverlayOfferingFields = z.object({
  platform: z.string().min(1),
  retention: DataRetention.optional(),
  region: z.string().nullable().optional(),
  prices: z.array(OverlayPriceRow).optional(),
  provenance: OverlaySource.optional(),
});

/** The offering fields that state a term and so need the offering's provenance. */
const SOURCED_OFFERING_FIELDS = ['retention', 'region', 'prices'] as const;

/**
 * One platform's terms for a model. `platform` is a plain string so a value
 * this code does not know survives parsing; the merge skips its model.
 * `provenance` is required when the offering states any of its terms, and
 * no two price rows may share an `effectiveFrom`.
 */
export const OverlayOffering = OverlayOfferingFields.superRefine((offering, ctx) => {
  const stated = SOURCED_OFFERING_FIELDS.filter((key) => offering[key] !== undefined);
  if (stated.length > 0 && offering.provenance === undefined) {
    ctx.addIssue({
      code: 'custom',
      path: ['provenance'],
      message: `offering states ${stated.join(', ')} but has no provenance`,
    });
  }
  const days = new Set<string>();
  (offering.prices ?? []).forEach((row, i) => {
    if (days.has(row.effectiveFrom)) {
      ctx.addIssue({
        code: 'custom',
        path: ['prices', i, 'effectiveFrom'],
        message: `two price rows share effectiveFrom '${row.effectiveFrom}'`,
      });
    }
    days.add(row.effectiveFrom);
  });
});
export type OverlayOffering = z.infer<typeof OverlayOffering>;

/** Lifecycle facts. An omitted field keeps the bundled value; `null` clears it. */
export const OverlayLifecycle = z.object({
  deprecatedAt: z.iso.date().nullable().optional(),
  retiresAt: z.iso.date().nullable().optional(),
  replacement: z.string().min(1).nullable().optional(),
});
export type OverlayLifecycle = z.infer<typeof OverlayLifecycle>;

const OverlayModelFields = z.object({
  id: z.string().min(1),
  vendor: z.string().min(1),
  name: z.string().min(1).optional(),
  family: z.object({ id: z.string().min(1), name: z.string().min(1) }).optional(),
  ctx: z.number().int().positive().optional(),
  maxOut: z.number().int().positive().optional(),
  capability: ModelCapability.nullable().optional(),
  aliases: z.array(z.string().min(1)).optional(),
  openWeights: z.boolean().optional(),
  lifecycle: OverlayLifecycle.optional(),
  offerings: z.array(OverlayOffering).optional(),
  provenance: z.record(z.string(), OverlaySource),
});

/** The overlay fields that state a fact and so need a provenance entry. */
const SOURCED_FIELDS: ReadonlySet<string> = new Set(
  Object.keys(OverlayModelFields.shape).filter(
    (key) => key !== 'id' && key !== 'vendor' && key !== 'provenance',
  ),
);

/**
 * One model's facts. An omitted field keeps the bundled value. `vendor` is a
 * plain string for the same reason as `OverlayOffering.platform`.
 * `provenance` names, for every stated field, the page it was read from and
 * when; its keys are limited to the model's field names. Its `offerings` entry
 * sources which platforms serve the model; each offering sources its own terms.
 */
export const OverlayModel = OverlayModelFields.superRefine((model, ctx) => {
  for (const key of Object.keys(model.provenance)) {
    if (!SOURCED_FIELDS.has(key)) {
      ctx.addIssue({
        code: 'custom',
        path: ['provenance', key],
        message: `provenance names '${key}', which is not a model field`,
      });
    }
  }
  for (const key of SOURCED_FIELDS) {
    if (model[key as keyof typeof model] !== undefined && !Object.hasOwn(model.provenance, key)) {
      ctx.addIssue({
        code: 'custom',
        path: ['provenance', key],
        message: `stated field '${key}' has no provenance`,
      });
    }
  }
});
export type OverlayModel = z.infer<typeof OverlayModel>;

export const CatalogOverlay = z.object({
  formatVersion: z.number().int(),
  version: z.number().int().positive(),
  publishedAt: z.iso.datetime(),
  models: z.array(OverlayModel),
});
export type CatalogOverlay = z.infer<typeof CatalogOverlay>;

/** Thrown when an overlay's `formatVersion` is not the one this code reads. */
export class UnsupportedOverlayFormatError extends Error {
  readonly formatVersion: number;

  constructor(formatVersion: number) {
    super(
      `catalog overlay format ${String(formatVersion)} is not supported; ` +
        `this release reads format ${String(CATALOG_OVERLAY_FORMAT_VERSION)}`,
    );
    this.name = 'UnsupportedOverlayFormatError';
    this.formatVersion = formatVersion;
  }
}

/** Overlay rows replace a bundled row with the same `effectiveFrom` and append otherwise. */
function mergePriceRows(
  existing: readonly PricePoint[],
  added: readonly OverlayPriceRow[],
): PricePoint[] {
  const byDay = new Map<string | null, PricePoint>();
  for (const row of existing) byDay.set(row.effectiveFrom, row);
  for (const row of added) {
    byDay.set(row.effectiveFrom, {
      effectiveFrom: row.effectiveFrom,
      price: freezePrice(row.price),
    });
  }
  return [...byDay.values()];
}

function freezePrice(price: ModelPrice): ModelPrice {
  return Object.freeze({
    ...price,
    longContext: price.longContext === null ? null : Object.freeze({ ...price.longContext }),
  });
}

function mergeOffering(
  entry: ModelEntry,
  defaults: VendorDefaults,
  platform: ModelPlatform,
  offering: OverlayOffering,
): PlatformOffering {
  const base =
    entry.platforms.get(platform) ??
    declaredOffering(
      entry.vendor,
      {
        platform,
        ...(offering.retention === undefined ? {} : { retention: offering.retention }),
        ...(offering.region === undefined ? {} : { region: offering.region }),
      },
      {
        firstPartyPrices: [],
        retention: defaults.retention ?? 'unknown',
        region: defaults.region ?? null,
      },
    );
  return platformOffering({
    platform: base.platform,
    hosting: base.hosting,
    firstParty: base.firstParty,
    prices: mergePriceRows(base.prices, offering.prices ?? []),
    retention: offering.retention ?? base.retention,
    region: offering.region === undefined ? base.region : offering.region,
  });
}

function lifecycleValue(stated: string | null | undefined, bundled: string | null): string | null {
  return stated === undefined ? bundled : stated;
}

function applyModel(
  entry: ModelEntry,
  model: OverlayModel,
  platforms: readonly ModelPlatform[],
  defaults: VendorDefaults,
): ModelEntry {
  const offerings = new Map(entry.platforms);
  (model.offerings ?? []).forEach((offering, i) => {
    const platform = platforms[i];
    if (platform !== undefined) {
      offerings.set(platform, mergeOffering(entry, defaults, platform, offering));
    }
  });

  return freezeModelEntry({
    ...entry,
    displayName: model.name ?? entry.displayName,
    familyId: model.family?.id ?? entry.familyId,
    familyName: model.family?.name ?? entry.familyName,
    capability: model.capability === undefined ? entry.capability : model.capability,
    contextWindow: model.ctx ?? entry.contextWindow,
    maxOutputTokens: model.maxOut ?? entry.maxOutputTokens,
    openWeights: model.openWeights ?? entry.openWeights,
    aliases: [...new Set([...entry.aliases, ...(model.aliases ?? [])])],
    platforms: offerings,
    deprecatedAt: lifecycleValue(model.lifecycle?.deprecatedAt, entry.deprecatedAt),
    retiresAt: lifecycleValue(model.lifecycle?.retiresAt, entry.retiresAt),
    replacement: lifecycleValue(model.lifecycle?.replacement, entry.replacement),
  });
}

/** Thrown when the overlays passed to `mergeCatalog` are not in ascending `version` order. */
export class OverlayVersionOrderError extends Error {
  readonly previous: number;

  readonly version: number;

  constructor(previous: number, version: number) {
    super(
      `catalog overlay version ${String(version)} follows version ${String(previous)}; ` +
        'overlays must be passed with strictly ascending versions',
    );
    this.name = 'OverlayVersionOrderError';
    this.previous = previous;
    this.version = version;
  }
}

/**
 * Merges overlays over the bundled entries, in the order given; where two
 * overlays state the same fact, the later one wins. An overlay model with a new
 * id is added as `'discovered'`; one with a known id has its stated fields
 * replaced, its offerings' price rows appended and its new offerings added. A
 * model whose vendor or platform this code does not know, or whose vendor
 * differs from the bundled entry's, is listed in `skipped` and leaves the
 * catalog unchanged.
 *
 * Every overlay must be in `CATALOG_OVERLAY_FORMAT_VERSION`, and their
 * `version`s must be strictly ascending: callers pass overlays oldest first
 * and refuse a version regression before calling. `publishedAt` is not read.
 *
 * @throws UnsupportedOverlayFormatError when an overlay's `formatVersion` is
 *   not `CATALOG_OVERLAY_FORMAT_VERSION`.
 * @throws OverlayVersionOrderError when an overlay's `version` is not greater
 *   than the one before it.
 */
export function mergeCatalog(
  bundled: readonly ModelEntry[],
  overlays: readonly CatalogOverlay[],
): { entries: readonly ModelEntry[]; skipped: readonly string[] } {
  let previous: number | null = null;
  for (const overlay of overlays) {
    if (overlay.formatVersion !== CATALOG_OVERLAY_FORMAT_VERSION) {
      throw new UnsupportedOverlayFormatError(overlay.formatVersion);
    }
    if (previous !== null && overlay.version <= previous) {
      throw new OverlayVersionOrderError(previous, overlay.version);
    }
    previous = overlay.version;
  }

  const entries = new Map<string, ModelEntry>(bundled.map((entry) => [entry.id, entry]));
  const skipped: string[] = [];

  for (const model of overlays.flatMap((overlay) => overlay.models)) {
    const vendor = ModelVendor.safeParse(model.vendor);
    const platforms = (model.offerings ?? []).map((o) => ModelPlatform.safeParse(o.platform));
    const existing = entries.get(model.id);
    if (
      !vendor.success ||
      platforms.some((p) => !p.success) ||
      (existing !== undefined && existing.vendor !== vendor.data)
    ) {
      skipped.push(model.id);
      continue;
    }

    const defaults = VENDOR_DEFAULTS.get(vendor.data) ?? {};
    const base =
      existing ??
      buildModelEntry(vendor.data, defaults, model.id, {
        name: model.name ?? model.id,
        seen: 'discovered',
      });
    entries.set(
      model.id,
      applyModel(
        base,
        model,
        platforms.flatMap((p) => (p.success ? [p.data] : [])),
        defaults,
      ),
    );
  }

  return { entries: Object.freeze([...entries.values()]), skipped: Object.freeze(skipped) };
}
