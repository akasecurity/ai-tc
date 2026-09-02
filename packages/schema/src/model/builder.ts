// The catalog builder. Declaring a model is one call with vendor-level defaults
// filled in, so adding a newly-released model is a single entry rather than a
// hand-copied block of eighteen fields, and a field left unstated inherits the
// vendor default rather than a neighbouring model's value.
//
// Usage (see `catalog.ts` for the real declarations):
//
//   const anthropic = vendor('anthropic', {
//     family: { id: 'claude', name: 'Claude' },
//     region: 'us',
//     retention: 'zero_retention',
//     training: { apiDefault: 'no', consumerDefault: 'no', ... },
//   });
//
//   anthropic.model('claude-opus-5', {
//     name: 'Claude Opus 5',
//     ctx: 1_000_000,
//     capability: 'reasoning',
//     price: anthropicPrice(5, 25, 0.5),
//     on: ['bedrock', 'vertex'],       // metadata resolves; price stays unknown
//   });
//
// The `price` argument is the FIRST-PARTY price and the builder attaches it
// only to the vendor's own platform. A reseller listed in `on` inherits the
// model's identity — same weights, same context window, same open-weights
// answer — with an unknown price and retention posture, since both are
// properties of the serving contract. Overriding either for a reseller takes
// the object form of `on`, which is more verbose than the bare string so that
// a reseller price reads as a decision in the diff.
import type {
  DataRetention,
  ModelCapability,
  ModelSeen,
  VendorTrainingPolicy,
} from './governance.ts';
import type { ModelPrice } from './pricing.ts';
import { ZERO_PRICE } from './pricing.ts';
import type { ModelHosting, ModelPlatform, ModelVendor } from './providers.ts';
import { firstPartyPlatformFor, hostingFor, isFirstParty } from './providers.ts';

/** What one platform offers for one model. */
export interface PlatformOffering {
  platform: ModelPlatform;
  hosting: ModelHosting;
  /** True when this is the vendor's own endpoint. */
  firstParty: boolean;
  /** `null` means the price is not verified for this platform — never 0, never a guess. */
  price: ModelPrice | null;
  /** `'unknown'` for any platform whose terms have not been read. */
  retention: DataRetention;
  /** Serving region, or `null` when unpinned/unverified. */
  region: string | null;
}

/** A fully-resolved catalog entry. Every field is present; unknowns are `null`. */
export interface ModelEntry {
  /** The vendor's canonical first-party model id. */
  id: string;
  vendor: ModelVendor;
  displayName: string;
  familyId: string;
  familyName: string;
  /** `null` is a curated "no flagged specialisation", not an unfilled field. */
  capability: ModelCapability | null;
  /** `null` when the published context window has not been verified. */
  contextWindow: number | null;
  /** `null` when the published output cap has not been verified. */
  maxOutputTokens: number | null;
  openWeights: boolean;
  /** Additional canonical spellings that mean this same model (e.g. a dated id). */
  aliases: readonly string[];
  /** The vendor's published training policy, or `null` if not curated. */
  training: VendorTrainingPolicy | null;
  /** Every platform known to serve this model, keyed by platform. */
  platforms: ReadonlyMap<ModelPlatform, PlatformOffering>;
  /**
   * The hosting band to assume when an observed id names no platform.
   *
   * A first-party model resolves to its own endpoint's band. An open-weights
   * model has no first-party endpoint and its id alone does not say whether it
   * ran on a third-party host or the caller's own hardware, so the band is a
   * CURATED call rather than a derived one — declared per model, and marked
   * estimated wherever it is rendered.
   */
  defaultHosting: ModelHosting;
  /**
   * Whether this is a model a deployment would deliberately onboard, or one
   * that is only ever reached by traffic. A legacy model nobody selects on
   * purpose is `'discovered'`, which puts it in the review queue.
   *
   * Curated rather than derived: being IN the catalog says the model is known,
   * not that anyone chose it.
   */
  seen: ModelSeen;
}

/** Vendor-level defaults every model from this vendor inherits. */
export interface VendorDefaults {
  family?: { id: string; name: string };
  region?: string | null;
  /** Retention on the vendor's OWN endpoint. Resellers always start `'unknown'`. */
  retention?: DataRetention;
  training?: VendorTrainingPolicy;
  openWeights?: boolean;
  defaultHosting?: ModelHosting;
}

/** A reseller/host entry with explicit overrides, for when its terms ARE known. */
export interface PlatformSpec {
  platform: ModelPlatform;
  price?: ModelPrice;
  retention?: DataRetention;
  region?: string | null;
}

/** How a model declares the platforms serving it. */
export type PlatformRef = ModelPlatform | PlatformSpec;

/** One model's declaration. Vendor defaults fill anything omitted. */
export interface ModelSpec {
  /** Human-facing name. */
  name: string;
  /** Published context window in tokens; omit when unverified. */
  ctx?: number;
  /** Published max output tokens; omit when unverified. */
  maxOut?: number;
  capability?: ModelCapability | null;
  /** The FIRST-PARTY price. Never applied to a reseller. */
  price?: ModelPrice;
  /** Platforms serving this model, besides the vendor's own. */
  on?: readonly PlatformRef[];
  /** Other ids that denote these same weights (dated forms, renames). */
  aliases?: readonly string[];
  /** Override the vendor's family for a model that sits outside it. */
  family?: { id: string; name: string };
  openWeights?: boolean;
  retention?: DataRetention;
  region?: string | null;
  /** Curated hosting band for an id that names no platform. Defaults to the
   * vendor's own endpoint's band, or `'gateway'` for a vendor with none. */
  defaultHosting?: ModelHosting;
  /** Defaults to `'managed'`; `'discovered'` for a model only traffic reaches. */
  seen?: ModelSeen;
}

function normalizeRef(ref: PlatformRef): PlatformSpec {
  return typeof ref === 'string' ? { platform: ref } : ref;
}

/**
 * A vendor-scoped model builder. Collects the models declared through it so a
 * catalog is assembled from explicit lists rather than from import side effects
 * — `catalog.ts` composes `vendor.models()` arrays, which keeps the build
 * order visible and makes the whole thing testable without module mocking.
 */
export class ModelVendorBuilder {
  readonly vendor: ModelVendor;

  private readonly defaults: VendorDefaults;

  private readonly entries: ModelEntry[] = [];

  constructor(vendor: ModelVendor, defaults: VendorDefaults = {}) {
    this.vendor = vendor;
    this.defaults = defaults;
  }

  /**
   * Declare a model. Returns the built entry (handy for tests and for
   * cross-referencing) and records it for `models()`.
   */
  model(id: string, spec: ModelSpec): ModelEntry {
    const family = spec.family ?? this.defaults.family ?? { id, name: spec.name };
    const ownPlatform = firstPartyPlatformFor(this.vendor);
    const openWeights = spec.openWeights ?? this.defaults.openWeights ?? false;
    const vendorRegion = spec.region ?? this.defaults.region ?? null;
    const vendorRetention = spec.retention ?? this.defaults.retention ?? 'unknown';

    const platforms = new Map<ModelPlatform, PlatformOffering>();

    // The vendor's own endpoint, when it has one. This is the only platform
    // that may carry `spec.price` and the vendor's retention posture.
    if (ownPlatform !== null) {
      platforms.set(ownPlatform, {
        platform: ownPlatform,
        hosting: hostingFor(ownPlatform),
        firstParty: true,
        price: spec.price ?? null,
        retention: vendorRetention,
        region: vendorRegion,
      });
    }

    for (const ref of spec.on ?? []) {
      const { platform, price, retention, region } = normalizeRef(ref);
      const firstParty = isFirstParty(this.vendor, platform);
      const hosting = hostingFor(platform);

      // Self-hosted weights: cost is a known zero and the data never leaves the
      // caller's infrastructure. Both are facts about the deployment, so they
      // are safe to assert without a per-platform price page.
      const isSelfHosted = hosting === 'local';

      platforms.set(platform, {
        platform,
        hosting,
        firstParty,
        price: price ?? (isSelfHosted ? ZERO_PRICE : firstParty ? (spec.price ?? null) : null),
        retention:
          retention ?? (isSelfHosted ? 'on_infrastructure' : firstParty ? vendorRetention : 'unknown'),
        region: region === undefined ? (firstParty ? vendorRegion : null) : region,
      });
    }

    // A vendor with a first-party endpoint answers this from that endpoint; a
    // vendor without one must state it, since the id carries no platform.
    const defaultHosting: ModelHosting =
      spec.defaultHosting ??
      this.defaults.defaultHosting ??
      (ownPlatform === null ? 'gateway' : hostingFor(ownPlatform));

    const entry: ModelEntry = {
      id,
      vendor: this.vendor,
      displayName: spec.name,
      familyId: family.id,
      familyName: family.name,
      capability: spec.capability ?? null,
      contextWindow: spec.ctx ?? null,
      maxOutputTokens: spec.maxOut ?? null,
      openWeights,
      aliases: Object.freeze([...(spec.aliases ?? [])]),
      training: this.defaults.training ?? null,
      platforms,
      defaultHosting,
      seen: spec.seen ?? 'managed',
    };

    this.entries.push(entry);
    return entry;
  }

  /** Every model declared through this builder, in declaration order. */
  models(): readonly ModelEntry[] {
    return this.entries;
  }
}

/** Start a vendor-scoped builder. */
export function vendor(v: ModelVendor, defaults: VendorDefaults = {}): ModelVendorBuilder {
  return new ModelVendorBuilder(v, defaults);
}
