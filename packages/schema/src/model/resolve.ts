// Model-id resolution. One raw model string, as reported by a harness, resolved
// to a catalog entry plus the platform that served it.
//
// The same weights are spelled differently on every platform:
//
//   claude-opus-5                        Anthropic API
//   anthropic.claude-opus-5              Bedrock, base id
//   us.anthropic.claude-opus-5           Bedrock, cross-region inference
//   global.anthropic.claude-opus-5       Bedrock, global inference
//   claude-haiku-4-5@20251001            Vertex, dated
//   amazon.nova-2-lite-v1:0              Bedrock, versioned
//   meta-llama/llama-3-3-70b             gateway namespace
//
// Resolution is tolerant on READ: decorations are stripped in a fixed order and
// the remainder is matched against canonical ids and their aliases. Ids are
// never GENERATED from the canonical form — the spellings vary by vendor and by
// model generation, so producing one would be a guess.
//
// Lookups go through `Map`, so a raw model string can only ever match a key that
// was declared. A string like `constructor` or `__proto__` resolves to nothing.
import type { ModelEntry } from './builder.ts';
import type { ModelPlatform } from './providers.ts';
import { GEO_PREFIXES, PLATFORM_NAMESPACES } from './providers.ts';

/** What a raw model string resolved to. */
export interface ResolvedModel {
  /** The catalog entry, or `null` when the id matched nothing. */
  entry: ModelEntry | null;
  /** The canonical id the raw string reduced to. */
  canonicalId: string;
  /** The platform inferred from the id's decorations, when it names one. */
  platform: ModelPlatform | null;
  /** The raw string exactly as reported. */
  raw: string;
}

const GEO_PREFIX_RE = new RegExp(`^(?:${GEO_PREFIXES.join('|')})\\.`, 'u');
const NAMESPACE_DOT_RE = new RegExp(`^(?:${PLATFORM_NAMESPACES.join('|')})\\.`, 'u');
const NAMESPACE_SLASH_RE = new RegExp(`^(?:${PLATFORM_NAMESPACES.join('|')})/`, 'iu');
const GATEWAY_VENDOR_SLASH_RE = /^[a-z0-9][\w.-]*\//iu;
const BEDROCK_VERSION_RE = /-v\d+:\d+$/u;
const BEDROCK_REVISION_RE = /:\d+$/u;
const VERTEX_VERSION_RE = /@[\w-]+$/u;
const DATED_SUFFIX_RE = /-\d{8}$/u;

/**
 * Strip the decorations a serving platform adds, in the order they nest.
 * Returns the bare id plus the platform its decorations implied, if any.
 */
export function stripPlatformDecorations(model: string): {
  id: string;
  platform: ModelPlatform | null;
} {
  let id = model.trim();
  let platform: ModelPlatform | null = null;

  // A geo prefix is unambiguously Bedrock cross-region/global inference.
  if (GEO_PREFIX_RE.test(id)) {
    id = id.replace(GEO_PREFIX_RE, '');
    platform = 'bedrock';
  }

  // A dotted vendor namespace is the Bedrock base-id form.
  if (NAMESPACE_DOT_RE.test(id)) {
    id = id.replace(NAMESPACE_DOT_RE, '');
    platform ??= 'bedrock';
  }

  // A `-vN:M` or trailing `:M` revision is Bedrock's model version.
  if (BEDROCK_VERSION_RE.test(id)) {
    id = id.replace(BEDROCK_VERSION_RE, '');
    platform ??= 'bedrock';
  } else if (BEDROCK_REVISION_RE.test(id)) {
    id = id.replace(BEDROCK_REVISION_RE, '');
    platform ??= 'bedrock';
  }

  // `@version` is Vertex's separator.
  if (VERTEX_VERSION_RE.test(id)) {
    id = id.replace(VERTEX_VERSION_RE, '');
    platform ??= 'vertex';
  }

  // A slash-separated namespace is a gateway spelling. The known-vendor form is
  // stripped without implying a platform, because several gateways use it and
  // the id alone does not say which.
  if (NAMESPACE_SLASH_RE.test(id)) {
    id = id.replace(NAMESPACE_SLASH_RE, '');
  } else if (GATEWAY_VENDOR_SLASH_RE.test(id)) {
    id = id.replace(GATEWAY_VENDOR_SLASH_RE, '');
  }

  return { id, platform };
}

/** An index over a set of entries, keyed by canonical id and by alias. */
export interface ModelIndex {
  byId: ReadonlyMap<string, ModelEntry>;
  entries: readonly ModelEntry[];
}

/**
 * Build a lookup index. An alias that collides with another model's canonical id
 * loses — a declared id always wins over an alias, so an alias can never
 * shadow a real model.
 */
export function buildModelIndex(entries: readonly ModelEntry[]): ModelIndex {
  const byId = new Map<string, ModelEntry>();
  for (const entry of entries) byId.set(entry.id, entry);
  for (const entry of entries) {
    for (const alias of entry.aliases) {
      if (!byId.has(alias)) byId.set(alias, entry);
    }
  }
  return { byId, entries: Object.freeze([...entries]) };
}

/**
 * Resolve a raw model string against an index.
 *
 * Matching is attempted most-specific first: the raw string exactly as reported,
 * then with platform decorations stripped, then with a trailing dated suffix
 * removed. The dated form is tried LAST so a model whose canonical id carries a
 * date (Anthropic's `claude-haiku-4-5-20251001` is one) matches itself before
 * the shorter form is considered.
 *
 * `entry` is `null` when nothing matched, and `canonicalId` is then the raw
 * string unchanged. That is the honest answer for a model this catalog does not
 * carry, and callers render it as unknown rather than falling back to a
 * lookalike.
 */
export function resolveModel(raw: string, index: ModelIndex): ResolvedModel {
  const exact = index.byId.get(raw);
  if (exact !== undefined) {
    return { entry: exact, canonicalId: raw, platform: null, raw };
  }

  const { id, platform } = stripPlatformDecorations(raw);
  const stripped = index.byId.get(id);
  if (stripped !== undefined) {
    return { entry: stripped, canonicalId: id, platform, raw };
  }

  if (DATED_SUFFIX_RE.test(id)) {
    const undated = id.replace(DATED_SUFFIX_RE, '');
    const byDate = index.byId.get(undated);
    if (byDate !== undefined) {
      return { entry: byDate, canonicalId: undated, platform, raw };
    }
  }

  // Nothing matched. Report the id exactly as it arrived rather than the
  // stripped form: the decorations were removed to ATTEMPT a match, and a
  // stripped id for a model the catalog does not carry is a rewrite nothing
  // justifies.
  return { entry: null, canonicalId: raw, platform, raw };
}
