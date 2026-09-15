// The esbuild entry the CLI shim (scripts/sanitize-capture.mjs) bundles. This
// directory is a DEV TOOL — nothing under src/ outside src/sanitize/ may import
// it, so the sanitiser never rides along in the page bundle.
export * from './classify.ts';
export * from './detector.ts';
export * from './sanitize-capture.ts';

import { ADAPTERS } from '../providers/registry.ts';
import type { ProviderAdapter } from '../providers/types.ts';
import { assertDeclarableTokens } from './classify.ts';

/** The adapter's own hostnames, or [] for a site no adapter drives. */
export function hostnamesForSite(site: string): readonly string[] {
  const adapter = ADAPTERS.find((a) => a.id === site);
  return adapter ? adapter.hostnames : [];
}

/**
 * The exact protocol tokens `site`'s adapter declares, VALIDATED.
 *
 * THROWS on an unusable declaration rather than filtering it out — see
 * `assertDeclarableTokens`'s own doc comment for why silently dropping one is
 * the worse failure. A site no adapter drives yields an empty set, mirroring
 * `hostnamesForSite`.
 *
 * Split from `protocolTokensForSite` — mirroring `toTapEndpoints(adapters)`
 * in src/tap-endpoints.ts, the existing precedent in this package for a
 * registry-derived table whose validator has to be drivable against a
 * synthetic array — so the validator can be exercised in tests without
 * routing through the real (today entirely non-declaring) registry.
 */
export function resolveProtocolTokens(
  adapters: readonly ProviderAdapter[],
  site: string,
): ReadonlySet<string> {
  const adapter = adapters.find((a) => a.id === site);
  if (adapter === undefined) return new Set();
  assertDeclarableTokens(site, adapter.protocolTokens);
  return new Set(adapter.protocolTokens);
}

/** `resolveProtocolTokens` over the real adapter registry. */
export function protocolTokensForSite(site: string): ReadonlySet<string> {
  return resolveProtocolTokens(ADAPTERS, site);
}
