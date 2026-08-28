import type { StorePosturePlugin } from '@akasecurity/schema';

import type { PolicyStore } from './policy-store.ts';

/**
 * The reporting artifact's own identity, supplied by the adapter that resolved
 * the gateway. The runtime cannot derive either half itself: each plugin ships
 * as its own npm package and reads its own installed manifest, so the package
 * name and version arrive from the adapter's side of the seam. `ossVersion` is
 * optional because no build records a separate core version today; absent, the
 * block reports it null.
 */
export type PluginBuildInfo = Pick<StorePosturePlugin, 'package' | 'version'> &
  Partial<Pick<StorePosturePlugin, 'ossVersion'>>;

/**
 * Produce the posture snapshot's `plugin` block: the build identity passed in,
 * plus policy freshness read from the on-disk policy cache — the SAME cache the
 * hook path scans with, so the report describes the bundle actually in force.
 *
 * The identity half is unconditional: a device that has never completed a
 * policy sync (the first report after `aka attach` most of all) still reports
 * which build is talking, with the policy fields null until a sync lands.
 * `read()` fail-opens to null on a missing or corrupt cache, so those nulls are
 * "no bundle cached", never an error surfaced.
 *
 * `policyFetchedAt` is guarded rather than copied: the cache's `fetchedAtMs` is
 * read tolerantly (any number parses, and an absent field reads as 0), and the
 * wire shape requires a positive epoch stamp — forwarding a zero or a mangled
 * value would fail the whole snapshot at the receiver, costing the posture the
 * block exists to enrich. An unusable stamp reports null; the bundle version
 * still travels.
 */
export function createPluginBlock(
  build: PluginBuildInfo,
  policyStore: Pick<PolicyStore, 'read'>,
): () => Promise<StorePosturePlugin> {
  return async () => {
    const cached = await policyStore.read();
    const fetchedAtMs = cached?.fetchedAtMs;
    return {
      package: build.package,
      version: build.version,
      ossVersion: build.ossVersion ?? null,
      policyBundleVersion: cached?.bundle.version ?? null,
      policyFetchedAt:
        fetchedAtMs !== undefined && Number.isSafeInteger(fetchedAtMs) && fetchedAtMs > 0
          ? fetchedAtMs
          : null,
    };
  };
}
