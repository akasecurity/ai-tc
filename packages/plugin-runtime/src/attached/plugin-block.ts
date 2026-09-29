import { readFileSync } from 'node:fs';

import { SQLITE_MIGRATIONS, StorePosturePlugin } from '@akasecurity/schema';

import { readInstalledVersion } from './install-record.ts';
import type { PolicyStore } from './policy-store.ts';

/**
 * The reporting artifact's own identity, supplied by the adapter that resolved
 * the gateway. The runtime cannot derive either half itself: each plugin ships
 * as its own npm package and reads its own installed manifest, so the package
 * name and version arrive from the adapter's side of the seam. `ossVersion` is
 * optional because no build records a separate core version today; absent, the
 * block reports it null.
 *
 * `installRoot` is the directory the host installed this plugin into, given
 * only by an adapter whose host keeps an install record for it
 * (readInstalledVersion). Given, the block reports that record's newest
 * version as `installedVersion`; omitted, the block leaves that key out.
 */
export type PluginBuildInfo = Pick<StorePosturePlugin, 'package' | 'version'> &
  Partial<Pick<StorePosturePlugin, 'ossVersion'>> & { installRoot?: string };

// One reader, one read: the manifest cannot change under a running process, so
// the first answer per manifest URL is cached — including a miss, which will
// not appear mid-process either. That bounds the cost to one fs read per
// process on every caller, which matters most on the host whose busiest hook
// evaluates its argument list on every invocation.
const manifestBuildCache = new Map<string, PluginBuildInfo | undefined>();

/**
 * Read a plugin's build identity from its installed manifest. Shared by the
 * plugin adapters' `build-info.ts` modules, which each supply only their own
 * two literals: the npm package name and where their host keeps the manifest.
 *
 * Best-effort: an unreadable or versionless manifest yields undefined and the
 * posture report goes out without a plugin block rather than failing anything.
 */
export function readManifestBuild(
  manifestUrl: URL,
  packageName: string,
): PluginBuildInfo | undefined {
  const key = manifestUrl.href;
  if (!manifestBuildCache.has(key)) {
    let build: PluginBuildInfo | undefined;
    try {
      const manifest = JSON.parse(readFileSync(manifestUrl, 'utf8')) as { version?: unknown };
      build =
        typeof manifest.version === 'string' && manifest.version.length > 0
          ? { package: packageName, version: manifest.version }
          : undefined;
    } catch {
      build = undefined;
    }
    manifestBuildCache.set(key, build);
  }
  return manifestBuildCache.get(key);
}

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
 * Two more members describe the running build, and are read here rather than
 * supplied by the adapter so every caller gets them with no plumbing:
 * `buildSchemaVersion`, the number of local-store migrations this build
 * carries, which is the version it migrates a store to. A snapshot whose store
 * count is above it usually describes a store a newer build migrated; that is
 * a hint, not a verdict. And `installedVersion`, what the host's install record
 * says is on disk, which leads `version` by one launch after an update; it is
 * read only for an adapter that names its `installRoot`.
 *
 * The two cache-derived fields are guarded against the wire shape's OWN bounds
 * (`StorePosturePlugin.shape.*`), not a re-spelled copy of them: the cache is
 * read tolerantly (`fetchedAtMs` accepts any number and an absent field reads
 * as 0; the bundle's `version` is an unbounded string), while the receiver
 * enforces the schema — and `reportStorePosture` sends the body unvalidated,
 * so an out-of-range value here would fail the WHOLE snapshot at the receiver,
 * costing the posture this block exists to enrich and charging the shared
 * forward breaker with the refusals. An unusable value reports null; the other
 * field still travels. A zero stamp also reports null — it is inside the
 * schema's bounds but means "never confirmed fresh", not an epoch. The final
 * parse is the belt over the two braces: a block the receiver would refuse is
 * dropped whole rather than sent.
 */
export function createPluginBlock(
  build: PluginBuildInfo,
  policyStore: Pick<PolicyStore, 'read'>,
): () => Promise<StorePosturePlugin | undefined> {
  return async () => {
    const cached = await policyStore.read();
    const fetchedAtMs = cached?.fetchedAtMs;
    const block: StorePosturePlugin = {
      package: build.package,
      version: build.version,
      ossVersion: build.ossVersion ?? null,
      policyBundleVersion:
        cached !== null &&
        StorePosturePlugin.shape.policyBundleVersion.safeParse(cached.bundle.version).success
          ? cached.bundle.version
          : null,
      policyFetchedAt:
        fetchedAtMs !== undefined &&
        fetchedAtMs > 0 &&
        StorePosturePlugin.shape.policyFetchedAt.safeParse(fetchedAtMs).success
          ? fetchedAtMs
          : null,
      ...(build.installRoot === undefined
        ? {}
        : { installedVersion: readInstalledVersion(build.installRoot) }),
      buildSchemaVersion: SQLITE_MIGRATIONS.length,
    };
    return StorePosturePlugin.safeParse(block).success ? block : undefined;
  };
}
