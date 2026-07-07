import type {
  ListPoliciesResponse,
  PolicyDetail,
  PolicyKind,
  PolicyStatsResponse,
} from '@akasecurity/schema';
import { BUILTIN_ORDER, BUILTIN_POLICIES, KNOWN_BUILTIN_IDS } from '@akasecurity/schema';

import type { PolicyCatalogReadPort } from '../ports.ts';
import type { SqliteInstalledPacksRepository } from './installed-packs.ts';

/**
 * OSS Policies page reads — the built-in policy catalog (monitor/warn/redact/
 * block) with live "used by N detections" counts joined from installed_packs.
 * Serves getBuiltinList / getStats /
 * getBuiltinDetail over the tenant-free local store, reusing the shared
 * @akasecurity/schema catalog (BUILTIN_POLICIES / BUILTIN_ORDER) so every
 * surface renders identical detail. The catalog IS the list (there are no
 * custom policies), so `kind='custom'` returns an empty list.
 */
export class SqlitePolicyCatalogRepository implements PolicyCatalogReadPort {
  constructor(
    private readonly packs: Pick<
      SqliteInstalledPacksRepository,
      'countsByPolicyId' | 'listByPolicyId'
    >,
  ) {}

  getPolicyList(kind?: PolicyKind): Promise<ListPoliciesResponse> {
    if (kind === 'custom') return Promise.resolve({ items: [] });
    // One grouped scan (not a COUNT per id) — the map attributes NULL-policy
    // packs to 'monitor', matching the Detections views.
    const counts = this.packs.countsByPolicyId();
    const items = BUILTIN_ORDER.map((id) => ({
      id,
      kind: 'builtin' as const,
      name: BUILTIN_POLICIES[id].name,
      enabled: true,
      usedByCount: counts.get(id) ?? 0,
    }));
    return Promise.resolve({ items });
  }

  getPolicyStats(): Promise<PolicyStatsResponse> {
    // Sum the same grouped counts over the canonical id set (not BUILTIN_ORDER,
    // which is display order), so a future archetype is never silently
    // undercounted — one scan, consistent with getPolicyList's attribution.
    const counts = this.packs.countsByPolicyId();
    const detectionsGoverned = KNOWN_BUILTIN_IDS.reduce(
      (sum, id) => sum + (counts.get(id) ?? 0),
      0,
    );
    const builtin = KNOWN_BUILTIN_IDS.length;
    return Promise.resolve({ policies: builtin, builtin, custom: 0, detectionsGoverned });
  }

  getPolicyDetail(id: string): Promise<PolicyDetail | null> {
    const builtinId = KNOWN_BUILTIN_IDS.find((bid) => bid === id);
    if (builtinId === undefined) return Promise.resolve(null);
    const catalog = BUILTIN_POLICIES[builtinId];
    return Promise.resolve({
      specVersion: 1,
      id,
      kind: 'builtin' as const,
      name: catalog.name,
      enabled: true,
      description: catalog.description,
      usedBy: this.packs.listByPolicyId(id),
    });
  }
}
