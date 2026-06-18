// Control-plane contracts for installing marketplace rule packs.
// Installing a published pack (by registry coordinate) snapshots that immutable
// version's rules and serves them in the policy bundle.
import { z } from 'zod';

import { Namespace, PackId, SemVer } from './registry.ts';

// The canonical open-source installed-pack shape AND the public OpenAPI component
// 'InstalledPack'. Metadata only — the snapshotted rules are not returned here
// (they reach the plugin via the policy bundle). Tenant-free — the public API
// contract carries no scoping columns.
export const InstalledPack = z
  .object({
    id: z.guid(),
    namespace: Namespace,
    packId: PackId,
    version: SemVer,
    name: z.string(),
    enabled: z.boolean().default(true),
    // UI-facing policy assignment — optional (nullable→optional pattern).
    // rowToInstalledPack includes the key only when policy_id is non-null, so
    // unassigned rows parse with policyId undefined (absent == unassigned).
    policyId: z.string().optional(),
  })
  .meta({ id: 'InstalledPack' });
export type InstalledPack = z.infer<typeof InstalledPack>;

// POST /v1/installed-packs — install (or re-install at a new version) a pack by
// its registry coordinate. The server fetches and snapshots the version's rules.
export const InstallPackRequest = z
  .object({
    namespace: Namespace,
    packId: PackId,
    version: SemVer,
  })
  .meta({ id: 'InstallPackRequest' });
export type InstallPackRequest = z.infer<typeof InstallPackRequest>;

// GET /v1/installed-packs
export const ListInstalledPacksResponse = z
  .object({
    items: z.array(InstalledPack),
  })
  .meta({ id: 'ListInstalledPacksResponse' });
export type ListInstalledPacksResponse = z.infer<typeof ListInstalledPacksResponse>;

// PATCH /v1/installed-packs/:namespace/:packId — partial update; at least one
// field must be present (enforced by the `.refine()` guard below).
export const PatchInstalledPackRequest = z
  .object({
    enabled: z.boolean().optional(),
    // null = unassign policy; string = assign a BuiltinPolicyId.
    // The service layer validates the string is in KNOWN_BUILTIN_IDS.
    policyId: z.string().nullable().optional(),
  })
  .refine((v) => Object.keys(v).some((k) => v[k as keyof typeof v] !== undefined), {
    message: 'At least one field must be provided',
  })
  .meta({ id: 'PatchInstalledPackRequest' });
export type PatchInstalledPackRequest = z.infer<typeof PatchInstalledPackRequest>;
