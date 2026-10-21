// Contracts for the in-place egress extraction pass: what the pure extractor
// produces and what the store writer consumes. The read-side Data Shares shapes
// live in ./shares.ts; these are the write-side boundary between the extraction
// module, both scan pipelines, and the persistence writer.
import * as z from 'zod';

import { SIGHTING_TOKEN_ANCHORED, SightingAliases } from './event.ts';
import { VariableName } from './finding.ts';
import {
  DataClass,
  DestinationKind,
  DestinationNetwork,
  HttpMethod,
  ShareTrustLevel,
  Transport,
} from './shares.ts';

// Package ecosystems the manifest scan can attribute an SDK dependency to.
export const EgressEcosystem = z
  .enum(['npm', 'pypi', 'go', 'maven', 'rubygems', 'cargo', 'composer', 'nuget'])
  .meta({ id: 'EgressEcosystem' });
export type EgressEcosystem = z.infer<typeof EgressEcosystem>;

// One known egress provider: recognition (host suffixes + SDK names per ecosystem)
// and what to record for it.
export const ProviderRegistryEntry = z
  .object({
    id: z.string(),
    name: z.string(),
    category: z.string(),
    /** Suffix-matched: 'stripe.com' matches api.stripe.com, never evilstripe.com. */
    hostSuffixes: z.array(z.string()).min(1),
    /** Canonical API base URL recorded for manifest-derived (method 'SDK') endpoints. */
    apiBase: z.string(),
    /** Most-sensitive first; index 0 becomes the endpoint dataClass. */
    defaultDataClasses: z.array(DataClass).min(1),
    /** SDK identifiers per ecosystem ('go' prefix-matched by path, 'maven' by group-id prefix). */
    sdks: z.partialRecord(EgressEcosystem, z.array(z.string())),
  })
  .meta({ id: 'ProviderRegistryEntry' });
export type ProviderRegistryEntry = z.infer<typeof ProviderRegistryEntry>;

// One source location that produced an egress hit. `file` is a posix path
// relative to the worktree root (git) or to the walked root directory (non-git).
// Both pipelines relativize the same way, so the same file yields the same path
// whichever one recorded it.
export const EgressCallSiteHit = z
  .object({
    file: z.string(),
    line: z.number().int().positive(),
    snippet: z.string(),
    dynamic: z.boolean(),
    vendored: z.boolean(),
  })
  .meta({ id: 'EgressCallSiteHit' });
export type EgressCallSiteHit = z.infer<typeof EgressCallSiteHit>;

/** The most credential references one call site carries. */
export const CREDENTIAL_REFS_PER_CALL_SITE_MAX = 8;

/**
 * A credential a call site uses, found inside the call expression: a secret
 * written in it, as its sighting token, or an environment variable it reads, by
 * name. Never a value, an excerpt or a masked value.
 */
export const EgressCredentialRef = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('literal'),
      token: z.string().regex(SIGHTING_TOKEN_ANCHORED),
      aliases: SightingAliases.optional(),
      ruleId: z.string().min(1).max(256),
    })
    .strict(),
  z.object({ kind: z.literal('variable'), variableName: VariableName.min(1) }).strict(),
]);
export type EgressCredentialRef = z.infer<typeof EgressCredentialRef>;

export const EgressCredentialRefs = z
  .array(EgressCredentialRef)
  .max(CREDENTIAL_REFS_PER_CALL_SITE_MAX);

// One fully resolved egress observation, ready for the store writer.
export const ResolvedEgressHit = z
  .object({
    host: z.string(),
    kind: DestinationKind,
    name: z.string(),
    category: z.string(),
    /** The id of the matched provider catalog entry; null for internal/external/ip destinations. */
    providerId: z.string().nullable(),
    trust: ShareTrustLevel,
    network: DestinationNetwork.nullable(),
    method: HttpMethod,
    transport: Transport,
    url: z.string(),
    template: z.boolean(),
    dataClass: DataClass,
    site: EgressCallSiteHit,
    /** Held in memory for the forward only; the store writes none of it. */
    credentialRefs: EgressCredentialRefs.optional(),
  })
  .meta({ id: 'ResolvedEgressHit' });
export type ResolvedEgressHit = z.infer<typeof ResolvedEgressHit>;

// How a write reconciles previously stored rows.
// 'walk': the caller walked the complete subtree under walkedPrefix ('' = project
//   root; a file target passes its own relative path) — stored call sites under
//   that prefix are replaced. Dot-path files are excluded from that replacement:
//   this walker never descends into them, so it must not delete rows only the
//   other walker can re-create.
// 'ledger': replace exactly scannedFiles ∪ deletedFiles; everything else is
//   preserved (the scanner's ledger-skip path).
export const EgressReconcile = z
  .discriminatedUnion('mode', [
    z.object({ mode: z.literal('walk'), walkedPrefix: z.string() }),
    z.object({
      mode: z.literal('ledger'),
      scannedFiles: z.array(z.string()),
      deletedFiles: z.array(z.string()),
    }),
  ])
  .meta({ id: 'EgressReconcile' });
export type EgressReconcile = z.infer<typeof EgressReconcile>;

// One project's egress-recording unit.
export const RecordProjectEgressInput = z
  .object({
    /** Stable reconcile key: 'git:<repo identity>' or 'path:<abs root>' (non-git). */
    projectKey: z.string().min(1),
    /** Display name only — never keys reconciliation. */
    project: z.string(),
    projectId: z.string().nullable(),
    reconcile: EgressReconcile,
    hits: z.array(ResolvedEgressHit),
  })
  .meta({ id: 'RecordProjectEgressInput' });
export type RecordProjectEgressInput = z.infer<typeof RecordProjectEgressInput>;

// What one write did — live per-project totals (computed via call-site joins;
// destinations/endpoints have no project column).
export const EgressWriteSummary = z
  .object({
    destinations: z.number().int().nonnegative(),
    endpoints: z.number().int().nonnegative(),
    callSites: z.number().int().nonnegative(),
    truncated: z.boolean(),
    /**
     * Files the cap dropped whole. Their stored rows were left untouched, so a
     * ledger-keeping caller must withhold their ledger entries and read them
     * again next scan.
     */
    droppedFiles: z.array(z.string()).default([]),
  })
  .meta({ id: 'EgressWriteSummary' });
export type EgressWriteSummary = z.infer<typeof EgressWriteSummary>;
