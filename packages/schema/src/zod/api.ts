// API contract: request/response Zod shapes for every route.
//
// Schema ids: object schemas used as a request *body* or a *response* carry a
// `.meta({ id })` so the OpenAPI generator emits them once under
// `components/schemas/<id>` and references them by `$ref`. Query/path schemas are
// intentionally NOT given ids — the generator expands their properties into
// individual OpenAPI `parameters`, which cannot be a `$ref`, so they stay inline.
import { z } from 'zod';

import { Event, IngestBatch } from './event.ts';
import { Finding } from './finding.ts';
import {
  AssetDetail,
  ConnectProjectBody,
  FileDetail,
  GetHarnessEventsQuery,
  GetProjectFileQuery,
  GetProjectTreeQuery,
  HarnessEventsResponse,
  InventoryStats,
  ListAssetsQuery,
  ListAssetsResponse,
  ListHarnessesResponse,
  ListProjectsResponse,
  ProjectSummary,
  ProjectTreeResponse,
  RescanResponse,
  SetFileAccessBody,
  SetFileAccessResponse,
  SetMcpTrustBody,
} from './inventory.ts';
import { AuditEventInput, InventoryContext } from './meta.ts';
import {
  Policy,
  PolicyBundle,
  PolicyDetail,
  PolicyListItem,
  PolicyStatsResponse,
} from './policy.ts';

// Max page size accepted by the list endpoints (events, findings). Exported so
// clients clamp their requested limit to it — asking for more is a 400.
export const LIST_QUERY_MAX_LIMIT = 200;

// GET /v1/events
export const ListEventsQuery = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(LIST_QUERY_MAX_LIMIT).default(50),
  sourceTool: z.string().optional(),
  kind: z.string().optional(),
  from: z.iso.datetime().optional(),
  to: z.iso.datetime().optional(),
});
export type ListEventsQuery = z.infer<typeof ListEventsQuery>;
export const ListEventsResponse = z
  .object({
    items: z.array(Event),
    nextCursor: z.string().nullable(),
  })
  .meta({ id: 'ListEventsResponse' });
export type ListEventsResponse = z.infer<typeof ListEventsResponse>;

// IngestRequest aliases IngestBatch, which registers the shared `IngestBatch`
// component once (see event.ts). IngestResponse reports how many events were
// accepted and how many were dropped as duplicates.
export const IngestRequest = IngestBatch;
export type IngestRequest = z.infer<typeof IngestRequest>;
export const IngestResponse = z
  .object({
    accepted: z.number().int(),
    duplicates: z.number().int(),
  })
  .meta({ id: 'IngestResponse' });
export type IngestResponse = z.infer<typeof IngestResponse>;

// GET /v1/findings
export const ListFindingsQuery = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(LIST_QUERY_MAX_LIMIT).default(50),
  severity: z.string().optional(),
  category: z.string().optional(),
  eventId: z.guid().optional(),
});
export type ListFindingsQuery = z.infer<typeof ListFindingsQuery>;
export const ListFindingsResponse = z
  .object({
    items: z.array(Finding),
    nextCursor: z.string().nullable(),
  })
  .meta({ id: 'ListFindingsResponse' });
export type ListFindingsResponse = z.infer<typeof ListFindingsResponse>;

// GET /v1/policies — the built-in policy catalog. Flipped to PolicyListItem[] in
// lockstep with the route switching to PoliciesService.getBuiltinList(), which
// returns exactly this shape, so the Zod response serializer stays consistent.
export const ListPoliciesResponse = z
  .object({ items: z.array(PolicyListItem) })
  .meta({ id: 'ListPoliciesResponse' });
export type ListPoliciesResponse = z.infer<typeof ListPoliciesResponse>;

// GET /v1/policies/stats
// Alias — component registered once as `PolicyStatsResponse` (see policy.ts).
export const GetPolicyStatsResponse = PolicyStatsResponse;
export type GetPolicyStatsResponse = z.infer<typeof GetPolicyStatsResponse>;

// GET /v1/policies/:id
// Alias — component registered once as `PolicyDetail` (see policy.ts).
export const GetPolicyResponse = PolicyDetail;
export type GetPolicyResponse = z.infer<typeof GetPolicyResponse>;

// POST /v1/policies
// Request omits the server-derived id (the tenant-free Policy carries no
// scoping columns to omit).
export const CreatePolicyRequest = Policy.omit({ id: true }).meta({
  id: 'CreatePolicyRequest',
});
export type CreatePolicyRequest = z.infer<typeof CreatePolicyRequest>;
// Response is the tenant-free Policy — component registered once as `Policy` (see
// policy.ts). The public API contract carries no scoping columns.
export const CreatePolicyResponse = Policy;
export type CreatePolicyResponse = z.infer<typeof CreatePolicyResponse>;

// PUT /v1/policies/:id
export const UpdatePolicyRequest = Policy.partial()
  .required({ id: true })
  .meta({ id: 'UpdatePolicyRequest' });
export type UpdatePolicyRequest = z.infer<typeof UpdatePolicyRequest>;
// Response is the tenant-free Policy — component registered once as `Policy` (see
// policy.ts). The public API contract carries no scoping columns.
export const UpdatePolicyResponse = Policy;
export type UpdatePolicyResponse = z.infer<typeof UpdatePolicyResponse>;

// GET /v1/policy-bundle
// Alias of PolicyBundle — component registered once as `PolicyBundle` (see policy.ts).
export const PolicyBundleResponse = PolicyBundle;
export type PolicyBundleResponse = z.infer<typeof PolicyBundleResponse>;

// ── Meta data model ingest ─────────────────────────────────────────────────

// POST /v1/inventory — idempotent upsert of a session's inventory dimensions.
// Body is an InventoryContext (host/harness/project; the org account is derived
// server-side from auth); response is the resolved content-addressed ids.
// IngestInventoryRequest aliases InventoryContext — the component is registered
// once as `InventoryContext` (see meta.ts) and refs there. Response is
// ResolvedInventory (also registered in meta.ts).
export const IngestInventoryRequest = InventoryContext;
export type IngestInventoryRequest = z.infer<typeof IngestInventoryRequest>;

// POST /v1/audit-events — append one audit-event fact (e.g. a Session root).
// Body aliases AuditEventInput (registered in meta.ts).
export const RecordAuditEventRequest = AuditEventInput;
export type RecordAuditEventRequest = z.infer<typeof RecordAuditEventRequest>;
export const RecordAuditEventResponse = z
  .object({ accepted: z.boolean() })
  .meta({ id: 'RecordAuditEventResponse' });
export type RecordAuditEventResponse = z.infer<typeof RecordAuditEventResponse>;

// GET /v1/facets — distinct inventory facet values (response = InventoryFacets,
// registered in meta.ts).

// ── Inventory API (/v1/inventory) ──────────────────────────────────────────
//
// All 21 shapes and 8 enums live in inventory.ts; they are exported from the
// package index via `export * from './inventory.ts'` in zod/index.ts. The
// aliased response types below follow the operationId naming convention used by
// findings/policies routes and serve as the single import surface for route
// files to pull response schemas from api.ts.
//
// Response shapes (ProjectSummary, HarnessSummary, AssetDetail, FileDetail)
// are defined in inventory.ts and stay in @akasecurity/schema so zod/api.ts
// can embed them in the public OpenAPI contract. They are not re-exported here
// (inventory.ts is in zod/index.ts), only aliased where a new name adds clarity.
//
// Query/param schemas (ListAssetsQuery, GetProjectTreeQuery, GetProjectFileQuery,
// GetHarnessEventsQuery) carry NO `.meta({ id })` — query params expand inline
// in OpenAPI `parameters` and cannot be $refs.  Route files import them directly
// from inventory.ts (via the package index) but they are also re-exported below
// for convenience.

// GET /v1/inventory/stats
export const GetInventoryStatsResponse = InventoryStats;
export type GetInventoryStatsResponse = z.infer<typeof GetInventoryStatsResponse>;

// GET /v1/inventory/harnesses
// Alias — component registered once as `ListHarnessesResponse` (inventory.ts).
export const GetListHarnessesResponse = ListHarnessesResponse;
export type GetListHarnessesResponse = z.infer<typeof GetListHarnessesResponse>;

// GET /v1/inventory/assets
// Alias — component registered once as `ListAssetsResponse` (inventory.ts).
export const GetListAssetsResponse = ListAssetsResponse;
export type GetListAssetsResponse = z.infer<typeof GetListAssetsResponse>;

// GET /v1/inventory/assets/:assetId
// Alias — component registered once as `AssetDetail` (inventory.ts).
export const GetAssetResponse = AssetDetail;
export type GetAssetResponse = z.infer<typeof GetAssetResponse>;

// GET /v1/inventory/projects
// Alias — component registered once as `ListProjectsResponse` (inventory.ts).
export const GetListProjectsResponse = ListProjectsResponse;
export type GetListProjectsResponse = z.infer<typeof GetListProjectsResponse>;

// GET /v1/inventory/projects/:projectId/tree
// Alias — component registered once as `ProjectTreeResponse` (inventory.ts).
export const GetProjectTreeResponse = ProjectTreeResponse;
export type GetProjectTreeResponse = z.infer<typeof GetProjectTreeResponse>;

// GET /v1/inventory/projects/:projectId/files
// Alias — component registered once as `FileDetail` (inventory.ts).
export const GetFileDetailResponse = FileDetail;
export type GetFileDetailResponse = z.infer<typeof GetFileDetailResponse>;

// PUT /v1/inventory/projects/:projectId/files/access — request + response.
// SetFileAccessBody and SetFileAccessResponse are the component ids (inventory.ts).
export const PutFileAccessRequest = SetFileAccessBody;
export type PutFileAccessRequest = z.infer<typeof PutFileAccessRequest>;
export const PutFileAccessResponse = SetFileAccessResponse;
export type PutFileAccessResponse = z.infer<typeof PutFileAccessResponse>;

// PUT /v1/inventory/assets/:assetId/trust — request.
// SetMcpTrustBody is the component id; response is AssetDetail (GetAssetResponse above).
export const PutMcpTrustRequest = SetMcpTrustBody;
export type PutMcpTrustRequest = z.infer<typeof PutMcpTrustRequest>;

// GET /v1/inventory/harnesses/:harnessId/events
// Alias — component registered once as `HarnessEventsResponse` (inventory.ts).
export const GetHarnessEventsResponse = HarnessEventsResponse;
export type GetHarnessEventsResponse = z.infer<typeof GetHarnessEventsResponse>;

// POST /v1/inventory/rescan
// Alias — component registered once as `RescanResponse` (inventory.ts). 202 status.
export const PostRescanResponse = RescanResponse;
export type PostRescanResponse = z.infer<typeof PostRescanResponse>;

// POST /v1/inventory/projects — request + response.
// ConnectProjectBody is the component id; response is ProjectSummary.
export const PostConnectProjectRequest = ConnectProjectBody;
export type PostConnectProjectRequest = z.infer<typeof PostConnectProjectRequest>;
export const PostConnectProjectResponse = ProjectSummary;
export type PostConnectProjectResponse = z.infer<typeof PostConnectProjectResponse>;

// Query param schemas — re-exported from inventory.ts for convenience.
// No `.meta({ id })` — see header comment above.
export { GetHarnessEventsQuery, GetProjectFileQuery, GetProjectTreeQuery, ListAssetsQuery };

// Shared error envelope shape intended for standardized API errors (not yet emitted by all handlers).
export const ErrorResponse = z
  .object({
    error: z.object({
      code: z.string(),
      message: z.string(),
      details: z.unknown().optional(),
    }),
  })
  .meta({ id: 'ErrorResponse' });
export type ErrorResponse = z.infer<typeof ErrorResponse>;
