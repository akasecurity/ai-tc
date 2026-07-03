import { z } from 'zod';

// ─── Enums ────────────────────────────────────────────────────────────────────

export const AssetType = z
  .enum(['project', 'skill', 'mcp', 'hook', 'config'])
  .meta({ id: 'AssetType' });
export type AssetType = z.infer<typeof AssetType>;

export const AccessLevel = z.enum(['open', 'approved', 'blocked']).meta({ id: 'AccessLevel' });
export type AccessLevel = z.infer<typeof AccessLevel>;

export const Origin = z
  .enum(['source', 'public-dep', 'vendored', 'config', 'data', 'docs', 'generated'])
  .meta({ id: 'Origin' });
export type Origin = z.infer<typeof Origin>;

export const TrustLevel = z.enum(['known-good', 'risky', 'unapproved']).meta({ id: 'TrustLevel' });
export type TrustLevel = z.infer<typeof TrustLevel>;

export const Flag = z
  .enum(['update', 'stale', 'conflict', 'unknown', 'change', 'untracked', 'risk', 'findings'])
  .meta({ id: 'Flag' });
export type Flag = z.infer<typeof Flag>;

export const Visibility = z.enum(['public', 'private']).meta({ id: 'Visibility' });
export type Visibility = z.infer<typeof Visibility>;

/**
 * Harness enforcement event outcome.
 * Renamed from EventKind to avoid collision with the existing EventKind (prompt/response/code_change)
 * exported from event.ts. OpenAPI component id: 'HarnessEventKind'.
 */
export const HarnessEventKind = z
  .enum(['block', 'redact', 'warn'])
  .meta({ id: 'HarnessEventKind' });
export type HarnessEventKind = z.infer<typeof HarnessEventKind>;

export const HarnessId = z.enum(['claudecode', 'cursor', 'codex']).meta({ id: 'HarnessId' });
export type HarnessId = z.infer<typeof HarnessId>;

// ─── Shared sub-shapes ────────────────────────────────────────────────────────

/** Reused across ProjectSummary, FolderSummary, SetFileAccessResponse */
export const AccessCounts = z
  .object({
    open: z.number().int().nonnegative(),
    approved: z.number().int().nonnegative(),
    blocked: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
  })
  .meta({ id: 'AccessCounts' });
export type AccessCounts = z.infer<typeof AccessCounts>;

// ─── Shape 1: AssetSummary ────────────────────────────────────────────────────

/** Shared by harness categories and asset group lists. */
export const AssetSummary = z
  .object({
    id: z.string(),
    type: AssetType,
    name: z.string(),
    sub: z.string(),
    flags: z.array(Flag),
    /** MCP servers only — omitted for all other types. */
    trust: TrustLevel.optional(),
  })
  .meta({ id: 'AssetSummary' });
export type AssetSummary = z.infer<typeof AssetSummary>;

// ─── Shape 2: ProjectSummary ──────────────────────────────────────────────────

/**
 * Response shape embedded in api.ts for the public OpenAPI contract.
 * Embedded in harness summaries, project lists, and connect-project responses.
 */
export const ProjectSummary = z
  .object({
    id: z.string(),
    name: z.string(),
    repo: z.string(),
    visibility: Visibility,
    language: z.string(),
    policyDefault: AccessLevel,
    updatedAt: z.iso.datetime(),
    accessCounts: AccessCounts,
    findingsCount: z.number().int().nonnegative(),
  })
  .meta({ id: 'ProjectSummary' });
export type ProjectSummary = z.infer<typeof ProjectSummary>;

// ─── Shape 3: HarnessSummary ──────────────────────────────────────────────────

/** Harness category row — type + ordered asset list. */
const HarnessCategory = z.object({
  /** One of config/skill/mcp/hook — never project (enforced at service layer). */
  type: AssetType,
  assets: z.array(AssetSummary),
});

/**
 * Response shape embedded in api.ts for the public OpenAPI contract.
 * Powers the by-harness tree view.
 */
export const HarnessSummary = z
  .object({
    id: HarnessId,
    label: z.string(),
    kind: z.string(),
    version: z.string(),
    sessions: z.number().int().nonnegative(),
    assetCount: z.number().int().nonnegative(),
    flagCount: z.number().int().nonnegative(),
    projects: z.array(ProjectSummary),
    categories: z.array(HarnessCategory),
  })
  .meta({ id: 'HarnessSummary' });
export type HarnessSummary = z.infer<typeof HarnessSummary>;

// ─── Shape 4: ListHarnessesResponse ──────────────────────────────────────────

export const ListHarnessesResponse = z
  .object({ items: z.array(HarnessSummary) })
  .meta({ id: 'ListHarnessesResponse' });
export type ListHarnessesResponse = z.infer<typeof ListHarnessesResponse>;

// ─── Shape 5: AssetGroup ──────────────────────────────────────────────────────

export const AssetGroup = z
  .object({
    /** Group key — never project (enforced at service layer). */
    type: AssetType,
    total: z.number().int().nonnegative(),
    /**
     * MCP group only — omitted for all other types.
     * Partial: only TrustLevel keys with non-zero counts are included.
     * Strict: unknown keys are rejected — only TrustLevel values are valid keys.
     */
    trustRollup: z
      .object({
        'known-good': z.number().int().nonnegative(),
        risky: z.number().int().nonnegative(),
        unapproved: z.number().int().nonnegative(),
      })
      .partial()
      .strict()
      .optional(),
    /**
     * Partial: only Flag keys with non-zero counts are included.
     * Strict: unknown keys are rejected — only Flag values are valid keys.
     */
    flagRollup: z
      .object({
        update: z.number().int().nonnegative(),
        stale: z.number().int().nonnegative(),
        conflict: z.number().int().nonnegative(),
        unknown: z.number().int().nonnegative(),
        change: z.number().int().nonnegative(),
        untracked: z.number().int().nonnegative(),
        risk: z.number().int().nonnegative(),
        findings: z.number().int().nonnegative(),
      })
      .partial()
      .strict(),
    items: z.array(AssetSummary),
  })
  .meta({ id: 'AssetGroup' });
export type AssetGroup = z.infer<typeof AssetGroup>;

// ─── Shape 6: ListAssetsResponse ─────────────────────────────────────────────

export const ListAssetsResponse = z
  .object({ groups: z.array(AssetGroup) })
  .meta({ id: 'ListAssetsResponse' });
export type ListAssetsResponse = z.infer<typeof ListAssetsResponse>;

// ─── Shape 7: McpTool ────────────────────────────────────────────────────────

export const McpTool = z
  .object({
    name: z.string(),
    signature: z.string(),
    description: z.string(),
    write: z.boolean(),
    /** Non-null string when tool is dangerous / blocked; null otherwise. */
    risk: z.string().nullable(),
  })
  .meta({ id: 'McpTool' });
export type McpTool = z.infer<typeof McpTool>;

// ─── Shape 8: AssetDetail ────────────────────────────────────────────────────

/** Inline finding callout on an asset detail (links to the Findings page). */
const AssetFindingRef = z.object({
  id: z.string(),
  title: z.string(),
  note: z.string(),
});

/**
 * Response shape embedded in api.ts for the public OpenAPI contract.
 * Powers the right-pane asset detail and setMcpTrust response.
 * `trust` is null for non-mcp; `tools` is omitted for non-mcp.
 */
export const AssetDetail = AssetSummary.extend({
  /** string | null — null when no description is available. */
  description: z.string().nullable(),
  /** trustLevel | null — null for non-MCP assets. */
  trust: TrustLevel.nullable(),
  /** Type-specific raw key/values — FE renders the grid. */
  meta: z.record(z.string(), z.unknown()),
  /** always present — object when there is an active finding, null when absent. */
  finding: AssetFindingRef.nullable(),
  /** MCP exposed-tools list — omitted for non-mcp. */
  tools: z.array(McpTool).optional(),
}).meta({ id: 'AssetDetail' });
export type AssetDetail = z.infer<typeof AssetDetail>;

// ─── Shape 9: ListProjectsResponse ───────────────────────────────────────────

export const ListProjectsResponse = z
  .object({ items: z.array(ProjectSummary) })
  .meta({ id: 'ListProjectsResponse' });
export type ListProjectsResponse = z.infer<typeof ListProjectsResponse>;

// ─── Shape 10: InventoryStats ─────────────────────────────────────────────────

export const InventoryStats = z
  .object({
    /** Total assets/projects with ≥1 flag or finding (drives the attention header chip). */
    attention: z.number().int().nonnegative(),
    byType: z.object({
      project: z.number().int().nonnegative(),
      skill: z.number().int().nonnegative(),
      mcp: z.number().int().nonnegative(),
      hook: z.number().int().nonnegative(),
      config: z.number().int().nonnegative(),
    }),
    harnesses: z.number().int().nonnegative(),
    mcpTrust: z.object({
      'known-good': z.number().int().nonnegative(),
      risky: z.number().int().nonnegative(),
      unapproved: z.number().int().nonnegative(),
    }),
  })
  .meta({ id: 'InventoryStats' });
export type InventoryStats = z.infer<typeof InventoryStats>;

// ─── Shape 11: FileSummary ────────────────────────────────────────────────────

export const FileSummary = z
  .object({
    path: z.string(),
    name: z.string(),
    origin: Origin,
    /** Effective access (override applied). */
    access: AccessLevel,
    /** True when a file_access_override differs from the computed default. */
    isCustom: z.boolean(),
    findings: z.number().int().nonnegative(),
    /** When the file was auto-blocked by a detection; null when not blocked. */
    blockedAt: z.iso.datetime().nullable().optional(),
    /** Why the file was blocked; null when absent. */
    note: z.string().nullable().optional(),
  })
  .meta({ id: 'FileSummary' });
export type FileSummary = z.infer<typeof FileSummary>;

// ─── Shape 12: FolderSummary ──────────────────────────────────────────────────

export const FolderSummary = z
  .object({
    name: z.string(),
    path: z.string(),
    /** Rollup of effective access across all descendants. */
    accessCounts: AccessCounts,
  })
  .meta({ id: 'FolderSummary' });
export type FolderSummary = z.infer<typeof FolderSummary>;

// ─── Shape 13: ProjectTreeResponse ───────────────────────────────────────────

export const ProjectTreeResponse = z
  .object({
    project: z.object({
      id: z.string(),
      repo: z.string(),
      visibility: Visibility,
    }),
    path: z.string(),
    /** Browse mode: one-level folders at the current path. Omitted in search mode. */
    folders: z.array(FolderSummary).optional(),
    files: z.array(FileSummary),
  })
  .meta({ id: 'ProjectTreeResponse' });
export type ProjectTreeResponse = z.infer<typeof ProjectTreeResponse>;

// ─── Shape 14: FileDetail ────────────────────────────────────────────────────

/**
 * Response shape embedded in api.ts for the public OpenAPI contract.
 * Powers the per-file detail drawer.
 * Extends FileSummary with project context and findingsRefs.
 */
export const FileDetail = FileSummary.extend({
  project: z.object({
    repo: z.string(),
    visibility: Visibility,
    language: z.string(),
    policyDefault: AccessLevel,
    updatedAt: z.iso.datetime(),
  }),
  findingsRefs: z.array(z.object({ id: z.string(), title: z.string() })),
}).meta({ id: 'FileDetail' });
export type FileDetail = z.infer<typeof FileDetail>;

// ─── Shape 15: SetFileAccessBody ─────────────────────────────────────────────

export const SetFileAccessBody = z
  .object({
    path: z.string(),
    access: AccessLevel,
  })
  .meta({ id: 'SetFileAccessBody' });
export type SetFileAccessBody = z.infer<typeof SetFileAccessBody>;

// ─── Shape 16: SetFileAccessResponse ─────────────────────────────────────────

export const SetFileAccessResponse = z
  .object({
    file: FileSummary,
    accessCounts: AccessCounts,
  })
  .meta({ id: 'SetFileAccessResponse' });
export type SetFileAccessResponse = z.infer<typeof SetFileAccessResponse>;

// ─── Shape 17: SetMcpTrustBody ────────────────────────────────────────────────

export const SetMcpTrustBody = z.object({ trust: TrustLevel }).meta({ id: 'SetMcpTrustBody' });
export type SetMcpTrustBody = z.infer<typeof SetMcpTrustBody>;

// ─── Shape 18: HarnessEventItem ──────────────────────────────────────────────

export const HarnessEventItem = z
  .object({
    kind: HarnessEventKind,
    title: z.string(),
    detail: z.string(),
    occurredAt: z.iso.datetime(),
    findingId: z.string().nullable().optional(),
  })
  .meta({ id: 'HarnessEventItem' });
export type HarnessEventItem = z.infer<typeof HarnessEventItem>;

// ─── Shape 19: HarnessEventsResponse ─────────────────────────────────────────

/** counts is keyed by HarnessEventKind values; all three keys are always present. */
export const HarnessEventsResponse = z
  .object({
    counts: z.object({
      block: z.number().int().nonnegative(),
      redact: z.number().int().nonnegative(),
      warn: z.number().int().nonnegative(),
    }),
    items: z.array(HarnessEventItem),
  })
  .meta({ id: 'HarnessEventsResponse' });
export type HarnessEventsResponse = z.infer<typeof HarnessEventsResponse>;

// ─── Shape 20: RescanResponse ─────────────────────────────────────────────────

export const RescanResponse = z
  .object({
    jobId: z.string(),
    startedAt: z.iso.datetime(),
  })
  .meta({ id: 'RescanResponse' });
export type RescanResponse = z.infer<typeof RescanResponse>;

// ─── Shape 21: ConnectProjectBody ────────────────────────────────────────────

export const ConnectProjectBody = z.object({ repo: z.string() }).meta({ id: 'ConnectProjectBody' });
export type ConnectProjectBody = z.infer<typeof ConnectProjectBody>;

// ─── Query schemas ────────────────────────────────────────────────────────────
// Query schemas intentionally carry NO `.meta({ id })`: the OpenAPI generator
// expands query params into individual `parameters` (which cannot be a `$ref`),
// so they must stay inline.  Body schemas above DO carry ids.  See api.ts header.

/** GET /v1/inventory/assets query params. */
export const ListAssetsQuery = z.object({
  /** Filter by one or more AssetType values; absent means all types. */
  type: z.array(AssetType).optional(),
  /** Free-text search term. */
  q: z.string().optional(),
});
export type ListAssetsQuery = z.infer<typeof ListAssetsQuery>;

/** GET /v1/inventory/projects/:id/tree query params. */
export const GetProjectTreeQuery = z.object({
  /** Subtree root path; defaults to repository root when absent. */
  path: z.string().optional(),
  /** Free-text filter applied to file paths. */
  q: z.string().optional(),
  /**
   * Special listing mode. `blocked` returns every effectively-blocked, auto-blocked
   * file across the whole repo (folders omitted, most-recent first), ignoring
   * `path`/`q` — powers the project-wide "recently blocked" strip.
   */
  filter: z.enum(['blocked']).optional(),
});
export type GetProjectTreeQuery = z.infer<typeof GetProjectTreeQuery>;

/** GET /v1/inventory/projects/:id/file query params.  `path` is required. */
export const GetProjectFileQuery = z.object({
  /** Repository-relative file path; absent or empty → 400. */
  path: z.string(),
});
export type GetProjectFileQuery = z.infer<typeof GetProjectFileQuery>;

/** GET /v1/inventory/harnesses/:id/events query params. */
export const GetHarnessEventsQuery = z.object({
  /** Maximum number of events to return.  Range: 1–50; default: 7. */
  limit: z.coerce.number().int().min(1).max(50).default(7),
});
export type GetHarnessEventsQuery = z.infer<typeof GetHarnessEventsQuery>;
