// Meta data-model contracts — Inventory / Audit / Source-Project / Classified
// Data / Inspection Definition / Inspection Finding: the generalization of
// the events/findings/rule shapes. These describe the meta tables; the live
// capture path writes events/findings independently.
//
// `.meta({ id })` is carried ONLY by the schemas API routes reference (the
// inventory/audit/facets shapes) so they emit as
// OpenAPI components. The not-routed shapes (ClassifiedData / Inspection*)
// deliberately omit it — an orphan id would still register in Zod's global
// registry and leak into the OpenAPI client (the .meta id-leak gotcha in
// local.ts). Add the id only when a route starts referencing the shape.
//
// Hashing is NOT done here. `@akasecurity/schema` must stay free of Node-API deps
// (`@akasecurity/detections` imports it), so the sha256 content-addressing lives in
// `@akasecurity/persistence`; this module only provides the pure `canonicalIdentity`
// join used to build the hash input.
import { z } from 'zod';

import { ActionTaken, DetectionCategory, Severity, Span } from './finding.ts';

// ── Discriminators ─────────────────────────────────────────────────────────

// Inventory super-type discriminator (the existence/dimension side).
// `skill` / `hook` are config artifacts (the "My Configuration" surface): they
// exist, carry mutable descriptive attributes, and appear/disappear — the same
// existence shape as host/harness/user, so they ride the single inventory table
// with no DDL change. See config-inventory.ts for their scan shapes.
export const InventoryObjectType = z
  .enum(['host', 'harness', 'user', 'skill', 'hook', 'mcp_server', 'config_file'])
  .meta({ id: 'InventoryObjectType' });
export type InventoryObjectType = z.infer<typeof InventoryObjectType>;

// Audit super-type discriminator (the timeline/fact side). The tree node types
// plus today's capture grain — kept as a superset of `events.kind` so mapping
// onto `audit_events.event_type` is a widening, not a remap.
export const AuditEventType = z
  .enum([
    'session',
    'run',
    'tool_call',
    'llm_call',
    'source_lookup',
    'prompt',
    'response',
    'code_change',
    // One row per config-inventory scan, hung off the session root. It is the
    // fact the posture inspection findings reference (findings require an
    // audit_event_id), and its started_at is the "scanned Nm ago" the read
    // surface renders.
    'config_scan',
  ])
  .meta({ id: 'AuditEventType' });
export type AuditEventType = z.infer<typeof AuditEventType>;

// ── Canonical attribute vocabulary ─────────────────────────────────────────
// The handful of keys that graduate into facets get a canonical name validated
// at ingest, so adapters can't drift (`os_version` vs `osVersion`) and silently
// NULL the generated columns. `.catchall` keeps the long tail flexible.

export const AttributeBag = z.record(z.string(), z.unknown());
export type AttributeBag = z.infer<typeof AttributeBag>;

export const HostAttributes = z
  .object({
    host_name: z.string().optional(),
    os: z.string().optional(),
    os_version: z.string().optional(),
    arch: z.string().optional(),
  })
  .catchall(z.unknown());
export type HostAttributes = z.infer<typeof HostAttributes>;

export const HarnessAttributes = z
  .object({
    harness_version: z.string().optional(),
    interface: z.string().optional(),
  })
  .catchall(z.unknown());
export type HarnessAttributes = z.infer<typeof HarnessAttributes>;

export const UserAttributes = z
  .object({
    display_name: z.string().optional(),
    email: z.string().optional(),
  })
  .catchall(z.unknown());
export type UserAttributes = z.infer<typeof UserAttributes>;

// Skill config artifact. `source`/`name` are the hashed identity (see
// config-inventory.ts); `version` is deliberately VOLATILE — an update must not
// mint a new inventory row, so it rides the bag as current
// state. `updated_at` is the skill directory's mtime (ISO), the "updated Nd ago"
// freshness signal.
export const SkillAttributes = z
  .object({
    source: z.string().optional(),
    version: z.string().optional(),
    description: z.string().optional(),
    updated_at: z.string().optional(),
    scope: z.string().optional(),
    plugin_name: z.string().optional(),
  })
  .catchall(z.unknown());
export type SkillAttributes = z.infer<typeof SkillAttributes>;

// Hook config artifact. Unlike skills, `command` IS part of the hashed identity
// (config-inventory.ts): an edited command is materially a different hook — the
// old row goes stale and a new row appears with a fresh first_seen, which is
// exactly the "new/unknown hook appeared" signal. The bag repeats the identity
// fields because the bag is what the read surface renders; the hash is opaque.
export const HookAttributes = z
  .object({
    event: z.string().optional(),
    matcher: z.string().optional(),
    command: z.string().optional(),
    scope: z.string().optional(),
    plugin_name: z.string().optional(),
    timeout: z.number().optional(),
  })
  .catchall(z.unknown());
export type HookAttributes = z.infer<typeof HookAttributes>;

// MCP-server config artifact. Identity is `name + scope` ONLY (config-inventory
// .ts) — `command`/`url` are deliberately VOLATILE: a same-named server whose
// endpoint silently changes is the most interesting drift event, and it must
// surface as an attribute change on a stable row (preserving the user's trust
// decision), never as a quiet new row that resets trust. `env_keys` carries env
// var NAMES only — values are never captured (the no-secrets rule).
export const McpServerAttributes = z
  .object({
    scope: z.string().optional(),
    transport: z.string().optional(),
    command: z.string().optional(),
    url: z.string().optional(),
    env_keys: z.array(z.string()).optional(),
    plugin_name: z.string().optional(),
    marketplace: z.string().optional(),
    project: z.string().optional(),
  })
  .catchall(z.unknown());
export type McpServerAttributes = z.infer<typeof McpServerAttributes>;

// Configuration-file artifact (settings / memory / .mcp.json / commands /
// agents dirs). The file IS the thing — identity is `path + scope` — and its
// contents are mutable state: `kind` is the human label ("User settings"),
// `detail` a derived SHAPE summary (top-level key names, entry counts, line
// counts — never values or content), `updated_at` the file mtime.
export const ConfigFileAttributes = z
  .object({
    kind: z.string().optional(),
    detail: z.string().optional(),
    scope: z.string().optional(),
    updated_at: z.string().optional(),
    entry_count: z.number().optional(),
  })
  .catchall(z.unknown());
export type ConfigFileAttributes = z.infer<typeof ConfigFileAttributes>;

// The token-usage attribute bag carried by an `llm_call` audit row. One row per
// assistant API response = one `usage` block from the transcript. Mirrors the
// HostAttributes style: every field `.optional()`, `.catchall(z.unknown())` for
// the long tail, and NO `.meta({ id })` — it is a validated bag, not a routed
// shape, and an orphan id would leak into the OpenAPI client (the .meta id-leak
// gotcha in local.ts). The hot fields (input/output tokens, cache, model,
// provider) are promoted to generated columns separately; the rest ride the bag.
export const LlmCallAttributes = z
  .object({
    // Tier 1 — promoted to generated columns (core cost + rollups).
    model: z.string().optional(),
    // Resolved at hook time (NOT in the transcript) — see provider snapshot.
    provider: z.string().optional(),
    input_tokens: z.number().int().nonnegative().optional(),
    output_tokens: z.number().int().nonnegative().optional(),
    cache_creation_input_tokens: z.number().int().nonnegative().optional(),
    cache_read_input_tokens: z.number().int().nonnegative().optional(),
    // Tier 2 — kept in the bag (high value, promote later if needed).
    // 1h vs 5m cache writes are priced differently (from usage.cache_creation.*).
    ephemeral_1h_input_tokens: z.number().int().nonnegative().optional(),
    ephemeral_5m_input_tokens: z.number().int().nonnegative().optional(),
    // Billed per request, separate from tokens (from usage.server_tool_use.*).
    web_search_requests: z.number().int().nonnegative().optional(),
    web_fetch_requests: z.number().int().nonnegative().optional(),
    // standard/batch/priority → price multiplier.
    service_tier: z.string().optional(),
    // `max_tokens` stops = truncation/waste signal.
    stop_reason: z.string().optional(),
    // Correlation keys to relate tokens ↔ message-content rows (joined later).
    message_id: z.string().optional(),
    uuid: z.string().optional(),
    parent_uuid: z.string().optional(),
    // Run grouping = the parent user record's `promptId` (NOT nearest user uuid).
    run_key: z.string().optional(),
  })
  .catchall(z.unknown());
export type LlmCallAttributes = z.infer<typeof LlmCallAttributes>;

// The reconciler → gateway → persistence input for one `llm_call` leaf row. It
// carries the NATURAL key (`sessionId` + `messageId`) rather than a row id: the
// content-addressed `llmCallId(sessionId, messageId)` is minted inside
// `@akasecurity/persistence` (the layer that holds the sha256 helper; the id
// is tenant-free for the single-tenant OSS local store), so the plugin never imports
// `@akasecurity/persistence` to mint it — keeping the
// `plugins/claude-code → @akasecurity/plugin-sdk` boundary intact. `parentId`/`rootSessionId` are
// both the `sessionId` (the leaf hangs directly off the session root).
// No `.meta({ id })` — it is a gateway-port input, not a routed OpenAPI shape.
export const LlmCallInput = z.object({
  sessionId: z.string().min(1),
  // `message.id` (`msg_…`) — the natural key the deterministic id hashes on.
  messageId: z.string().min(1),
  // The session-root id the leaf hangs off (FK `parent_id` + `root_session_id`).
  parentId: z.string().min(1),
  rootSessionId: z.string().min(1),
  // The record's own ISO timestamp (`occurredAt`) — the leaf's `started_at`.
  startedAt: z.iso.datetime(),
  attributes: LlmCallAttributes,
});
export type LlmCallInput = z.infer<typeof LlmCallInput>;

// The attribute bag carried by a `tool_call` audit row. One row per transcript
// `tool_use` block, enriched with its matching `tool_result` (is_error / output
// size). Mirrors the `LlmCallAttributes` style — every field `.optional()`,
// `.catchall(z.unknown())`, and NO `.meta({ id })` (a validated bag, not a routed
// shape; an orphan id would leak into the OpenAPI client, the local.ts gotcha).
// Layer 1 is metadata-only: no raw tool input/output rides the bag. The masked
// content + inspection findings are added on the SAME rows in the Layer-2 pass.
export const ToolCallAttributes = z
  .object({
    tool_name: z.string().optional(),
    // The transcript `tool_use.id` (`toolu_…`) — the natural key the id hashes on.
    tool_use_id: z.string().optional(),
    // The salient input, MASKED — a WebFetch url, a Bash command, a file path — so a
    // query can see "which WebFetch / which Bash" without the row ever holding a raw
    // secret. Redacted by the reconciler via `maskText` before it reaches this bag.
    target: z.string().optional(),
    // From the matching `tool_result.is_error` — surfaced so a query can filter
    // failed tool calls without reading content.
    is_error: z.boolean().optional(),
    // Character sizes of the serialized tool input / result (metadata, not payload).
    input_size: z.number().int().nonnegative().optional(),
    output_size: z.number().int().nonnegative().optional(),
    // Correlation keys (same grammar as the llm_call bag): the assistant record's
    // own uuid, its parent user record, and the run grouping key (parent's promptId).
    uuid: z.string().optional(),
    parent_uuid: z.string().optional(),
    run_key: z.string().optional(),
  })
  .catchall(z.unknown());
export type ToolCallAttributes = z.infer<typeof ToolCallAttributes>;

// One detected-secret hit to attach to a tool_call as an `inspection_finding`
// (Layer 2b). Carries the rule IDENTITY (not a definition id) + the masked hit; the
// content-addressed inspection_definition / classified_data / inspection_finding ids
// are all minted in `@akasecurity/persistence` from these natural keys, so the plugin
// never mints them. `maskedMatch` is already masked (via maskMatch) — the raw secret
// never rides this shape. No `.meta({ id })` (a gateway-port input, not a routed shape).
export const ToolCallInspection = z.object({
  ruleId: z.string().min(1),
  ruleName: z.string(),
  // The rule's specVersion (stringified) — bumps mint a new inspection_definition.
  // `.min(1)` to match `InspectionDefinitionInput.version` (fail fast on an
  // empty-version rule rather than writing an empty-version definition row).
  ruleVersion: z.string().min(1),
  category: DetectionCategory,
  severity: Severity,
  span: Span,
  maskedMatch: z.string(),
  actionTaken: ActionTaken,
  confidence: z.number().min(0).max(1),
});
export type ToolCallInspection = z.infer<typeof ToolCallInspection>;

// The reconciler → gateway → persistence input for one `tool_call` leaf. Carries
// the NATURAL key (`sessionId` + `toolUseId`); the content-addressed
// `toolCallId(sessionId, toolUseId)` is minted inside `@akasecurity/persistence` (same
// boundary reason as `LlmCallInput`). `parentId`/`rootSessionId` are both the
// `sessionId` — the leaf hangs directly off the session root. No
// `.meta({ id })` — a gateway-port input, not a routed OpenAPI shape.
export const ToolCallInput = z.object({
  sessionId: z.string().min(1),
  toolUseId: z.string().min(1),
  parentId: z.string().min(1),
  rootSessionId: z.string().min(1),
  startedAt: z.iso.datetime(),
  attributes: ToolCallAttributes,
  // Secrets detected in the tool's (masked) target — written as linked
  // `inspection_findings`. Empty for a clean tool call.
  inspections: z.array(ToolCallInspection).default([]),
});
export type ToolCallInput = z.infer<typeof ToolCallInput>;

// The vocabulary keyed by object_type, for callers that validate a bag before
// upsert.
export const INVENTORY_ATTRIBUTE_VOCAB = {
  host: HostAttributes,
  harness: HarnessAttributes,
  user: UserAttributes,
  skill: SkillAttributes,
  hook: HookAttributes,
  mcp_server: McpServerAttributes,
  config_file: ConfigFileAttributes,
} as const;

// ── Input shapes (pre-id; the resolver/tests pass these) ───────────────────
// Content-addressed ids are computed in `@akasecurity/persistence` from the identity
// key, so these inputs carry the identity key, not the id.

export const InventoryInput = z
  .object({
    objectType: InventoryObjectType,
    // The identity key hashed into the id: stable machine id (host) / tool
    // (harness) / local-or-account id (user). NOT the descriptive attributes.
    identityKey: z.string().min(1),
    location: z.string().optional(),
    title: z.string().optional(),
    // Resolved id of the host row this harness/user runs on (intra-inventory edge).
    hostId: z.string().optional(),
    attributes: AttributeBag.default({}),
  })
  .meta({ id: 'InventoryInput' });
export type InventoryInput = z.infer<typeof InventoryInput>;

export const SourceProjectInput = z
  .object({
    // The remote url/identifier — hashed into the content-addressed id.
    url: z.string().min(1),
    name: z.string().optional(),
    attributes: AttributeBag.default({}),
  })
  .meta({ id: 'SourceProjectInput' });
export type SourceProjectInput = z.infer<typeof SourceProjectInput>;

export const AuditEventInput = z
  .object({
    // Unique per event (a random id, e.g. randomUUID) — facts are never deduped.
    id: z.string().min(1),
    eventType: AuditEventType,
    startedAt: z.iso.datetime(),
    endedAt: z.iso.datetime().optional(),
    parentId: z.string().optional(),
    // The Session root id; descendants resolve inventory via this join.
    rootSessionId: z.string().optional(),
    hostId: z.string().optional(),
    harnessId: z.string().optional(),
    sourceProjectId: z.string().optional(),
    // Derived rollup of this event's findings' severities, not intrinsic.
    severity: Severity.optional(),
    priority: z.string().optional(),
    content: z.string().optional(),
    contentHash: z.string().optional(),
    // JSON bag + snapshotted volatile attrs (os_version, …) true at capture.
    attributes: AttributeBag.optional(),
  })
  .meta({ id: 'AuditEventInput' });
export type AuditEventInput = z.infer<typeof AuditEventInput>;

export const ClassifiedDataInput = z.object({
  // The sensitive-data class (`aws_key`, `email_pii`, …) — the identity key.
  class: z.string().min(1),
  label: z.string().optional(),
  attributes: AttributeBag.optional(),
});
export type ClassifiedDataInput = z.infer<typeof ClassifiedDataInput>;

export const InspectionDefinitionInput = z.object({
  ruleId: z.string().min(1),
  // id = sha256(ruleId + version): editing a rule mints a new definition id.
  version: z.string().min(1),
  name: z.string(),
  category: DetectionCategory,
  severity: Severity,
  // The serialized matcher/definition (the "what to look for").
  definition: z.string(),
});
export type InspectionDefinitionInput = z.infer<typeof InspectionDefinitionInput>;

export const InspectionFindingInput = z.object({
  id: z.string().min(1),
  auditEventId: z.string().min(1),
  inspectionDefinitionId: z.string().min(1),
  classifiedDataId: z.string().optional(),
  span: Span,
  maskedMatch: z.string(),
  actionTaken: ActionTaken,
  confidence: z.number().min(0).max(1),
});
export type InspectionFindingInput = z.infer<typeof InspectionFindingInput>;

// ── Resolver / gateway DTOs ────────────────────────────────────────────────
// The shapes the inventory resolver (@akasecurity/plugin-sdk) produces and the
// DataGateway / @akasecurity/persistence consume. Zod with `.meta({ id })`
// since ingest-style routes (POST /v1/inventory, GET /v1/facets) reference
// them — they are part of the API surface.

// The resolved per-session inventory descriptors `ensureInventory` upserts — the
// machine/repo facts the resolver produces (host/harness/project). The
// User/Account dimension is NOT here: the writer adds the local user account.
export const InventoryContext = z
  .object({
    host: InventoryInput.optional(),
    harness: InventoryInput.optional(),
    project: SourceProjectInput.optional(),
  })
  .meta({ id: 'InventoryContext' });
export type InventoryContext = z.infer<typeof InventoryContext>;

// The content-addressed ids `ensureInventory` resolved, ready to stamp onto a
// Session audit row. `accountId` is the inventory User/Account dimension row.
export const ResolvedInventory = z
  .object({
    hostId: z.string().optional(),
    harnessId: z.string().optional(),
    accountId: z.string().optional(),
    sourceProjectId: z.string().optional(),
  })
  .meta({ id: 'ResolvedInventory' });
export type ResolvedInventory = z.infer<typeof ResolvedInventory>;

// Filter-facet values for the read surfaces, read from the small Inventory
// dimension (with the generated-column indexes), never by scanning the audit fact.
export const InventoryFacets = z
  .object({
    hosts: z.array(z.string()),
    harnesses: z.array(z.string()),
    osVersions: z.array(z.string()),
    projects: z.array(z.string()),
  })
  .meta({ id: 'InventoryFacets' });
export type InventoryFacets = z.infer<typeof InventoryFacets>;

// ── Token-usage read DTOs ──────────────────────────────────────────────────
// The per-(session, model, provider) token rollup the report surface renders.
// Token counts are the saved truth; `estimatedCostUsd` is DERIVED at read time
// from the price map (null when the (provider, model) pair is unknown — never a
// guessed figure). `GET /v1/activity/sessions/{sessionId}` references this
// shape directly (its `tokens` field) — `.meta({id})` registers it as an
// OpenAPI component. Style matches the camelCase read DTOs above (InventoryFacets).
export const TokenRollup = z
  .object({
    sessionId: z.string(),
    model: z.string(),
    provider: z.string(),
    inputTokens: z.number().int().nonnegative(),
    outputTokens: z.number().int().nonnegative(),
    // Merged 1h+5m cache writes. Cost is NOT re-derivable from this total: the
    // upstream model prices the 1h/5m split (2×/1.25× input) off the leaf
    // `llm_call` bag's ephemeral_{1h,5m}_input_tokens, not this merged sum.
    cacheCreation: z.number().int().nonnegative(),
    cacheRead: z.number().int().nonnegative(),
    totalTokens: z.number().int().nonnegative(),
    // Computed upstream at read time from the leaf `llm_call` attribute bag (which
    // carries the ephemeral 1h/5m split); the rollup only STORES the already-
    // computed number. Null when (provider, model) is unknown — never a guess.
    estimatedCostUsd: z.number().nullable(),
  })
  .meta({ id: 'TokenRollup' });
export type TokenRollup = z.infer<typeof TokenRollup>;

// A session's token report: its per-(model, provider) rollups plus the
// session-level totals (also derived at read time from the `llm_call` leaves —
// never stored on the session root, per the structural-parent invariant).
export const SessionTokenReport = z.object({
  sessionId: z.string(),
  rollups: z.array(TokenRollup),
  totalTokens: z.number().int().nonnegative(),
  // Σ of the PRICED rollups only; null when no rollup had a known price.
  estimatedCostUsd: z.number().nullable(),
  // True whenever any rollup has a null cost (unknown provider/model), so the
  // total understates real spend — the UI renders `≥ $X` instead of a falsely
  // precise figure rather than silently dropping the unpriced calls.
  costIsPartial: z.boolean(),
});
export type SessionTokenReport = z.infer<typeof SessionTokenReport>;

// A cross-session token usage row, collapsed onto one `(provider, model)` — the
// grain the read surfaces render as a "usage by model" table (built by
// `aggregateTokenUsage`). `cacheTokens` merges cache creation + read (the rollup
// keeps them split; the aggregate view shows one "cache" column). No `.meta({id})`
// — a read DTO, not a routed OpenAPI shape (an orphan id would leak into the
// client, the local.ts gotcha).
export const ModelTokenUsage = z.object({
  provider: z.string(),
  model: z.string(),
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheTokens: z.number().int().nonnegative(),
  totalTokens: z.number().int().nonnegative(),
  // Σ of this model's PRICED rollups; null when none had a known price.
  estimatedCostUsd: z.number().nullable(),
});
export type ModelTokenUsage = z.infer<typeof ModelTokenUsage>;

// The cross-session token usage summary — the per-model rows (largest first)
// plus the grand totals. `costIsPartial` is true when ANY rollup was unpriced,
// so `estimatedCostUsd` is a lower bound the UI renders as `≥ $X`. No
// `.meta({id})` (a read DTO, not a routed shape — see ModelTokenUsage).
export const TokenUsageSummary = z.object({
  models: z.array(ModelTokenUsage),
  sessionCount: z.number().int().nonnegative(),
  totalTokens: z.number().int().nonnegative(),
  estimatedCostUsd: z.number(),
  costIsPartial: z.boolean(),
});
export type TokenUsageSummary = z.infer<typeof TokenUsageSummary>;

// ── Pure content-addressing helper ─────────────────────────────────────────

// Injective serialization of the parts that get hashed into a content-addressed
// id. JSON array encoding is unambiguous (["a","b"] vs ["ab",""]) without a
// magic separator, so distinct part lists can never produce the same string.
// `@akasecurity/persistence` sha256's the result.
export function canonicalIdentity(parts: readonly string[]): string {
  return JSON.stringify(parts);
}
