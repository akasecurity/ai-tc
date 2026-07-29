// Base storage-row contracts — the tenant-free SHAPE of every control-plane table
// in the OSS local store (this package, SQLite).
//
// These interfaces are the single source of truth for the column set of each
// entity. The SQLite tables are asserted to equal the base
// (drizzle/adherence.test.ts): a column added/removed/renamed on the table
// without updating the base becomes a `tsc --noEmit` failure — divergence is
// caught at compile time.
//
// Why a generic time parameter: the base is parameterized on its time column so
// the same shape stays reusable across storage dialects. The local store pins it
// to epoch-millis `INTEGER` (`number`); everything else (`boolean`, `real`→`number`,
// enums, nullability) is dialect-independent. No other normalization is needed or
// permitted — keeping the guard honest (no hand-tuned per-column coercion that
// could pass vacuously).
//
// These are STORAGE rows (dialect scalars, JSON stored as `text`), distinct from
// the domain Zod shapes in ../zod (ISO-string time, parsed JSON). The repository
// row-mappers convert between the two; a runtime round-trip test pins that
// mapping (separate from this compile-time column-set guard).

/** events — append-only capture. No createdAt/updatedAt by design. */
export interface BaseEventRow<TTime = number> {
  id: string;
  sourceTool: string;
  kind: 'prompt' | 'response' | 'code_change' | 'tool_use';
  occurredAt: TTime;
  contentHash: string;
  content: string;
  metadata: string | null;
}

/** findings — append-only. No time column at all. */
export interface BaseFindingRow {
  id: string;
  eventId: string;
  ruleId: string;
  category: string;
  severity: string;
  spanStart: number;
  spanEnd: number;
  maskedMatch: string;
  actionTaken: string;
  confidence: number;
  findingKey: string | null;
  // Preserved first-detection time (epoch millis), an integer column
  // (like finding_resolution.resolvedAt) — NOT a TTime-parameterized column, so
  // it stays `number`. Nullable: added via a plain
  // ADD COLUMN (SQLite cannot ALTER-ADD a NOT NULL column without a constant
  // default, and this value is a per-row backfill from events.occurred_at, not a
  // constant), then backfilled for legacy rows; the findings writer populates it
  // on every INSERT going forward. Read paths COALESCE onto occurred_at as a
  // defensive fallback.
  firstDetectedAt: number | null;
}

/** policies — mutable (createdAt/updatedAt). */
export interface BasePolicyRow<TTime = number> {
  id: string;
  scope: 'global' | 'repo' | 'user';
  target: string;
  action: string;
  enabled: boolean;
  customKeywords: string | null;
  name: string | null;
  createdAt: TTime;
  updatedAt: TTime;
}

/** installed_packs — mutable. rulesJson is a storage-only snapshot (text). */
export interface BaseInstalledPackRow<TTime = number> {
  id: string;
  namespace: string;
  packId: string;
  version: string;
  name: string;
  rulesJson: string;
  enabled: boolean;
  policyId: string | null;
  createdAt: TTime;
  updatedAt: TTime;
}

// ─── [Meta] data model ───────────────────────────────────────────────────────
// osVersion/harnessVersion (inventory) and the token facets (audit_events) are
// generated columns (VIRTUAL on SQLite) — nullable, so
// `string | null` / `number | null`.

/** inventory — the polymorphic config/existence dimension, content-addressed. */
export interface BaseInventoryRow<TTime = number> {
  id: string;
  objectType: 'host' | 'harness' | 'user' | 'skill' | 'hook' | 'mcp_server' | 'config_file';
  location: string | null;
  title: string | null;
  hostId: string | null;
  attributes: string;
  osVersion: string | null;
  harnessVersion: string | null;
  firstSeen: TTime;
  lastSeen: TTime;
}

/** source_project — content-addressed by remote url. */
export interface BaseSourceProjectRow<TTime = number> {
  id: string;
  url: string | null;
  name: string | null;
  attributes: string;
  firstSeen: TTime;
  lastSeen: TTime;
}

/** audit_events — polymorphic timeline fact, self-ref tree. */
export interface BaseAuditEventRow<TTime = number> {
  id: string;
  parentId: string | null;
  rootSessionId: string | null;
  eventType:
    | 'session'
    | 'run'
    | 'tool_call'
    | 'llm_call'
    | 'source_lookup'
    | 'prompt'
    | 'response'
    | 'code_change'
    | 'tool_use'
    | 'config_scan';
  hostId: string | null;
  harnessId: string | null;
  sourceProjectId: string | null;
  startedAt: TTime;
  endedAt: TTime | null;
  severity: string | null;
  priority: string | null;
  content: string | null;
  contentHash: string | null;
  attributes: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cacheCreationInputTokens: number | null;
  cacheReadInputTokens: number | null;
  model: string | null;
  provider: string | null;
}

/** classified_data — small CLASS dimension keyed by class only. */
export interface BaseClassifiedDataRow {
  id: string;
  class: string;
  label: string | null;
  attributes: string | null;
}

/** inspection_definitions — a detection rule version. */
export interface BaseInspectionDefinitionRow {
  id: string;
  ruleId: string;
  name: string;
  category: string;
  severity: string;
  definition: string;
  version: string;
}

/** inspection_findings — a hit of a definition against an audit event. */
export interface BaseInspectionFindingRow {
  id: string;
  auditEventId: string;
  inspectionDefinitionId: string;
  classifiedDataId: string | null;
  spanStart: number;
  spanEnd: number;
  maskedMatch: string;
  actionTaken: string;
  confidence: number;
  findingKey: string | null;
  firstDetectedAt: number | null;
}
