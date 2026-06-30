// OSS local store — SQLite dialect, single-node, tenant-free.
//
// This is the canonical open-source schema for the plugin/CLI's local
// ~/.aka/data/aka.db store. It deliberately carries NO tenant_id / user_id, no
// FKs to a tenants/users catalog, and no auth tables — the local store is a
// single-node, tenant-free store.
//
// events and findings are append-only (no updated_at); policies and
// installed_packs are mutable. occurred_at / created_at / updated_at are
// epoch-millis INTEGER columns (converted at the repo boundary).
import { sql } from 'drizzle-orm';
import {
  type AnySQLiteColumn,
  check,
  index,
  integer,
  real,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

import { COL } from '../columns.ts';

export const events = sqliteTable(
  'events',
  {
    id: text(COL.id).primaryKey(),
    sourceTool: text(COL.sourceTool).notNull(),
    kind: text(COL.kind, { enum: ['prompt', 'response', 'code_change'] }).notNull(),
    occurredAt: integer(COL.occurredAt).notNull(),
    contentHash: text(COL.contentHash).notNull(),
    content: text(COL.content).notNull(),
    metadata: text(COL.metadata),
  },
  (t) => [index('idx_events_occurred').on(t.occurredAt)],
);

export const findings = sqliteTable(
  'findings',
  {
    id: text(COL.id).primaryKey(),
    eventId: text(COL.eventId)
      .notNull()
      .references(() => events.id),
    ruleId: text(COL.ruleId).notNull(),
    category: text(COL.category).notNull(),
    severity: text(COL.severity).notNull(),
    spanStart: integer(COL.spanStart).notNull(),
    spanEnd: integer(COL.spanEnd).notNull(),
    maskedMatch: text(COL.maskedMatch).notNull(),
    actionTaken: text(COL.actionTaken).notNull(),
    confidence: real(COL.confidence).notNull(),
    // Stable, content-addressed key correlating a finding across re-scans (so a
    // resolution recorded against one scan's finding survives a later scan's
    // fresh `id`). Nullable: legacy rows predate the key and are never
    // backfilled; only at-rest findings ever carry one. UNIQUE (not just
    // indexed): SQLite never equates two NULLs in a unique index, so any number
    // of in-flight/legacy NULL rows coexist freely, while a real key is the
    // `ON CONFLICT (finding_key) DO UPDATE` target the findings writer upserts
    // on — a re-scan of an unchanged file reconciles onto the same row instead
    // of duplicating it.
    findingKey: text(COL.findingKey),
    // Preserved first-detection time (epoch millis). Set once, on INSERT, from
    // the finding's parent event's occurred_at; the ON CONFLICT (finding_key)
    // upsert deliberately EXCLUDES it, so a re-detection under a later event
    // keeps the original detection time. Nullable (see BaseFindingRow) — a plain
    // ADD COLUMN + one-time backfill (migration 0008); read paths COALESCE onto
    // occurred_at. Powers MTTR / the recently-resolved feed's detection time.
    firstDetectedAt: integer(COL.firstDetectedAt),
  },
  (t) => [
    index('idx_findings_event').on(t.eventId),
    uniqueIndex('uq_findings_key').on(t.findingKey),
  ],
);

// FINDING RESOLUTION — a user's disposition of a finding (by finding_key, not
// the row-specific findings.id), so it survives the finding being re-detected
// under a fresh id on a later scan. Append-only-ish: one row is written per
// resolution action; evidence is a free-form text justification/reference.
export const findingResolution = sqliteTable(
  'finding_resolution',
  {
    id: text(COL.id).primaryKey(),
    findingKey: text(COL.findingKey).notNull(),
    status: text(COL.status).notNull(),
    method: text(COL.method).notNull(),
    resolvedAt: integer(COL.resolvedAt).notNull(),
    evidence: text(COL.evidence),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [index('idx_finding_resolution_key').on(t.findingKey)],
);

export const policies = sqliteTable(
  'policies',
  {
    id: text(COL.id).primaryKey(),
    scope: text(COL.scope, { enum: ['global', 'repo', 'user'] })
      .notNull()
      .default('global'),
    target: text(COL.target).notNull(),
    action: text(COL.action).notNull(),
    enabled: integer(COL.enabled, { mode: 'boolean' }).notNull().default(true),
    customKeywords: text(COL.customKeywords),
    name: text(COL.name),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [uniqueIndex('uq_policies_scope_target').on(t.scope, t.target)],
);

export const installedPacks = sqliteTable(
  'installed_packs',
  {
    id: text(COL.id).primaryKey(),
    namespace: text(COL.namespace).notNull(),
    packId: text(COL.packId).notNull(),
    version: text(COL.version).notNull(),
    name: text(COL.name).notNull(),
    rulesJson: text(COL.rulesJson).notNull(),
    enabled: integer(COL.enabled, { mode: 'boolean' }).notNull().default(true),
    // The PACK's per-pack enforcement policy: a BuiltinPolicyId ARCHETYPE string
    // (monitor|warn|redact|block), NEVER a policies-table Policy.id guid. This is
    // the third enforcement axis (see PolicyTarget) — a pack, not a rule or a
    // category. NULL == unassigned == Monitor (DEFAULT_PACK_POLICY_ID). Resolved
    // to an action via policyIdToAction; the runtime expands it into
    // per-rule policies so it actually gates enforcement.
    policyId: text(COL.policyId),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [uniqueIndex('uq_installed_packs_pack').on(t.namespace, t.packId)],
);

// AVAILABLE PACKS — the detection inventory the CURRENTLY RUNNING plugin/CLI
// binary ships, mirrored on every gateway open / `aka init`. This is metadata
// about the binary, not user state: comparing a row here against its
// installed_packs counterpart is how the dashboards/CLI compute "update
// available" (version OR rule-content drift). Updates are applied MANUALLY by
// copying a row from this table into installed_packs — the seeding path never
// mutates an existing installed row. rules_json is carried (not just version)
// so an applier with no bundled rules of its own (the OSS web-ui) can copy the
// snapshot straight from the store.
export const availablePacks = sqliteTable(
  'available_packs',
  {
    id: text(COL.id).primaryKey(),
    namespace: text(COL.namespace).notNull(),
    packId: text(COL.packId).notNull(),
    version: text(COL.version).notNull(),
    name: text(COL.name).notNull(),
    rulesJson: text(COL.rulesJson).notNull(),
    // Which binary last rewrote this mirror row, as `<binary>@<version>`
    // (e.g. `plugin@0.0.2-alpha.8`, `aka-cli@0.0.2-alpha.8`). Nullable —
    // pre-hardening writers never set it. Powers the stale-session notice
    // (an old plugin session learns a newer binary recorded here) and
    // mixed-version forensics.
    recordedBy: text(COL.recordedBy),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [uniqueIndex('uq_available_packs_pack').on(t.namespace, t.packId)],
);

// PACK WRITE GATE — a one-row control table backing the installed_packs
// write-gate trigger (added by hand in migration 0006; drizzle does not model
// triggers). The trigger silently ignores (RAISE(IGNORE)) any UPDATE of
// version/name/rules_json on installed_packs unless `open = 1`, and the ONLY
// writer that opens the gate is applyUpdate — inside its own transaction, so
// the gate can never be left open. This defends the manual-updates invariant
// against ALREADY-SHIPPED binaries (≤0.0.2-alpha.5 hooks run a compiled-in
// auto-sync upsert that no app-level guard can reach): the invariant lives in
// the database itself. enabled/policy_id/updated_at stay freely updatable
// (the trigger is column-scoped), and INSERTs are unaffected.
//
// SCOPE (deliberate): the gate exists ONLY in this local
// SQLite store. The clobber forensics are a local-store phenomenon — cached
// plugin generations running compiled-in SQL against the shared local file.
export const packWriteGate = sqliteTable(
  '_pack_write_gate',
  {
    id: integer(COL.id).primaryKey(),
    open: integer(COL.open).notNull().default(0),
  },
  (t) => [check('ck_pack_write_gate_single_row', sql`${t.id} = 1`)],
);

// EXCEPTIONS — user-approved grants letting one specific detected value pass an
// enforcing policy. Match key: (rule_id, value_fingerprint), where the
// fingerprint is a keyed HMAC-SHA256 of the raw match — never the value itself,
// never reversible. Lifecycle state is DERIVED, never stored: a row is active
// iff revoked_at IS NULL AND (expires_at IS NULL OR in the future) AND
// (max_uses IS NULL OR use_count < max_uses). Consumed/expired/revoked rows are
// retained as audit evidence; consumption is a single conditional UPDATE that
// increments use_count. expires_at / last_used_at / created_at / updated_at /
// revoked_at are epoch-millis integers; conditions is a JSON text column.
export const exceptions = sqliteTable(
  'exceptions',
  {
    id: text(COL.id).primaryKey(),
    ruleId: text(COL.ruleId).notNull(),
    category: text(COL.category).notNull(),
    valueFingerprint: text(COL.valueFingerprint).notNull(),
    keyVersion: integer(COL.keyVersion).notNull(),
    maskedValue: text(COL.maskedValue).notNull(),
    scope: text(COL.scope, { enum: ['once', 'temporary', 'permanent'] }).notNull(),
    expiresAt: integer(COL.expiresAt),
    maxUses: integer(COL.maxUses),
    useCount: integer(COL.useCount).notNull().default(0),
    lastUsedAt: integer(COL.lastUsedAt),
    justification: text(COL.justification).notNull(),
    conditions: text(COL.conditions),
    createdBy: text(COL.createdBy).notNull(),
    createdVia: text(COL.createdVia, {
      enum: ['cli-approve', 'cli-add', 'web-approve', 'web-add', 'api'],
    }).notNull(),
    createdAt: integer(COL.createdAt).notNull(),
    updatedAt: integer(COL.updatedAt).notNull(),
    revokedAt: integer(COL.revokedAt),
    revokedBy: text(COL.revokedBy),
    revokeReason: text(COL.revokeReason),
  },
  (t) => [
    // One unrevoked grant per (rule, value, key version). PARTIAL on
    // revoked_at IS NULL: revoking frees the slot so the same value can be
    // re-granted later without colliding with the retained terminal row.
    // This index also serves the evaluation lookup — (rule_id,
    // value_fingerprint) is its left prefix under the same predicate, so a
    // separate lookup index would be pure write amplification.
    uniqueIndex('uq_exceptions_active')
      .on(t.ruleId, t.valueFingerprint, t.keyVersion)
      .where(sql`revoked_at IS NULL`),
  ],
);

// ─── [Meta] data model — tenant-free local mirror ───────────────────────────
// The inventory / audit / inspection dimensions of the meta data model,
// here without tenant_id / user_id (single-node, tenant-free local store).
// Content-addressed ids dedupe within the store.

// INVENTORY — host / harness / user dimension, content-addressed.
export const inventory = sqliteTable(
  'inventory',
  {
    id: text(COL.id).primaryKey(),
    objectType: text(COL.objectType, {
      enum: ['host', 'harness', 'user', 'skill', 'hook', 'mcp_server', 'config_file'],
    }).notNull(),
    location: text(COL.location),
    title: text(COL.title),
    // intra-inventory edge: a harness/user row points at its host row.
    hostId: text(COL.hostId).references((): AnySQLiteColumn => inventory.id),
    attributes: text(COL.attributes).notNull(),
    osVersion: text(COL.osVersion).generatedAlwaysAs(
      sql`json_extract(attributes, '$.os_version')`,
      { mode: 'virtual' },
    ),
    harnessVersion: text(COL.harnessVersion).generatedAlwaysAs(
      sql`json_extract(attributes, '$.harness_version')`,
      { mode: 'virtual' },
    ),
    firstSeen: integer(COL.firstSeen).notNull(),
    lastSeen: integer(COL.lastSeen).notNull(),
  },
  (t) => [
    index('idx_inventory_type').on(t.objectType),
    index('idx_inventory_type_osver').on(t.objectType, t.osVersion),
    index('idx_inventory_type_harnessver').on(t.objectType, t.harnessVersion),
  ],
);

// SOURCE / PROJECT — content-addressed by remote url. Kept identical to
// BaseSourceProjectRow (the no-divergence column-set contract): the Inventory
// read model's per-project extras (visibility / language / policy_default) and the
// sample `provenance` marker live in the `attributes` JSON, NOT as columns, so this
// shared meta table's shape never diverges from base.
export const sourceProject = sqliteTable('source_project', {
  id: text(COL.id).primaryKey(),
  url: text(COL.url),
  name: text(COL.name),
  attributes: text(COL.attributes).notNull(),
  firstSeen: integer(COL.firstSeen).notNull(),
  lastSeen: integer(COL.lastSeen).notNull(),
});

// AUDIT EVENT (timeline) — polymorphic fact, self-ref tree.
export const auditEvents = sqliteTable(
  'audit_events',
  {
    id: text(COL.id).primaryKey(),
    parentId: text(COL.parentId).references((): AnySQLiteColumn => auditEvents.id),
    rootSessionId: text(COL.rootSessionId).references((): AnySQLiteColumn => auditEvents.id),
    eventType: text(COL.eventType, {
      enum: [
        'session',
        'run',
        'tool_call',
        'llm_call',
        'source_lookup',
        'prompt',
        'response',
        'code_change',
        'config_scan',
      ],
    }).notNull(),
    hostId: text(COL.hostId).references(() => inventory.id),
    harnessId: text(COL.harnessId).references(() => inventory.id),
    sourceProjectId: text(COL.sourceProjectId).references(() => sourceProject.id),
    startedAt: integer(COL.startedAt).notNull(),
    endedAt: integer(COL.endedAt),
    severity: text(COL.severity),
    priority: text(COL.priority),
    content: text(COL.content),
    contentHash: text(COL.contentHash),
    attributes: text(COL.attributes),
    // Token usage (input/output/cache tokens, model, provider) is snapshotted into
    // `attributes` on llm_call rows and surfaced as generated columns so rollups can
    // SUM/index them without re-running json_extract per row.
    inputTokens: integer(COL.inputTokens).generatedAlwaysAs(
      sql`json_extract(attributes, '$.input_tokens')`,
      { mode: 'virtual' },
    ),
    outputTokens: integer(COL.outputTokens).generatedAlwaysAs(
      sql`json_extract(attributes, '$.output_tokens')`,
      { mode: 'virtual' },
    ),
    cacheCreationInputTokens: integer(COL.cacheCreationInputTokens).generatedAlwaysAs(
      sql`json_extract(attributes, '$.cache_creation_input_tokens')`,
      { mode: 'virtual' },
    ),
    cacheReadInputTokens: integer(COL.cacheReadInputTokens).generatedAlwaysAs(
      sql`json_extract(attributes, '$.cache_read_input_tokens')`,
      { mode: 'virtual' },
    ),
    model: text(COL.model).generatedAlwaysAs(sql`json_extract(attributes, '$.model')`, {
      mode: 'virtual',
    }),
    provider: text(COL.provider).generatedAlwaysAs(sql`json_extract(attributes, '$.provider')`, {
      mode: 'virtual',
    }),
  },
  (t) => [
    index('idx_audit_parent').on(t.parentId),
    index('idx_audit_session').on(t.rootSessionId, t.startedAt),
    index('idx_audit_harness_t').on(t.harnessId, t.startedAt),
    index('idx_audit_project_t').on(t.sourceProjectId, t.startedAt),
    // Token rollups only ever read llm_call rows, so this is a PARTIAL index on
    // event_type='llm_call' — it serves the by-session/by-day SUM access paths
    // without taxing writes of every other (far more numerous) event_type.
    index('idx_audit_session_type')
      .on(t.rootSessionId, t.startedAt)
      .where(sql`event_type = 'llm_call'`),
  ],
);

// CLASSIFIED DATA — small CLASS dimension, keyed by class only.
export const classifiedData = sqliteTable('classified_data', {
  id: text(COL.id).primaryKey(),
  class: text(COL.classKey).notNull(),
  label: text(COL.label),
  attributes: text(COL.attributes),
});

// INSPECTION DEFINITION — a detection rule version (id = sha256(rule_id+version)).
export const inspectionDefinitions = sqliteTable('inspection_definitions', {
  id: text(COL.id).primaryKey(),
  ruleId: text(COL.ruleId).notNull(),
  name: text(COL.name).notNull(),
  category: text(COL.category).notNull(),
  severity: text(COL.severity).notNull(),
  definition: text(COL.definition).notNull(),
  version: text(COL.version).notNull(),
});

// INSPECTION FINDING — a hit of a definition against an audit event.
export const inspectionFindings = sqliteTable(
  'inspection_findings',
  {
    id: text(COL.id).primaryKey(),
    auditEventId: text(COL.auditEventId)
      .notNull()
      .references(() => auditEvents.id),
    inspectionDefinitionId: text(COL.inspectionDefinitionId)
      .notNull()
      .references(() => inspectionDefinitions.id),
    classifiedDataId: text(COL.classifiedDataId).references(() => classifiedData.id),
    spanStart: integer(COL.spanStart).notNull(),
    spanEnd: integer(COL.spanEnd).notNull(),
    maskedMatch: text(COL.maskedMatch).notNull(),
    actionTaken: text(COL.actionTaken).notNull(),
    confidence: real(COL.confidence).notNull(),
  },
  (t) => [index('idx_inspection_findings_event').on(t.auditEventId)],
);

// ─── Data Shares (outbound egress) — tenant-free local mirror ────────────────
// Outbound data egress detected in the user's software, grouped by destination
// (provider / internal domain / raw IP) → endpoint → call-site. The share_*
// tables are tenant-free. trust/status/network are DERIVED on
// read from kind/trust/transport (+ any egress_decision_override), so only the
// base facts live here. Seeded sample rows carry provenance='sample'.

// DESTINATION — one host we send data to.
export const shareDestination = sqliteTable(
  'share_destination',
  {
    id: text(COL.id).primaryKey(),
    kind: text(COL.kind, { enum: ['provider', 'internal', 'ip'] }).notNull(),
    name: text(COL.name).notNull(),
    host: text(COL.host).notNull(),
    category: text(COL.category).notNull(),
    trust: text(COL.trust).notNull(),
    note: text(COL.note),
    networkJson: text(COL.networkJson),
    lastSeen: integer(COL.lastSeen).notNull(),
    provenance: text(COL.provenance).notNull().default('scan'),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_share_destination_kind').on(t.kind),
    uniqueIndex('uq_share_destination_host').on(t.host),
  ],
);

// ENDPOINT — one method+url path on a destination.
export const shareEndpoint = sqliteTable(
  'share_endpoint',
  {
    id: text(COL.id).primaryKey(),
    destinationId: text(COL.destinationId)
      .notNull()
      .references(() => shareDestination.id),
    method: text(COL.method).notNull(),
    transport: text(COL.transport).notNull(),
    url: text(COL.url).notNull(),
    template: integer(COL.template, { mode: 'boolean' }).notNull().default(false),
    dataClass: text(COL.dataClass).notNull(),
    lastSeen: integer(COL.lastSeen).notNull(),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_share_endpoint_dest').on(t.destinationId),
    uniqueIndex('uq_share_endpoint').on(t.destinationId, t.method, t.url),
  ],
);

// CALL SITE — one source location that reaches an endpoint.
export const shareCallSite = sqliteTable(
  'share_call_site',
  {
    id: text(COL.id).primaryKey(),
    endpointId: text(COL.endpointId)
      .notNull()
      .references(() => shareEndpoint.id),
    project: text(COL.project).notNull(),
    file: text(COL.file).notNull(),
    line: integer(COL.line).notNull(),
    snippet: text(COL.snippet).notNull(),
    dynamic: integer(COL.dynamic, { mode: 'boolean' }).notNull().default(false),
    vendored: integer(COL.vendored, { mode: 'boolean' }).notNull().default(false),
    projectId: text(COL.projectId),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_share_call_site_endpoint').on(t.endpointId),
    uniqueIndex('uq_share_call_site').on(t.endpointId, t.project, t.file, t.line),
  ],
);

// EGRESS DECISION OVERRIDE — a user allow/block decision on a destination.
export const egressDecisionOverride = sqliteTable(
  'egress_decision_override',
  {
    id: text(COL.id).primaryKey(),
    destinationId: text(COL.destinationId)
      .notNull()
      .references(() => shareDestination.id),
    decision: text(COL.decision).notNull(),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [uniqueIndex('uq_egress_decision_override').on(t.destinationId)],
);

// ─── Inventory API (asset model) — tenant-free local store ───────────────────
// The rich asset inventory the Inventory page renders: skills / MCP
// servers / hooks / config as inventory_asset, their harness edges as
// harness_asset (→ the inventory harness rows), and per-project files with
// per-file LLM access. Tenant-free. Seeded
// sample assets carry provenance='sample'.

// ASSET — a skill / mcp / hook / config artifact.
export const inventoryAsset = sqliteTable(
  'inventory_asset',
  {
    id: text(COL.id).primaryKey(),
    assetType: text(COL.assetType).notNull(),
    name: text(COL.name).notNull(),
    sub: text(COL.sub),
    description: text(COL.description),
    flagsJson: text(COL.flagsJson).notNull().default('[]'),
    metaJson: text(COL.metaJson).notNull().default('{}'),
    trust: text(COL.trust),
    toolsJson: text(COL.toolsJson),
    provenance: text(COL.provenance).notNull().default('scan'),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [index('idx_inventory_asset_type').on(t.assetType)],
);

// HARNESS ↔ ASSET edge — which harness exposes which asset.
export const harnessAsset = sqliteTable(
  'harness_asset',
  {
    id: text(COL.id).primaryKey(),
    harnessId: text(COL.harnessId)
      .notNull()
      .references(() => inventory.id),
    assetId: text(COL.assetId)
      .notNull()
      .references(() => inventoryAsset.id),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_harness_asset_harness').on(t.harnessId),
    uniqueIndex('uq_harness_asset').on(t.harnessId, t.assetId),
  ],
);

// PROJECT FILE — one file in a connected project, with its default LLM access.
export const projectFile = sqliteTable(
  'project_file',
  {
    id: text(COL.id).primaryKey(),
    projectId: text(COL.projectId)
      .notNull()
      .references(() => sourceProject.id),
    path: text(COL.path).notNull(),
    name: text(COL.name).notNull(),
    origin: text(COL.origin).notNull(),
    defaultAccess: text(COL.defaultAccess).notNull(),
    findingsCount: integer(COL.findingsCount).notNull().default(0),
    blockedAt: integer(COL.blockedAt),
    note: text(COL.note),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_project_file_project').on(t.projectId),
    uniqueIndex('uq_project_file').on(t.projectId, t.path),
  ],
);

// FILE ACCESS OVERRIDE — a user's per-file LLM-access decision.
export const fileAccessOverride = sqliteTable(
  'file_access_override',
  {
    id: text(COL.id).primaryKey(),
    projectId: text(COL.projectId)
      .notNull()
      .references(() => sourceProject.id),
    path: text(COL.path).notNull(),
    access: text(COL.access).notNull(),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    index('idx_file_access_override_project').on(t.projectId),
    uniqueIndex('uq_file_access_override').on(t.projectId, t.path),
  ],
);

// MCP TRUST OVERRIDE — a user's trust classification for an MCP asset.
export const mcpTrustOverride = sqliteTable(
  'mcp_trust_override',
  {
    id: text(COL.id).primaryKey(),
    // Opaque asset id — deliberately NO foreign key (dropped in 0005). Trust
    // overrides span two id namespaces that never collide: sample
    // `inventory_asset` rows and the content-addressed meta `inventory` rows
    // real scanned MCP servers live in. A user trust decision must survive the
    // scanner's Type-1 bag replace, so it can never ride the inventory row
    // itself — and an FK to either table would reject the other's ids under
    // PRAGMA foreign_keys = ON.
    assetId: text(COL.assetId).notNull(),
    trust: text(COL.trust).notNull(),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [uniqueIndex('uq_mcp_trust_override').on(t.assetId)],
);
