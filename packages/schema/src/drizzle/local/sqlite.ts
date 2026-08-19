// The local store — SQLite dialect, one store per machine.
//
// This is the canonical schema for the plugin/CLI's ~/.aka/data/aka.db store.
// Every row in it belongs to the machine it sits on, so it carries no owner
// columns, no FKs to an account catalog and no auth tables: identity is the file
// path, and the OS account that owns the file is the only boundary.
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
    // Drizzle's `enum` is a TypeScript-level narrowing only — it emits no SQL
    // CHECK — so widening this list needs no migration: stores written by an
    // older build accept a 'tool_use' row as-is.
    kind: text(COL.kind, { enum: ['prompt', 'response', 'code_change', 'tool_use'] }).notNull(),
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
  (t) => [
    index('idx_finding_resolution_key').on(t.findingKey),
    // Serves the resolution-driven /security reads, which ask "which findings
    // were resolved in this window" and therefore drive from a resolved_at range.
    // With finding_key as the table's only index that range had none to scan, so
    // the read passed over the whole table — a bare `SCAN fr`, which is the one
    // thing `hot-read-query-plans.test.ts` hard-fails on.
    index('idx_finding_resolution_resolved_at').on(t.resolvedAt),
  ],
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
    // What the grant authorizes; 'reveal_to_model' also satisfies suppression
    // (strictly stronger), while 'suppress' never reveals.
    capability: text(COL.capability, { enum: ['suppress', 'reveal_to_model'] })
      .notNull()
      .default('suppress'),
    scope: text(COL.scope, { enum: ['once', 'temporary', 'permanent'] }).notNull(),
    expiresAt: integer(COL.expiresAt),
    maxUses: integer(COL.maxUses),
    useCount: integer(COL.useCount).notNull().default(0),
    lastUsedAt: integer(COL.lastUsedAt),
    justification: text(COL.justification).notNull(),
    conditions: text(COL.conditions),
    createdBy: text(COL.createdBy).notNull(),
    createdVia: text(COL.createdVia, {
      enum: ['cli-approve', 'cli-add', 'web-approve', 'web-add', 'api', 'setup-triage'],
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

// ─── [Meta] data model — local mirror ────────────────────────────────────────
// The inventory / audit / inspection dimensions of the meta data model,
// here without owner columns — one store per machine.
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
        'tool_use',
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
    // Serves the time-range read family that scans a single event_type across
    // a start/end window (e.g. the Activity timeline, token rollups by day)
    // without a full-table scan.
    index('idx_audit_type_t').on(t.eventType, t.startedAt),
    // Serves the newest-first reads that span every event_type — the flat
    // findings list walks (started_at DESC, id DESC) in keyset batches, which
    // the composite indexes above cannot serve because none of them leads with
    // started_at. Without it each batch sorts the whole remaining scope.
    index('idx_audit_started_at').on(t.startedAt),
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
    // Stable, content-addressed key correlating a finding across re-scans, mirroring
    // findings.findingKey. Nullable and UNIQUE (not just indexed): SQLite never
    // equates two NULLs in a unique index, so legacy/in-flight NULL rows coexist
    // freely. Not yet populated — no writer sets it.
    findingKey: text(COL.findingKey),
    // Preserved first-detection time (epoch millis), mirroring
    // findings.firstDetectedAt. Nullable — added via a plain ADD COLUMN with no
    // backfill. Not yet populated — no writer sets it.
    firstDetectedAt: integer(COL.firstDetectedAt),
  },
  (t) => [
    index('idx_inspection_findings_event').on(t.auditEventId),
    uniqueIndex('uq_inspection_findings_key').on(t.findingKey),
  ],
);

// ─── Data Shares (outbound egress) — local mirror ────────────────────────────
// Outbound data egress detected in the user's software, grouped by destination
// (provider / internal domain / raw IP) → endpoint → call-site. The share_*
// tables carry no owner columns. trust/status/network are DERIVED on
// read from kind/trust/transport (+ any egress_decision_override), so only the
// base facts live here. Seeded sample rows carry provenance='sample'.

// DESTINATION — one host we send data to.
export const shareDestination = sqliteTable(
  'share_destination',
  {
    id: text(COL.id).primaryKey(),
    kind: text(COL.kind, { enum: ['provider', 'internal', 'external', 'ip'] }).notNull(),
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
    // Stable per-project reconcile key ('git:<repo identity>' or
    // 'path:<absolute root>'). `project` is a display name and never keys
    // reconciliation. The default exists so the column can be added to stores
    // that already hold rows; writers always supply it explicitly.
    projectKey: text(COL.projectKey).notNull().default(''),
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
    // Per-project reconcile, last-seen confirmation and totals all filter on
    // project_key alone; uq_share_call_site leads with endpoint_id and cannot
    // serve that seek. endpoint_id trails so those queries stay covering.
    index('idx_share_call_site_project').on(t.projectKey, t.endpointId),
    uniqueIndex('uq_share_call_site').on(t.endpointId, t.projectKey, t.file, t.line),
  ],
);

// EGRESS DECISION OVERRIDE — a user allow/block decision on a destination.
export const egressDecisionOverride = sqliteTable(
  'egress_decision_override',
  {
    id: text(COL.id).primaryKey(),
    // Nullable, ON DELETE SET NULL: pruning a destination clears this pointer
    // instead of blocking the delete, so a host-keyed row outlives the
    // destination it was made on.
    destinationId: text(COL.destinationId).references(() => shareDestination.id, {
      onDelete: 'set null',
    }),
    // The decision's host. It is what the read joins on, so a row survives its
    // destination being pruned and re-attaches when the same host is detected
    // again under a fresh id. NULL on rows written before the column existed,
    // which are matched by destination_id instead.
    host: text(COL.host),
    decision: text(COL.decision).notNull(),
    createdAt: integer(COL.createdAt)
      .notNull()
      .$defaultFn(() => Date.now()),
    updatedAt: integer(COL.updatedAt)
      .notNull()
      .$defaultFn(() => Date.now()),
  },
  (t) => [
    uniqueIndex('uq_egress_decision_override').on(t.destinationId),
    // PARTIAL on host IS NOT NULL: one decision per host, while any number of
    // host-NULL rows coexist.
    uniqueIndex('uq_egress_decision_override_host')
      .on(t.host)
      .where(sql`\`host\` IS NOT NULL`),
  ],
);

// ─── Inventory API (asset model) — local store ───────────────────────────────
// The rich asset inventory the Inventory page renders: skills / MCP
// servers / hooks / config as inventory_asset, their harness edges as
// harness_asset (→ the inventory harness rows), and per-project files with
// per-file LLM access. No owner columns. Seeded
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

// ─── Secret vault — the reversible store ─────────────────────────────────────
// Everywhere else a detected value is destroyed or reduced to a one-way keyed
// fingerprint. Here it survives as AEAD ciphertext, so its owner can get it back
// while the model only ever holds the pointer. The raw value appears ONLY in the
// `ciphertext` column — never in masked_match, never in an index, never in a
// deref audit row.

// SECRET VAULT — one row per detected VALUE, unique on the keyed fingerprint, so
// the same secret seen twice yields one row and one pointer.
export const secretVault = sqliteTable(
  'secret_vault',
  {
    // The stable random surrogate the wire pointer carries. NOT the fingerprint:
    // putting keyed-HMAC material on the wire would leak correlation material
    // into model context and into committed files.
    pointerId: text(COL.pointerId).primaryKey(),
    // HMAC of the raw under `exception.key`, and the epoch it was derived under.
    // This is what a reveal grant matches on; it rotates independently of
    // key_version below (different key, different rotation semantics).
    valueFingerprint: text(COL.valueFingerprint).notNull(),
    fingerprintKeyVersion: integer(COL.fingerprintKeyVersion).notNull(),
    // The vault-key epoch this row's ciphertext is sealed under.
    keyVersion: integer(COL.keyVersion).notNull(),
    // The pointer-format generation (POINTER_FORMAT_VERSION) this row's
    // ciphertext AAD is bound under — the AAD only, never the wire tag, which
    // is checked against the current constant before any row is looked up.
    // Recorded per row so a future format bump can still open and re-seal
    // existing entries instead of stranding them. Default 2: every row written
    // before this column existed was sealed under format version 2.
    formatVersion: integer(COL.formatVersion).notNull().default(2),
    // Fixed at first mint, never updated on re-detection: the same value seen
    // later under a different rule's category keeps its minted category, so one
    // value always yields exactly one wire token.
    category: text(COL.category).notNull(),
    ruleId: text(COL.ruleId).notNull(),
    maskedMatch: text(COL.maskedMatch).notNull(),
    provider: text(COL.provider),
    ciphertext: text(COL.ciphertext).notNull(),
    nonce: text(COL.nonce).notNull(),
    authTag: text(COL.authTag).notNull(),
    // How often this VALUE has been detected on this machine — the reuse signal.
    // Distinct from secret_vault_deref.pointer_count.
    occurrenceCount: integer(COL.occurrenceCount).notNull().default(1),
    firstSeen: integer(COL.firstSeen).notNull(),
    lastSeen: integer(COL.lastSeen).notNull(),
  },
  (t) => [
    // One row per value — this is what makes the pointer deterministic and the
    // reuse count meaningful.
    uniqueIndex('uq_secret_vault_value').on(t.valueFingerprint),
    // The dashboard inventory's keyset page: newest-first by last_seen, broken
    // by the primary key. Without it every page full-scans the table and sorts
    // it in a temp B-tree, so paging bounds the payload but not the query.
    index('idx_secret_vault_last_seen').on(t.lastSeen, t.pointerId),
    // The reuse list's keyset page, ranked by how often a value recurs. Same
    // argument as above — it is a second ORDER BY over the same table, and
    // without its own index it lands in exactly the temp-B-tree scan the line
    // above exists to avoid.
    index('idx_secret_vault_reuse').on(t.occurrenceCount, t.pointerId),
  ],
);

// SECRET VAULT SIGHTING — where a pointer has been written: one row per
// (pointer, location), timestamps bumped on re-sighting. Deliberately no FK to
// secret_vault: the record of where pointers went is itself evidence and must
// survive a purge, exactly like the deref trail.
export const secretVaultSighting = sqliteTable(
  'secret_vault_sighting',
  {
    id: text(COL.id).primaryKey(),
    pointerId: text(COL.pointerId).notNull(),
    location: text(COL.location).notNull(),
    kind: text(COL.kind, {
      enum: ['prompt', 'tool-input', 'tool-output', 'file', 'transcript'],
    }).notNull(),
    firstSeen: integer(COL.firstSeen).notNull(),
    lastSeen: integer(COL.lastSeen).notNull(),
  },
  (t) => [
    // Also serves every by-pointer lookup as its left prefix — no separate
    // single-column index.
    uniqueIndex('uq_secret_vault_sighting').on(t.pointerId, t.location),
  ],
);

// SECRET VAULT DEREF — the audit trail. Every de-reference writes one, whatever
// the outcome. Never carries the raw value or the ciphertext.
export const secretVaultDeref = sqliteTable(
  'secret_vault_deref',
  {
    id: text(COL.id).primaryKey(),
    // Deliberately NO foreign key to secret_vault: purging the vault must not
    // erase the record that a de-reference happened.
    pointerId: text(COL.pointerId).notNull(),
    at: integer(COL.at).notNull(),
    target: text(COL.target, { enum: ['human', 'model'] }).notNull(),
    reason: text(COL.reason, {
      enum: ['display', 'explicit-reveal', 'view-render', 'model-input', 'remediation', 'purge'],
    }).notNull(),
    outcome: text(COL.outcome, { enum: ['revealed', 'refused', 'unavailable'] }).notNull(),
    // Present only on a model crossing a reveal grant authorized.
    grantId: text(COL.grantId),
    // How many pointers ONE batched render resolved; 1 when unbatched. The
    // model crossings are never batched, so theirs is always 1.
    pointerCount: integer(COL.pointerCount).notNull().default(1),
  },
  (t) => [
    index('idx_secret_vault_deref_pointer').on(t.pointerId),
    // The audit view's default read: model crossings newest-first.
    index('idx_secret_vault_deref_reason_at').on(t.reason, t.at),
    // The trail's keyset page. The (reason, at) index above does not serve it:
    // its left prefix is `reason`, and the default read excludes reasons rather
    // than selecting them, so ordering across the rest still needs this one.
    // Still required: it serves the page with the batched toggle ON, where the
    // partial index below does not apply.
    index('idx_secret_vault_deref_at').on(t.at, t.id),
    // The same page with the toggle OFF, which is the default. The index above
    // orders that read but does not filter it, and `display`/`view-render` are
    // the high-volume reasons — so the walk descends `at`, fetches each row and
    // discards most of them on `reason`. Matching the list's own predicate makes
    // it index-only: measured 0.293 ms -> 0.032 ms over 100k rows at a 2%
    // surfaced ratio, first page and deep page alike.
    index('idx_secret_vault_deref_signal')
      .on(t.at, t.id)
      .where(sql`${t.reason} NOT IN ('display', 'view-render')`),
  ],
);
