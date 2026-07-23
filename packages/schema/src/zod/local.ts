// Local-mode contracts: the plugin-owned ~/.aka settings + machine-local
// identity, plus pure row mappers from the wire shapes (IngestEvent /
// DetectedFinding) to the SQLite `events`/`findings` tables.
//
// No I/O and NO @akasecurity/detections dependency: masking of a raw match happens in
// the SDK *before* a DetectedFinding is built, so these mappers only reshape.
import { z } from 'zod';

import type {
  auditEvents,
  classifiedData,
  events,
  exceptions,
  findings,
  inspectionDefinitions,
  inspectionFindings,
  inventory,
  sourceProject,
} from '../drizzle/local/sqlite.ts';
import { isoToEpochMillis } from '../time.ts';
import type { IngestEvent } from './event.ts';
import type { ActionTaken, DetectedFinding } from './finding.ts';
import type {
  AuditEventInput,
  ClassifiedDataInput,
  InspectionDefinitionInput,
  InspectionFindingInput,
  InventoryInput,
  SourceProjectInput,
} from './meta.ts';
import type { Rule } from './rule.ts';

// Bumped whenever WorkspaceSettings gains or loses a field, so the loader can
// migrate an older settings.json. v2 added historicalAccess; v3 added
// dataSharesInPlace.
export const WORKSPACE_SETTINGS_SPEC_VERSION = 3;

// How the plugin runs. Single-valued: the plugin operates entirely against the
// local store. Kept as an enum so the settings file stays explicit and the
// value set can grow without a shape change.
export const RunMode = z.enum(['standalone']);
export type RunMode = z.infer<typeof RunMode>;

// What happens to detected sensitive data (the onboarding "handling" choice).
// The single-action precursor to the structured Policy/PolicyBundle that grouped
// detection policies will use.
export const SimpleDetectionPolicy = z.enum(['redact', 'warn']);
export type SimpleDetectionPolicy = z.infer<typeof SimpleDetectionPolicy>;

// What AKA may review beyond the live session (the onboarding "historical &
// memory access" choice). 'full' consents to scanning pre-install surfaces —
// scratch/temp files, agent memory and prior conversation transcripts — for
// already-leaked secrets; 'session-only' declines, limiting AKA to what the
// current session, working tree, git history and pointed scans already cover.
// Default is 'session-only': historical scanning needs explicit opt-in, never
// an assumed grant on an upgrade.
export const HistoricalAccess = z.enum(['full', 'session-only']);
export type HistoricalAccess = z.infer<typeof HistoricalAccess>;

// Onboarding answers + global prefs, persisted to ~/.aka/settings/settings.json.
// Versioned and default-filled so future config steps are additive: a
// settings.json written by an older plugin still parses, with any missing key
// taking its default.
//
// Plugin-local only — deliberately NO `.meta({ id })`. An id would register this
// in Zod's global registry, and a @fastify/swagger setup
// emits every registered schema as an OpenAPI component, leaking this plugin
// config into a public API client. No API route references it.
export const WorkspaceSettings = z.object({
  specVersion: z.number().int().positive().default(WORKSPACE_SETTINGS_SPEC_VERSION),
  // Settings files written by earlier releases may carry the retired 'attached'
  // value; it parses as 'standalone' so those files keep loading.
  runMode: z.preprocess(
    (v) => (v === 'attached' ? 'standalone' : v),
    RunMode.default('standalone'),
  ),
  policy: SimpleDetectionPolicy.default('redact'),
  // Consent for scanning pre-install surfaces; opt-in (see HistoricalAccess).
  historicalAccess: HistoricalAccess.default('session-only'),
  // In-place egress extraction on the scan paths; disable to stop all Data
  // Shares writes.
  dataSharesInPlace: z.boolean().default(true),
  // Absent until /aka:setup completes; its presence is what "onboarded" means.
  onboardedAt: z.iso.datetime().optional(),
});
export type WorkspaceSettings = z.infer<typeof WorkspaceSettings>;

// The default (unonboarded) settings the SDK falls back to when no file exists.
export function defaultWorkspaceSettings(): WorkspaceSettings {
  return WorkspaceSettings.parse({});
}

// Row shapes derived from the local Drizzle tables, so the mappers can never
// drift from the columns the local aka.db actually has. The SDK binds these by
// key with node:sqlite named params; the keys match the Drizzle property names.
export type EventRow = typeof events.$inferInsert;
export type FindingRow = typeof findings.$inferInsert;
export type ExceptionRow = typeof exceptions.$inferInsert;

// IngestEvent (the wire shape) -> events row. `occurred_at` is an epoch-millis
// integer column, so convert at the boundary; `metadata` is a JSON text column,
// so stringify it (or null).
export function toEventRow(event: IngestEvent): EventRow {
  return {
    id: event.id,
    sourceTool: event.sourceTool,
    kind: event.kind,
    occurredAt: isoToEpochMillis(event.occurredAt),
    contentHash: event.contentHash,
    content: event.content,
    metadata: event.metadata ? JSON.stringify(event.metadata) : null,
  };
}

// A DetectedFinding with the OSS-local-only finding_key correlation key already
// computed. Deliberately NOT part of the DetectedFinding zod contract (the
// public/API wire shape) — see drizzle/adherence.test.ts's "findings ≡
// BaseFindingRow + findingKey" guard: it is a local-only correlation key, not
// part of the public finding contract.
// Optional/nullable: only at-rest (worktree-scan) findings carry one — see
// @akasecurity/plugin-sdk's createPluginRuntime capture().
export type DetectedFindingWithKey = DetectedFinding & { findingKey?: string | null };

// DetectedFinding (already masked + assigned id/eventId/actionTaken by the SDK)
// -> findings row. `span` is split into the span_start/span_end columns. The raw
// matched text never reaches this layer.
export function toFindingRow(finding: DetectedFindingWithKey): FindingRow {
  return {
    id: finding.id,
    eventId: finding.eventId,
    ruleId: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
    spanStart: finding.span.start,
    spanEnd: finding.span.end,
    maskedMatch: finding.maskedMatch,
    actionTaken: finding.actionTaken,
    confidence: finding.confidence,
    findingKey: finding.findingKey ?? null,
  };
}

// --- meta data model row mappers -------------------------------------------
// The [Meta] Data Model tables (see ./meta.ts). Pure reshapers, like the two
// above: they take the content-addressed `id` already computed by the Node
// layer (`@akasecurity/persistence` — `@akasecurity/schema` stays Node-API-free), plus a
// capture-time `now` (epoch millis) for inventory lifecycle bookkeeping.
// JSON bags are stringified; the generated columns (os_version, harness_version)
// are derived by SQLite and never set here.

export type InventoryRow = typeof inventory.$inferInsert;
export type SourceProjectRow = typeof sourceProject.$inferInsert;
export type AuditEventRow = typeof auditEvents.$inferInsert;
export type ClassifiedDataRow = typeof classifiedData.$inferInsert;
export type InspectionDefinitionRow = typeof inspectionDefinitions.$inferInsert;
export type InspectionFindingRow = typeof inspectionFindings.$inferInsert;

// Meta row mappers for the single-node local store. Inventory
// FKs + tree pointers come pre-resolved on the input; `started_at`/`ended_at`/
// `first_seen`/`last_seen` are epoch-millis integers.
export function toInventoryRow(input: InventoryInput, id: string, now: number): InventoryRow {
  return {
    id,
    objectType: input.objectType,
    location: input.location ?? null,
    title: input.title ?? null,
    hostId: input.hostId ?? null,
    attributes: JSON.stringify(input.attributes),
    firstSeen: now,
    lastSeen: now,
  };
}

export function toSourceProjectRow(
  input: SourceProjectInput,
  id: string,
  now: number,
): SourceProjectRow {
  return {
    id,
    url: input.url,
    name: input.name ?? null,
    attributes: JSON.stringify(input.attributes),
    firstSeen: now,
    lastSeen: now,
  };
}

export function toAuditEventRow(input: AuditEventInput): AuditEventRow {
  return {
    id: input.id,
    parentId: input.parentId ?? null,
    rootSessionId: input.rootSessionId ?? null,
    eventType: input.eventType,
    hostId: input.hostId ?? null,
    harnessId: input.harnessId ?? null,
    sourceProjectId: input.sourceProjectId ?? null,
    startedAt: isoToEpochMillis(input.startedAt),
    endedAt: input.endedAt ? isoToEpochMillis(input.endedAt) : null,
    severity: input.severity ?? null,
    priority: input.priority ?? null,
    content: input.content ?? null,
    contentHash: input.contentHash ?? null,
    attributes: input.attributes ? JSON.stringify(input.attributes) : null,
  };
}

export function toClassifiedDataRow(input: ClassifiedDataInput, id: string): ClassifiedDataRow {
  return {
    id,
    class: input.class,
    label: input.label ?? null,
    attributes: input.attributes ? JSON.stringify(input.attributes) : null,
  };
}

export function toInspectionDefinitionRow(
  input: InspectionDefinitionInput,
  id: string,
): InspectionDefinitionRow {
  return {
    id,
    ruleId: input.ruleId,
    name: input.name,
    category: input.category,
    severity: input.severity,
    definition: input.definition,
    version: input.version,
  };
}

export function toInspectionFindingRow(input: InspectionFindingInput): InspectionFindingRow {
  return {
    id: input.id,
    auditEventId: input.auditEventId,
    inspectionDefinitionId: input.inspectionDefinitionId,
    classifiedDataId: input.classifiedDataId ?? null,
    spanStart: input.span.start,
    spanEnd: input.span.end,
    maskedMatch: input.maskedMatch,
    actionTaken: input.actionTaken,
    confidence: input.confidence,
  };
}

// --- read-projection DTOs --------------------------------------------------
// Plain TS types (NOT zod schemas, NO `.meta({ id })`): these are the shapes the
// plugin's read surfaces (/findings, /health, /audit) and the
// DataGateway return. Registering them in Zod's global registry would leak them
// into the generated OpenAPI client (see the `.meta` id-leak gotcha), and
// no API route references them — so they stay as bare interfaces consumed by
// `@akasecurity/persistence` and `@akasecurity/plugin-sdk` alike, without a cross-package dep.

// A finding joined with its event, shaped for the read surfaces. occurredAt is
// re-materialized as ISO so the presentation layer never touches epochs. The raw
// secret is never here — only `maskedMatch`.
export interface FindingView {
  id: string;
  eventId: string;
  ruleId: string;
  category: string;
  severity: string;
  maskedMatch: string;
  actionTaken: ActionTaken;
  confidence: number;
  occurredAt: string;
  sourceTool: string;
  kind: string;
}

export interface HealthSummary {
  findings: number;
  byAction: Record<ActionTaken, number>;
  // Whole-store open-findings count per severity. The store is append-only with
  // no resolution state yet, so every finding is "open" — these sum to `findings`.
  // The read surfaces' status bar reads its unreviewed tally from here (not from
  // whatever finding page a command happened to fetch), so the footer is stable
  // across /findings, /health and /recommend regardless of each command's limit.
  bySeverity: { critical: number; high: number; medium: number; low: number };
  // Fraction (0..1) of detection categories that have an enabled policy. Fresh
  // installs seed every category enabled (=1). Config-posture scoring is future.
  coverage: number;
}

export interface DayActivity {
  day: string; // YYYY-MM-DD (UTC)
  total: number;
  redacted: number;
  warned: number;
  blocked: number;
}

// One loaded detection pack, recorded into the local `installed_packs` table so
// the Detections dashboard can count detections/rules/active and compare the
// stored version against the registry ("global artifact") to flag updates. The
// plugin's standalone gateway upserts these on open from the SDK's bundled packs;
// `rules` is the snapshot persisted to rules_json (the per-pack rule count).
//
// Plugin-local — NO `.meta({ id })`, like every other type in this file: an id
// would register it in Zod's global registry and leak it into the
// generated OpenAPI client. No API route references it.
export interface InstalledPackInput {
  // Publisher handle the pack ships under (e.g. 'aka' for AKA-bundled library
  // packs). With packId it forms the (namespace, packId) upsert key.
  namespace: string;
  packId: string;
  version: string;
  name: string;
  // The rules actually loaded for this pack — snapshotted to rules_json.
  rules: Rule[];
}
