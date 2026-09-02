// Local-mode contracts: the plugin-owned ~/.aka settings + machine-local
// identity, plus pure row mappers from the wire shapes (IngestEvent /
// DetectedFinding) to the SQLite `events`/`findings` tables, and from the same
// wire shapes onto the generalized audit/inspection tables the live capture
// path (recordCapture) writes today.
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
  CaptureAttributes,
  ClassifiedDataInput,
  InspectionDefinitionInput,
  InspectionFindingInput,
  InventoryInput,
  SourceProjectInput,
} from './meta.ts';
import type { Rule } from './rule.ts';
import { VaultConsent, VaultInlineReveal, VaultKeyCustody } from './vault.ts';

// A changelog marker for the WorkspaceSettings shape, not a migration trigger:
// v2 added historicalAccess; v3 added dataSharesInPlace; v4 added
// modelJudgeConsent; v5 added the secret-vault fields (vaultConsent,
// vaultKeyCustody, vaultInlineReveal); v6 added historySyncConsent. Nothing
// reads it, and nothing re-stamps it — the `.default()` below only fills when
// the key is absent, and applyOnboarding's merge preserves whatever an existing
// settings.json already carries. So an already-onboarded machine keeps the
// version that first wrote its file, however often this is bumped. Every field
// added so far has been optional/defaulted (backward compatible), which is why
// no migration has been needed. Re-stamp this on write before relying on it to
// gate one.
export const WORKSPACE_SETTINGS_SPEC_VERSION = 6;

// The payload-shape version the /aka:setup model-judge sends to the model API.
// Recorded alongside a user's modelJudgeConsent so a consent granted against an
// older payload shape stops counting once this is bumped.
export const MODEL_JUDGE_PAYLOAD_VERSION = 1;

// The shape of the activity a machine sends to the deployment it is attached to
// on the DEFERRED path — the outbox. Recorded alongside a user's
// historySyncConsent so a grant given against a narrower payload stops counting
// once this is bumped: widening what is sent re-asks rather than assuming.
//
// v1 covered one lane: the activity already recorded BEFORE the machine
// attached, structural rows only, with `content` dropped by construction
// (rebuildAuditEvent) so no prompt or reply text could ride it.
//
// v2 WIDENS THE SUBJECT from "the pre-attach backlog" to "everything this
// machine still owes the deployment", which now includes CAPTURE rows whose
// `content` is the prompt / reply / tool-output text, masked only at detected
// spans. That is a genuinely different payload — it is the first version under
// which declining changes what text can leave the machine — so every v1 grant
// is invalidated and re-asked. The name is narrower than the meaning: the
// persisted key stays `historySyncConsent` because renaming an on-disk field
// would be this file's first settings migration, and the widened scope is
// carried by these comments and the copy rather than by a rename.
//
// What declining costs is bounded and is NOT a regression: the live forward is
// authorized by attaching and is unaffected. Declining only means an
// undelivered capture is DROPPED rather than retained and retried — exactly the
// behaviour of every release before the outbox existed.
export const HISTORY_SYNC_PAYLOAD_VERSION = 2;

// How the plugin runs.
//   'standalone' — everything against the local store under ~/.aka. No other
//     party participates, and this is the default and the only mode this
//     repository can complete on its own.
//   'attached'   — the machine is registered against an organization's own
//     deployment, which supplies policy and receives activity.
//
// THE TRANSPORT FOR 'attached' IS NOT IN THIS FILE, and the rule that keeps it
// out is narrower than it once was. This block used to say the transport was not
// in this TREE at all; @akasecurity/remote ended that — it is the one package
// here that reaches a network, and it reaches only the deployment a machine's
// own settings name.
//
// What lives here is still the STATE alone: the mode, the descriptor below, and
// nothing that parses, resolves or dials it. A machine set to 'attached' whose
// credential is missing or unusable behaves exactly as standalone; it never
// silently degrades detection.
export const RunMode = z.enum(['standalone', 'attached']);
export type RunMode = z.infer<typeof RunMode>;

// Which deployment this machine is attached to. Opaque to THIS FILE — nothing
// here parses, resolves or dials `endpoint`; it is stored so the dashboard can
// name what the user is attached to and so a detach has something to clear.
//
// "This file", not "this tree", for the same reason the RunMode block above was
// narrowed: @akasecurity/remote dials this endpoint, and the CLI and the local
// dashboard both ask it to. The block above was corrected when that landed and
// this one was not, which left the two neighbours disagreeing about the same
// fact — the weaker claim is the true one, and it is the only one this file can
// actually keep.
//
// DELIBERATELY CARRIES NO CREDENTIAL. A bearer token in settings.json would sit
// in a file every local process can read for as long as the attachment lasts,
// and this repository has no consumer for one. Whatever authenticates the
// attachment belongs to the distribution that owns the transport, in whatever
// store that distribution already uses for secrets.
export const ControlPlaneConnection = z
  .object({
    endpoint: z.string().min(1),
    // Display name for the deployment, shown instead of the raw endpoint.
    label: z.string().min(1).optional(),
    attachedAt: z.iso.datetime(),
  })
  .meta({ id: 'ControlPlaneConnection' });
export type ControlPlaneConnection = z.infer<typeof ControlPlaneConnection>;

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

// A recorded model-judge consent: when it was given, and the payload shape it
// was given against. Named here (rather than inlined on WorkspaceSettings) so
// the plugin, CLI and dashboard all reference one shape.
export const ModelJudgeConsent = z.object({
  acknowledgedAt: z.iso.datetime(),
  payloadVersion: z.number().int().positive(),
});
export type ModelJudgeConsent = z.infer<typeof ModelJudgeConsent>;

// The single definition of "the user has consented to the CURRENT payload" —
// shared by the plugin's judge gate, the CLI and the dashboard so they cannot
// disagree about what counts as granted. Presence alone is not enough: a consent
// recorded against an older payload shape is stale, and stale reads as revoked
// (the user is asked again rather than silently held to a grant for a payload
// they never saw). Pure logic over the schema — no I/O — so every surface,
// including the bundler-agnostic dashboard views, can import it.
export function isModelJudgeConsentValid(consent: ModelJudgeConsent | undefined): boolean {
  return consent?.payloadVersion === MODEL_JUDGE_PAYLOAD_VERSION;
}

// A recorded consent to send, on the deferred path, the activity this machine
// still owes its deployment — the pre-attach backlog and, since payload v2, the
// captures no live forward delivered. Carries the payload shape it was given
// against and the deployment it was given for. The endpoint is part of the grant
// because consent to send to one deployment is never consent to send to another.
export const HistorySyncConsent = z.object({
  acknowledgedAt: z.iso.datetime(),
  payloadVersion: z.number().int().positive(),
  endpoint: z.string(),
});
export type HistorySyncConsent = z.infer<typeof HistorySyncConsent>;

// The single definition of "this machine may send what it owes to the deployment
// it is attached to now". Both halves must hold: a grant recorded against an
// older payload shape no longer covers what would be sent, and a grant given for
// a different deployment never travels. Either way stale reads as revoked, so
// the user is asked again rather than held to a grant they did not give. Pure
// logic over the schema — no I/O.
export function isHistorySyncConsentValid(
  consent: HistorySyncConsent | undefined,
  endpoint: string | undefined,
): boolean {
  if (consent === undefined || endpoint === undefined) return false;
  return consent.payloadVersion === HISTORY_SYNC_PAYLOAD_VERSION && consent.endpoint === endpoint;
}

/**
 * "This grant is for THIS deployment but was recorded against an older payload."
 *
 * Deliberately NOT the negation of isHistorySyncConsentValid, and the difference
 * is a safety property rather than a nicety. That predicate fails for two
 * unrelated reasons, and only one of them may be healed by re-saving:
 *
 *   old version, same endpoint  → stale. The user already chose to share with
 *                                 THIS deployment; what changed is what sharing
 *                                 means. Re-asking in place is honest.
 *   different endpoint          → NOT stale, whatever the version says. The
 *                                 grant names another deployment, and a surface
 *                                 that treated it as stale would offer to "re-
 *                                 consent" a machine into sending its activity
 *                                 somewhere the user never agreed to. It must
 *                                 read as no grant at all.
 *
 * So the endpoint clause is an equality here, not an omission: a caller asking
 * "should I offer a one-save re-consent?" must get `false` the moment the
 * deployment differs. Pure logic over the schema — no I/O.
 */
export function isHistorySyncConsentStale(
  consent: HistorySyncConsent | undefined,
  endpoint: string | undefined,
): boolean {
  if (consent === undefined || endpoint === undefined) return false;
  return consent.endpoint === endpoint && consent.payloadVersion !== HISTORY_SYNC_PAYLOAD_VERSION;
}

// Onboarding answers + global prefs, persisted to ~/.aka/settings/settings.json.
// Versioned and default-filled so future config steps are additive: a
// settings.json written by an older plugin still parses, with any missing key
// taking its default.
//
// Plugin-local only — deliberately NO `.meta({ id })`. An id registers the shape
// in Zod's global registry, and a consumer walking that registry publishes every
// entry it finds under that name. This is on-disk plugin configuration, not a
// shape anything refers to by name, so it stays unregistered.
export const WorkspaceSettings = z.object({
  specVersion: z.number().int().positive().default(WORKSPACE_SETTINGS_SPEC_VERSION),
  runMode: RunMode.default('standalone'),
  // Present only while attached; a detach clears it. Its presence is what makes
  // `runMode: 'attached'` mean anything — see isAttached.
  controlPlane: ControlPlaneConnection.optional(),
  policy: SimpleDetectionPolicy.default('redact'),
  // Consent for scanning pre-install surfaces; opt-in (see HistoricalAccess).
  historicalAccess: HistoricalAccess.default('session-only'),
  // In-place egress extraction on the scan paths; disable to stop all Data
  // Shares writes.
  dataSharesInPlace: z.boolean().default(true),
  // Consent to keep a RECOVERABLE encrypted copy of detected values in the local
  // vault, instead of destroying them. Absent by default: this is a custody
  // change from one-way redaction, so it is never an assumed grant on upgrade.
  // Revoking stops future vaulting; it does not erase what is already stored —
  // purging the vault is the eraser.
  vaultConsent: VaultConsent.optional(),
  // Where the vault master key lives.
  vaultKeyCustody: VaultKeyCustody.default('file'),
  // How a pointer renders in assistant prose on screen (see VaultInlineReveal).
  vaultInlineReveal: VaultInlineReveal.default('masked'),
  // Absent until /aka:setup completes; its presence is what "onboarded" means.
  onboardedAt: z.iso.datetime().optional(),
  // Records that the user consented to sending findings to the model API for
  // the /aka:setup judge, along with the payload-shape version they agreed to.
  // Absent until granted; a stale payloadVersion means the consent no longer
  // covers the current payload and must be re-granted.
  modelJudgeConsent: ModelJudgeConsent.optional(),
  // Records that the user consented to the DEFERRED send — the outbox — along
  // with the payload shape and the endpoint they agreed to. Since payload v2
  // that covers both the pre-attach backlog and undelivered captures (which
  // carry prompt/reply text in `content`); the key name predates the widening.
  // Absent until granted, and a grant for a different endpoint or an older
  // payload no longer counts.
  historySyncConsent: HistorySyncConsent.optional(),
});
export type WorkspaceSettings = z.infer<typeof WorkspaceSettings>;

// The default (unonboarded) settings the SDK falls back to when no file exists.
export function defaultWorkspaceSettings(): WorkspaceSettings {
  return WorkspaceSettings.parse({});
}

/**
 * Whether this machine is actually attached. The mode alone is not enough: a
 * settings file can carry `runMode: 'attached'` with no descriptor (an older
 * file, a hand edit, an interrupted attach), and treating that as attached
 * would show the user a connection that does not exist and offer them a detach
 * that clears nothing. Both halves, or standalone.
 */
export function isAttached(settings: WorkspaceSettings): boolean {
  return settings.runMode === 'attached' && settings.controlPlane !== undefined;
}

/**
 * How the attached deployment should be named on screen: the administrator's
 * label if one was supplied, else the raw endpoint. One function so every
 * surface names it the same way.
 */
export function controlPlaneName(connection: ControlPlaneConnection): string {
  return connection.label ?? connection.endpoint;
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
    findingKey: input.findingKey ?? null,
    firstDetectedAt: input.firstDetectedAt ? isoToEpochMillis(input.firstDetectedAt) : null,
  };
}

// --- capture-path (recordCapture) mappers -----------------------------------
// The live hook capture path writes IngestEvent + DetectedFinding[] straight
// into the generalized audit_events/inspection_definitions/inspection_findings
// trio (see LocalDatabase.recordCapture in @akasecurity/persistence). These two
// mappers are the legacy-shape -> generalized-shape reshapers for that path,
// mirroring toEventRow/toFindingRow's role for the retired events/findings pair.

// IngestEvent -> the audit_events row's `attributes` bag for a capture leaf
// (prompt/response/code_change/tool_use). Every legacy EventMetadata key maps
// onto its snake_case CaptureAttributes name, EXCEPT `sessionId` — that becomes
// the row's `root_session_id`/`parent_id` FK, never an attribute (the same
// reason ToolCallInput/LlmCallInput carry `sessionId` as a top-level field
// rather than in their bags). `source_tool` has no metadata source of its own:
// it comes from the event's own `sourceTool` column, mirrored onto the bag
// because a capture-typed audit row has no equivalent column of its own.
export function toCaptureAttributes(event: IngestEvent): CaptureAttributes {
  const metadata = event.metadata;
  return {
    source_tool: event.sourceTool,
    ...(metadata?.repo !== undefined ? { repo: metadata.repo } : {}),
    ...(metadata?.filePath !== undefined ? { file_path: metadata.filePath } : {}),
    ...(metadata?.toolName !== undefined ? { tool_name: metadata.toolName } : {}),
    ...(metadata?.gitignored !== undefined ? { gitignored: metadata.gitignored } : {}),
    ...(metadata?.wholeFile !== undefined ? { whole_file: metadata.wholeFile } : {}),
    ...(metadata?.correlationId !== undefined ? { correlation_id: metadata.correlationId } : {}),
    ...(metadata?.traceId !== undefined ? { trace_id: metadata.traceId } : {}),
    ...(metadata?.exceptionIds !== undefined ? { exception_ids: metadata.exceptionIds } : {}),
    ...(metadata?.inspectionMs !== undefined ? { inspection_ms: metadata.inspectionMs } : {}),
    // `model`/`turnIndex` have no dedicated CaptureAttributes field (no writer
    // has ever populated either), but every legacy metadata key still rides
    // the bag rather than being silently dropped — CaptureAttributes'
    // `.catchall(z.unknown())` carries the long tail.
    ...(metadata?.model !== undefined ? { model: metadata.model } : {}),
    ...(metadata?.turnIndex !== undefined ? { turn_index: metadata.turnIndex } : {}),
  };
}

// The placeholder rule-definition version every capture-path finding mints
// under. DetectedFindingWithKey (the legacy findings/capture shape) carries no
// rule name or version — those exist only on the transcript reconciler's
// ToolCallInspection (see mask.ts's ScanFinding) — so this fixed literal is the
// closest available stand-in for a rule format that has, itself, so far only
// ever shipped as `specVersion: 1` (see Rule in rule.ts). Every finding for the
// same rule collapses onto ONE definition row: inspectionDefinitions.upsert is
// an idempotent upsert keyed on (ruleId, version).
// The rule-definition version a capture-path finding mints under. The capture
// shape (DetectedFindingWithKey) carries no real rule name/version, so the
// version is synthesized from the classification the finding arrived with.
// Folding category+severity into the version — hence into the content-addressed
// definition id (sha256 of ruleId + version) — means a pack update that
// reclassifies a rule mints a NEW definition row instead of being swallowed by
// the first-write-wins INSERT OR IGNORE, while re-detecting the SAME
// classification stays idempotent (same version -> same id). Mirrors the
// migration backfill's `unmigrated/<category>/<severity>` keying, so the live
// path and the copied history agree on definition identity.
export function captureDefinitionVersion(finding: DetectedFindingWithKey): string {
  return `capture/${finding.category}/${finding.severity}`;
}

// DetectedFindingWithKey -> the InspectionDefinitionInput its finding resolves
// against, at the capture path's coarser (ruleId-only) granularity. No display
// name is available at this boundary either, so the rule id doubles as its own
// name and `definition` carries only the bare identity — the same
// identity-only fallback style as the transcript reconciler's writeToolCall
// (`definition: JSON.stringify({ ruleId })`).
export function toCaptureDefinitionInput(
  finding: DetectedFindingWithKey,
): InspectionDefinitionInput {
  return {
    ruleId: finding.ruleId,
    version: captureDefinitionVersion(finding),
    name: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
    definition: JSON.stringify({ ruleId: finding.ruleId }),
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
