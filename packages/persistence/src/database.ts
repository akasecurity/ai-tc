import { randomUUID } from 'node:crypto';
import { existsSync, renameSync, rmSync } from 'node:fs';
import { join, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type {
  ConfigInventoryReport,
  ConfigScanRecord,
  DetectedFindingWithKey,
  IngestEvent,
  InventoryContext,
  InventoryFacets,
  InventoryInput,
  ProjectFilesScan,
  ResolvedInventory,
} from '@akasecurity/schema';
import {
  captureDefinitionVersion,
  isoToEpochMillis,
  toCaptureAttributes,
  toCaptureDefinitionInput,
} from '@akasecurity/schema';

import { captureId } from './ids.ts';
import { escapeLikePattern } from './internal/sql-text.ts';
import { failOpenTransaction, withTransaction } from './internal/transactions.ts';
import { akaWarn } from './internal/warn.ts';
import { applyMigrations, isForeignSqliteLineage } from './migrations.ts';
import { DB_FILENAME, ensureDataDirSync, tightenPerms, walSidecars } from './paths.ts';
import { SqliteActivityRepository } from './repositories/activity.ts';
import { SqliteAuditEventsRepository } from './repositories/audit-events.ts';
import { SqliteClassifiedDataRepository } from './repositories/classified-data.ts';
import { SqliteConfigInventoryRepository } from './repositories/config-inventory.ts';
import { SqliteDetectionsRepository } from './repositories/detections.ts';
import { SqliteEventsRepository } from './repositories/events.ts';
import { SqliteExceptionsRepository } from './repositories/exceptions.ts';
import { SqliteFindingsRepository } from './repositories/findings.ts';
import { SqliteInspectionDefinitionsRepository } from './repositories/inspection-definitions.ts';
import { SqliteInspectionFindingsRepository } from './repositories/inspection-findings.ts';
import { SqliteInstalledPacksRepository } from './repositories/installed-packs.ts';
import { SqliteInventoryRepository } from './repositories/inventory.ts';
import { SqliteInventoryAssetsRepository } from './repositories/inventory-assets.ts';
import { SqlitePoliciesRepository } from './repositories/policies.ts';
import { SqlitePolicyCatalogRepository } from './repositories/policy-catalog.ts';
import { SqliteProjectFilesRepository } from './repositories/project-files.ts';
import { SqliteResolutionsRepository } from './repositories/resolutions.ts';
import { SqliteRuleProbeCacheRepository } from './repositories/rule-probe-cache.ts';
import { SqliteScanLedgerRepository } from './repositories/scan-ledger.ts';
import { SqliteSecurityRepository } from './repositories/security.ts';
import { SqliteSharesRepository } from './repositories/shares.ts';
import { SqliteSourceProjectRepository } from './repositories/source-project.ts';
import { purgeSampleData } from './sample-purge.ts';

// InventoryContext / ResolvedInventory / InventoryFacets are the cross-mode
// shapes — they live in @akasecurity/schema (the contract spine) so the resolver
// (@akasecurity/plugin-sdk) and both DataGateways reference them without coupling to
// @akasecurity/persistence. Re-exported here for back-compat with existing imports.
export type { InventoryContext, InventoryFacets, ResolvedInventory } from '@akasecurity/schema';

/**
 * The local SQLite store under <dir>/aka.db — the writer of events/findings
 * for the plugin/CLI. Uses the Node 24+ builtin node:sqlite (no native dep,
 * tsup-bundleable), applies the canonical schema from @akasecurity/schema on
 * open, and seeds default per-category policies. The repositories are bound to
 * this open handle. Single-node: one machine, one owner, one store.
 *
 * `dir` is the resolved data directory (e.g. ~/.aka/data, computed by the SDK's
 * layout helpers) — persistence is layout-agnostic and only needs the path.
 */
export interface LocalDatabase {
  readonly events: SqliteEventsRepository;
  readonly findings: SqliteFindingsRepository;
  readonly policies: SqlitePoliciesRepository;
  readonly installedPacks: SqliteInstalledPacksRepository;
  // Worktree-scan skip ledger (path + mtime + hash per ruleset) — written by the
  // scanner so /aka:scan re-runs skip unchanged files, including clean ones.
  readonly scanLedger: SqliteScanLedgerRepository;
  // Detection-exception grants (canonical `exceptions` table: fingerprint-keyed,
  // consumed at enforcement time) + the short-lived blocked-detections ledger
  // the CLI approve flow reads.
  readonly exceptions: SqliteExceptionsRepository;
  // finding_resolution writer/reader (a user's disposition of a finding, keyed
  // by finding_key so it survives a later re-scan's fresh row id) — a
  // plugin-local table like scan_ledger, outside the canonical drizzle schema
  // helpers. Read/written by the scanner's resolution diff + the CLI/web-ui
  // resolution surfaces.
  readonly resolutions: SqliteResolutionsRepository;
  // Runtime ReDoS timing cache — see SqliteRuleProbeCacheRepository. Read and
  // written by the plugin SDK's rule-registration filter, never by the
  // dashboard.
  readonly ruleProbeCache: SqliteRuleProbeCacheRepository;
  // Read-only Security dashboard aggregations (severity/enforcement/timeseries/
  // top-sources/scan-coverage) over events+findings. Read by the OSS web-ui + CLI.
  readonly security: SqliteSecurityRepository;
  // Policies page reads — the built-in policy catalog (monitor/warn/redact/block)
  // with live "used by N detections" counts over installed_packs. Read by the OSS
  // web-ui. Distinct from `policies` (the raw enforcement Policy[] bundle).
  readonly policyCatalog: SqlitePolicyCatalogRepository;
  // Detections page read views (list/detail/stats) over installed_packs (+ findings
  // for the 30-day count). Read by the OSS web-ui.
  readonly detections: SqliteDetectionsRepository;
  // Data Shares page read views (grouped register / needs-review / detail / stats)
  // over share_destination/endpoint/call_site + the egress decision override, plus
  // the egress-decision write. Read/written by the OSS web-ui.
  readonly shares: SqliteSharesRepository;
  // Inventory page read views (harnesses / assets / projects / stats / project tree
  // / asset+file detail) over the asset model (inventory_asset/harness_asset/
  // project_file + overrides), plus the file-access / MCP-trust writes. Read/written
  // by the OSS web-ui. Distinct from `inventory` (the low-level meta-dimension writer).
  readonly inventoryAssets: SqliteInventoryAssetsRepository;
  // Activity page read views (today stats / session list / session detail with an
  // embedded audit timeline) reconstructed from the audit_events store. Read by the
  // OSS web-ui.
  readonly activity: SqliteActivityRepository;
  // Meta data-model repositories — the generalized inventory/audit/inspection
  // tables recordCapture (below) and recordConfigScan write into.
  readonly inventory: SqliteInventoryRepository;
  readonly sourceProject: SqliteSourceProjectRepository;
  readonly auditEvents: SqliteAuditEventsRepository;
  readonly classifiedData: SqliteClassifiedDataRepository;
  readonly inspectionDefinitions: SqliteInspectionDefinitionsRepository;
  readonly inspectionFindings: SqliteInspectionFindingsRepository;
  // Atomic capture write: one audit_events row (event_type = the capture's
  // kind) plus one inspection_findings row per already-masked
  // DetectedFinding[] (the SDK masks before calling), resolving each finding's
  // inspection_definitions row from its ruleId. Fail-open: a locked/corrupt DB
  // or a bad row rolls back and is swallowed — dropping telemetry never breaks
  // a session.
  recordCapture(event: IngestEvent, findings: DetectedFindingWithKey[]): void;
  // Idempotent upsert of the session's host/harness/account/project dimensions
  // by content-addressed id, in one transaction. Returns the resolved ids to
  // stamp onto the Session audit row. Fail-open: returns {} if the DB is
  // unavailable — inventory resolution must never break a session.
  ensureInventory(ctx: InventoryContext): ResolvedInventory;
  // One config scan, atomically: skill/hook inventory upserts + the config_scan
  // audit event + (when present) the posture definitions and their findings —
  // one transaction, so a torn scan never persists. Finding rows are minted
  // here: random row id, audit_event_id = the scan event, and the
  // content-addressed inspection_definition_id resolved from the finding's
  // (ruleId, version) natural key against the record's definitions. Fail-open.
  recordConfigScan(record: ConfigScanRecord): void;
  // One project-file scan, atomically: upsert every walked file and prune rows
  // the scan did not re-see (skipped for a truncated scan — a partial walk must
  // never shrink the tree). Backs the Inventory page's real file tree. Fail-open:
  // an empty scan or a locked DB leaves the stored tree untouched.
  recordProjectFiles(projectId: string, scan: ProjectFilesScan): void;
  // Self-heal for the pre-worktree-fix resolver bug: fold source_project rows
  // minted for a linked-worktree CHECKOUT PATH (the session's own worktree root,
  // or anything under <headRoot>/.claude/worktrees/) into the repo's canonical
  // row — remapping their audit-event references (FK) before deleting. One
  // session with the fixed plugin permanently clears a store's ghost projects.
  // Fail-open.
  reconcileWorktreeProjects(canonicalId: string, headRoot: string, worktreeRoot: string): void;
  // The Skills & Hooks read surface: artifacts seen by the latest scan, with
  // statuses derived at read time from that scan's open posture findings.
  configInventoryReport(): ConfigInventoryReport;
  // Filter-facet values for the read surfaces, read from the small Inventory
  // dimension (with the generated-column indexes), never the audit fact.
  facets(): InventoryFacets;
  // One-shot cleanup of the RETIRED demo/sample dataset from stores created by
  // previously shipped builds — the product seeds no sample data anymore.
  // Deletes exactly the provenance='sample' / `sample:`-prefixed rows, leaving
  // real scanned/ingested rows. Idempotent + fail-open; invoked by the web-ui
  // bootstrap, not the plugin's hot path.
  purgeSampleData(): void;
  // Runs `fn` inside a single SQLite transaction on this handle: BEGIN, then
  // COMMIT on resolve or ROLLBACK on throw (the rejection propagates). Do not
  // call this from inside another transaction.
  transaction<T>(fn: () => Promise<T> | T): Promise<T>;
  close(): void;
}

// Attach the resolved host id to a harness/account descriptor — the
// intra-inventory edge (a harness/user runs on a host).
function linkHost(input: InventoryInput, hostId: string | undefined): InventoryInput {
  return hostId ? { ...input, hostId } : input;
}

// Open the store with the shared PRAGMAs: WAL lets the plugin (events/findings)
// and an optional local reader share the file; busy_timeout absorbs brief
// contention; foreign keys enforce the event→finding reference.
function openWithPragmas(file: string): DatabaseSync {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 2000');
  db.exec('PRAGMA foreign_keys = ON');
  return db;
}

// Move an incompatible legacy store aside (recoverable) so a fresh one can be
// created. The handle was closed first, checkpointing the WAL into the main file,
// so the -wal/-shm sidecars are stale and removed — a fresh handle would otherwise
// pair the new db with the old WAL. Returns the backup path.
function backupLegacyStore(file: string): string {
  const backup = `${file}.legacy.${String(Date.now())}.bak`;
  renameSync(file, backup);
  for (const sidecar of walSidecars(file)) {
    if (existsSync(sidecar)) rmSync(sidecar);
  }
  return backup;
}

export function openLocalDatabase(dir: string): LocalDatabase {
  ensureDataDirSync(dir);
  const file = join(dir, DB_FILENAME);
  let db = openWithPragmas(file);

  // A legacy (tenant-bearing) aka.db can't be migrated forward onto the
  // tenant-free lineage — same user_version space, so the applier would skip it,
  // then every write would die on NOT NULL tenant_id and be swallowed fail-open
  // (silent persistence loss). Back the old file up (recoverable) and start fresh
  // so writes work; the reset is a one-time, loud-on-stderr event.
  if (isForeignSqliteLineage(db)) {
    db.close();
    const backup = backupLegacyStore(file);
    db = openWithPragmas(file);
    akaWarn(
      `Detected an older, incompatible (tenant-bearing) ${DB_FILENAME}; backed it up to ` +
        `${backup} and created a fresh store.`,
    );
  }

  applyMigrations(db, file);
  tightenPerms(file);

  const events = new SqliteEventsRepository(db);
  const findings = new SqliteFindingsRepository(db);
  const policies = new SqlitePoliciesRepository(db);
  const installedPacks = new SqliteInstalledPacksRepository(db);
  const scanLedger = new SqliteScanLedgerRepository(db);
  const exceptions = new SqliteExceptionsRepository(db);
  const resolutions = new SqliteResolutionsRepository(db);
  const ruleProbeCache = new SqliteRuleProbeCacheRepository(db);
  const security = new SqliteSecurityRepository(db);
  const detections = new SqliteDetectionsRepository(db);
  const shares = new SqliteSharesRepository(db);
  const policyCatalog = new SqlitePolicyCatalogRepository(installedPacks);
  const inventory = new SqliteInventoryRepository(db);
  const inventoryAssets = new SqliteInventoryAssetsRepository(db);
  const projectFiles = new SqliteProjectFilesRepository(db);
  const activity = new SqliteActivityRepository(db);
  const sourceProject = new SqliteSourceProjectRepository(db);
  const auditEvents = new SqliteAuditEventsRepository(db);
  const classifiedData = new SqliteClassifiedDataRepository(db);
  const inspectionDefinitions = new SqliteInspectionDefinitionsRepository(db);
  const inspectionFindings = new SqliteInspectionFindingsRepository(db);
  const configInventory = new SqliteConfigInventoryRepository(db);
  policies.seedDefaults();

  function recordCapture(event: IngestEvent, detected: DetectedFindingWithKey[]): void {
    // Fail-open: dropping telemetry is acceptable; breaking the host session
    // is not. A locked/corrupt DB or a bad row leaves the session untouched.
    failOpenTransaction(db, () => {
      const sessionId = event.metadata?.sessionId;

      // Plant the session's structural root before the capture's own row FKs
      // onto it (see auditEvents.ensureSessionRoot for why this ordering is
      // load-bearing — INSERT OR IGNORE does not suppress a foreign-key
      // violation, so without the root the whole capture would roll back).
      if (sessionId) {
        auditEvents.ensureSessionRoot(sessionId, event.occurredAt);
      }

      // The capture's own audit row. Content-addressed on (sessionId,
      // contentHash, filePath) — captureId — so re-ingesting identical content in
      // the same session never duplicates it, yet two DISTINCT files with
      // byte-identical content stay two rows (see captureId). All four capture
      // kinds (prompt/response/code_change/tool_use) map onto AuditEventType as
      // themselves — see the superset invariant documented there.
      const auditEventId = captureId(
        sessionId ?? null,
        event.contentHash,
        event.metadata?.filePath ?? null,
      );
      auditEvents.insertAuditEvent({
        id: auditEventId,
        eventType: event.kind,
        startedAt: event.occurredAt,
        parentId: sessionId,
        rootSessionId: sessionId,
        content: event.content,
        contentHash: event.contentHash,
        attributes: toCaptureAttributes(event),
      });

      // Definitions first, keyed by (ruleId, version) — mirrors
      // recordConfigScan's structure — so each finding resolves its
      // content-addressed definition id without minting one itself. The capture
      // path's version folds in category+severity (captureDefinitionVersion), so
      // the map collapses to one definition upsert per distinct
      // (ruleId, category, severity) — a pack update that reclassifies a rule
      // mints a new definition row rather than being frozen at first-write.
      const definitionIds = new Map<string, string>();
      for (const finding of detected) {
        // Scope dedup to the event's session so one sensitive value crossing
        // several surfaces in one action (prompt → tool call) is recorded
        // once — the legacy cross-surface guarantee, rejoined onto the
        // generalized tables (see SqliteInspectionFindingsRepository).
        if (
          sessionId &&
          inspectionFindings.isSessionDuplicate(finding.ruleId, finding.maskedMatch, sessionId)
        ) {
          continue;
        }
        // Guard against resubmitting the identical capture: the audit event
        // row itself is content-addressed and idempotent (INSERT OR IGNORE),
        // but an in-flight finding's own row id is a fresh random uuid per
        // call, so without this check a replayed capture would duplicate its
        // findings even though its parent event never duplicates.
        if (
          inspectionFindings.isEventDuplicate(
            auditEventId,
            finding.ruleId,
            finding.maskedMatch,
            finding.span.start,
            finding.span.end,
          )
        ) {
          continue;
        }
        const key = `${finding.ruleId}@${captureDefinitionVersion(finding)}`;
        let definitionId = definitionIds.get(key);
        if (!definitionId) {
          definitionId = inspectionDefinitions.upsert(toCaptureDefinitionInput(finding));
          definitionIds.set(key, definitionId);
        }
        inspectionFindings.insertFinding({
          id: finding.id,
          auditEventId,
          inspectionDefinitionId: definitionId,
          span: finding.span,
          maskedMatch: finding.maskedMatch,
          actionTaken: finding.actionTaken,
          confidence: finding.confidence,
          findingKey: finding.findingKey ?? undefined,
        });
      }
    });
  }

  function ensureInventory(ctx: InventoryContext): ResolvedInventory {
    const resolved: ResolvedInventory = {};
    const committed = failOpenTransaction(db, () => {
      const now = Date.now();
      // Host first: harness/account rows link to it via the intra-inventory edge.
      if (ctx.host) resolved.hostId = inventory.upsert(ctx.host, now);
      if (ctx.harness) {
        resolved.harnessId = inventory.upsert(linkHost(ctx.harness, resolved.hostId), now);
      }
      // The User/Account dimension. The local store has a single owner, so
      // the account is a fixed 'local' identity.
      resolved.accountId = inventory.upsert(
        linkHost(
          {
            objectType: 'user',
            identityKey: 'local',
            attributes: { source: 'local' },
          },
          resolved.hostId,
        ),
        now,
      );
      if (ctx.project) resolved.sourceProjectId = sourceProject.upsert(ctx.project, now);
    });
    // Fail-open: inventory resolution must never break a session.
    return committed ? resolved : {};
  }

  function recordConfigScan(record: ConfigScanRecord): void {
    // Fail-open: dropping a scan is acceptable; breaking the session is not.
    failOpenTransaction(db, () => {
      // The scan's own timestamp, not Date.now(): liveness on the read side is
      // `last_seen >= scan.started_at`, so stamping the upserts with exactly
      // the scan time makes "seen by this scan" true by construction — no
      // wall-clock skew between building the record and writing it.
      const now = isoToEpochMillis(record.scanEvent.startedAt);
      for (const item of record.items) inventory.upsert(item, now);
      auditEvents.insertAuditEvent(record.scanEvent);
      // Definitions first, keyed by (ruleId, version), so each finding can
      // resolve its content-addressed definition id without the caller ever
      // minting one (the natural-key boundary — see ConfigPostureFindingInput).
      const definitionIds = new Map<string, string>();
      for (const def of record.definitions ?? []) {
        definitionIds.set(`${def.ruleId}@${def.version}`, inspectionDefinitions.upsert(def));
      }
      for (const finding of record.findings ?? []) {
        const definitionId = definitionIds.get(`${finding.ruleId}@${finding.version}`);
        // A finding whose definition isn't in the record is a caller bug;
        // skipping it keeps the write untorn rather than failing the scan.
        if (!definitionId) continue;
        inspectionFindings.insertFinding({
          id: randomUUID(),
          auditEventId: record.scanEvent.id,
          inspectionDefinitionId: definitionId,
          span: finding.span,
          maskedMatch: finding.maskedMatch,
          actionTaken: finding.actionTaken,
          confidence: finding.confidence,
        });
      }
    });
  }

  function recordProjectFiles(projectId: string, scan: ProjectFilesScan): void {
    // An empty scan is a failed/irrelevant walk, never "the project has no
    // files" — writing it would prune the whole stored tree. Drop it.
    if (scan.files.length === 0) return;
    // Fail-open: dropping a scan is acceptable; breaking the session is not.
    failOpenTransaction(db, () => {
      projectFiles.replaceForProject(projectId, scan, Date.now());
    });
  }

  async function transaction<T>(fn: () => Promise<T> | T): Promise<T> {
    db.exec('BEGIN');
    try {
      const result = await fn();
      db.exec('COMMIT');
      return result;
    } catch (err) {
      // ROLLBACK discards any partial writes from this transaction. A
      // rollback failure here does not replace the original error.
      try {
        db.exec('ROLLBACK');
      } catch {
        // already rolled back / no open transaction
      }
      throw err;
    }
  }

  function reconcileWorktreeProjects(
    canonicalId: string,
    headRoot: string,
    worktreeRoot: string,
  ): void {
    try {
      // Rows the OLD resolver minted: url = a checkout path, never a remote.
      // Two shapes are recognizable without touching the filesystem — the
      // session's own worktree root, and Claude Code's worktree convention
      // under the head repo. A worktree placed elsewhere heals when a session
      // next runs inside it (the first predicate). That predicate only applies
      // when the session IS a linked worktree: in a plain clone the two roots
      // coincide, and a row keyed by that same path is the repo's LEGITIMATE
      // identity from before a remote was added — never a ghost to fold.
      // Both flavors of each path are matched: pre-fix ghosts minted on
      // Windows carry `\`-separated urls that the posix patterns miss.
      const headPosix = headRoot.split(sep).join('/');
      const worktreePosix = worktreeRoot.split(sep).join('/');
      const exactArm = worktreeRoot === headRoot ? '' : 'url IN (:worktreePosix, :worktreeWin) OR ';
      const stale = db
        .prepare(
          `SELECT id FROM source_project
           WHERE id <> :canonicalId
             AND (${exactArm}url LIKE :pattern ESCAPE '\\' OR url LIKE :patternWin ESCAPE '\\')`,
        )
        .all({
          canonicalId,
          ...(worktreeRoot === headRoot
            ? {}
            : { worktreePosix, worktreeWin: worktreePosix.split('/').join('\\') }),
          pattern: `${escapeLikePattern(headPosix)}/.claude/worktrees/%`,
          patternWin: `${escapeLikePattern(headPosix.split('/').join('\\'))}\\\\.claude\\\\worktrees\\\\%`,
        }) as { id: string }[];
      if (stale.length === 0) return;
      withTransaction(db, () => {
        for (const { id } of stale) {
          db.prepare(
            'UPDATE audit_events SET source_project_id = :canonicalId WHERE source_project_id = :id',
          ).run({ canonicalId, id });
          // User file-access overrides are security controls — MIGRATED, never
          // deleted. Paths are repo-relative in both rows, so they re-apply
          // cleanly on the canonical project; where the canonical row already
          // has an override for the same path, its own wins (OR IGNORE) and
          // the ghost's copy is dropped by the residual delete.
          db.prepare(
            'UPDATE OR IGNORE file_access_override SET project_id = :canonicalId WHERE project_id = :id',
          ).run({ canonicalId, id });
          db.prepare('DELETE FROM file_access_override WHERE project_id = :id').run({ id });
          db.prepare('DELETE FROM project_file WHERE project_id = :id').run({ id });
          db.prepare('DELETE FROM source_project WHERE id = :id').run({ id });
        }
      });
    } catch {
      // Fail-open: a locked store leaves the ghost rows for the next session.
    }
  }

  function facets(): InventoryFacets {
    return {
      hosts: inventory.distinctTitles('host'),
      harnesses: inventory.distinctTitles('harness'),
      osVersions: inventory.osVersions(),
      projects: sourceProject.distinctNames(),
    };
  }

  return {
    events,
    findings,
    policies,
    installedPacks,
    scanLedger,
    exceptions,
    resolutions,
    ruleProbeCache,
    security,
    detections,
    shares,
    policyCatalog,
    inventory,
    inventoryAssets,
    activity,
    sourceProject,
    auditEvents,
    classifiedData,
    inspectionDefinitions,
    inspectionFindings,
    recordCapture,
    ensureInventory,
    recordConfigScan,
    recordProjectFiles,
    reconcileWorktreeProjects,
    configInventoryReport: () => configInventory.report(),
    facets,
    purgeSampleData: () => {
      purgeSampleData(db);
    },
    transaction,
    close: () => {
      db.close();
    },
  };
}
