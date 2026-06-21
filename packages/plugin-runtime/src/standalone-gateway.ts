import { randomUUID } from 'node:crypto';

import type {
  BlockedDetectionInput,
  LocalDatabase,
  ResolutionInput,
} from '@akasecurity/persistence';
import {
  compareBinaryVersions,
  inspectionFindingId,
  openLocalDatabase,
  toolCallId,
} from '@akasecurity/persistence';
import type {
  CaptureRecord,
  DataGateway,
  LlmCallLeaf,
  ScanLedgerEntry,
  ScanLedgerState,
} from '@akasecurity/plugin-sdk';
import { buildTokenReports, defaultCostModel, readFingerprintKey } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  AuditEventInput,
  ConfigInventoryReport,
  ConfigScanRecord,
  DayActivity,
  FindingView,
  HealthSummary,
  InstalledPackInput,
  InventoryContext,
  InventoryFacets,
  LlmCallAttributes,
  LlmCallInput,
  Policy,
  PolicyBundle,
  ProjectFilesScan,
  ResolvedInventory,
  Rule,
  SessionTokenReport,
  ToolCallInput,
} from '@akasecurity/schema';

import { PLUGIN_RECORDER_BINARY } from './recorder.ts';

/**
 * Standalone mode: the plugin on its own. All data lives in the shared SQLite
 * store under <dataDir>/aka.db (via @akasecurity/persistence). There is no network — the
 * policy bundle is synthesized from the local policies table, and the detection
 * ruleset is the user's INSTALLED snapshot (installed_packs, enabled packs
 * only), so pack updates and the enable/disable toggle genuinely gate what
 * runs. The SDK's compiled-in bundled packs are only the fail-open fallback
 * for an empty/unreadable store (see getPolicyBundle).
 *
 * On open it records the binary's detection inventory (available_packs mirror
 * + install-if-absent into installed_packs — never mutating an existing
 * installed row; updates are manual).
 */
export class StandaloneDataGateway implements DataGateway {
  private readonly db: LocalDatabase;
  // Kept for the fingerprint key lookup (exception.key lives beside the store).
  private readonly dataDir: string;

  constructor(
    dataDir: string,
    detections: InstalledPackInput[] = [],
    meta?: { recordedBy?: string },
  ) {
    this.db = openLocalDatabase(dataDir);
    this.dataDir = dataDir;
    this.db.installedPacks.recordInventory(detections, meta);
  }

  recordCapture(record: CaptureRecord): Promise<void> {
    this.db.recordCapture(record.event, record.findings);
    return Promise.resolve();
  }

  ensureInventory(ctx: InventoryContext): Promise<ResolvedInventory> {
    return Promise.resolve(this.db.ensureInventory(ctx));
  }

  recordAuditEvent(event: AuditEventInput): Promise<void> {
    this.db.auditEvents.insertAuditEvent(event);
    return Promise.resolve();
  }

  // The id is minted inside the repository from the natural key — the plugin can't
  // import @akasecurity/persistence to compute it, so the gateway is the boundary that
  // hands the natural key across. INSERT OR IGNORE → idempotent re-reads.
  recordLlmCall(input: LlmCallInput): Promise<void> {
    this.db.auditEvents.insertLlmCall(input);
    return Promise.resolve();
  }

  // One reconcile pass = one transaction. All leaves commit together
  // (single lock + WAL fsync); a contended SQLITE_BUSY rolls back and rejects so the
  // reconciler drops the whole pass and recovers it idempotently on the next read.
  recordLlmCalls(inputs: readonly LlmCallInput[]): Promise<void> {
    if (inputs.length === 0) return Promise.resolve();
    return new Promise((resolve, reject) => {
      try {
        this.db.auditEvents.runInTransaction(() => {
          for (const input of inputs) this.db.auditEvents.insertLlmCall(input);
        });
        resolve();
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  // One reconcile pass = one transaction (mirrors `recordLlmCalls`). Tool-call
  // leaves are immutable facts (plain INSERT OR IGNORE), so a re-read no-ops on the
  // deterministic id; a contended SQLITE_BUSY rolls back and rejects so the caller
  // drops the whole pass and recovers it idempotently next time.
  recordToolCalls(inputs: readonly ToolCallInput[]): Promise<void> {
    if (inputs.length === 0) return Promise.resolve();
    return new Promise((resolve, reject) => {
      try {
        this.db.auditEvents.runInTransaction(() => {
          for (const input of inputs) this.writeToolCall(input);
        });
        resolve();
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  // The tool_call leaf + its inspection findings, written together inside the
  // caller's transaction (Layer 2b). The audit-event id the findings FK into is the
  // SAME content-addressed `toolCallId` the leaf insert mints, so both re-read
  // idempotently. Definitions/classified-data are idempotent upserts; findings are
  // content-addressed INSERT OR IGNORE.
  private writeToolCall(input: ToolCallInput): void {
    this.db.auditEvents.insertToolCall(input);
    if (input.inspections.length === 0) return;
    const auditEventId = toolCallId(input.sessionId, input.toolUseId);
    for (const insp of input.inspections) {
      const definitionId = this.db.inspectionDefinitions.upsert({
        ruleId: insp.ruleId,
        version: insp.ruleVersion,
        name: insp.ruleName,
        category: insp.category,
        severity: insp.severity,
        // Store the rule identity as JSON, matching the other producer
        // (`detections/config-posture`, which stores `JSON.stringify({ … })`) — a
        // future reader that `JSON.parse`s this column won't choke on a bare id.
        // Transcript-derived findings carry only the identity, not a matcher/check.
        definition: JSON.stringify({ ruleId: insp.ruleId }),
      });
      const classifiedDataId = this.db.classifiedData.upsert({ class: insp.category });
      this.db.inspectionFindings.insertFinding({
        id: inspectionFindingId(auditEventId, definitionId, insp.span.start, insp.span.end),
        auditEventId,
        inspectionDefinitionId: definitionId,
        classifiedDataId,
        span: insp.span,
        maskedMatch: insp.maskedMatch,
        actionTaken: insp.actionTaken,
        confidence: insp.confidence,
      });
    }
  }

  // One SQLite transaction inside the LocalDatabase (fail-open there).
  recordConfigScan(record: ConfigScanRecord): Promise<void> {
    this.db.recordConfigScan(record);
    return Promise.resolve();
  }

  configInventoryReport(): Promise<ConfigInventoryReport> {
    return Promise.resolve(this.db.configInventoryReport());
  }

  readSessionProvider(sessionId: string): Promise<string | undefined> {
    return Promise.resolve(this.db.auditEvents.sessionProvider(sessionId));
  }

  facets(): Promise<InventoryFacets> {
    return Promise.resolve(this.db.facets());
  }

  // The scan ruleset from the user's installed snapshot, with a fail-open
  // ladder deciding whether it is authoritative. The invariant: a snapshot is
  // served as `complete` (replacing the compiled-in bundled packs) ONLY when it
  // is fully trustworthy — the ONE exception is a deliberately empty inventory
  // (the user disabled every pack), which is an authoritative "detect nothing".
  //   - store unreadable / no installed packs at all (fresh, seed-failed, or
  //     foreign store) → undefined → bundled fallback;
  //   - every pack disabled → complete empty set (respect the user's choice);
  //   - ANY invalid rule among enabled packs (all-invalid, partial corruption,
  //     or a single malformed entry) → undefined → bundled fallback. Serving a
  //     reduced "complete" set would silently drop exactly the corrupted rules
  //     with no fallback; the bundled packs are a superset, so falling back
  //     never loses coverage. Steady-state installed rules are all valid
  //     (generated + Zod-checked), so this only fires on a genuinely
  //     malformed/foreign store;
  //   - enabled packs that produce ZERO rules with no invalids (e.g. every
  //     enabled pack's rules_json is `[]`) → undefined → bundled fallback: an
  //     enabled pack contributing nothing is untrustworthy, not a real
  //     "detect nothing" (that is expressed by disabling packs, handled above);
  //   - otherwise → the enabled packs' validated rules, marked complete.
  private installedScanRules():
    | { rules: Rule[]; ruleActions: Map<string, ActionTaken>; complete: true }
    | undefined {
    try {
      const snapshot = this.db.installedPacks.installedRuleset();
      if (snapshot.installedPacks === 0) return undefined;
      if (snapshot.enabledPacks === 0) return { rules: [], ruleActions: new Map(), complete: true };
      if (snapshot.invalidRules > 0) return undefined;
      if (snapshot.rules.length === 0) return undefined;
      return { rules: snapshot.rules, ruleActions: snapshot.ruleActions, complete: true };
    } catch {
      return undefined;
    }
  }

  async getPolicyBundle(): Promise<PolicyBundle> {
    const policies = await this.db.policies.readPolicies();
    // Distinct custom keywords across the local policies, mirroring the wire
    // bundle's flat list.
    const customKeywords = [...new Set(policies.flatMap((p) => p.customKeywords ?? []))];
    // The user's installed snapshot is the effective ruleset (rulesComplete);
    // undefined falls back to the runtime's bundled packs (rules: [] without
    // the flag preserves the historical composition).
    const installed = this.installedScanRules();
    // Per-detection enforcement: each installed pack's assigned policy becomes
    // the action for every rule it contributes, emitted as ruleId-targeted
    // policies the runtime's resolveAction prefers over the seeded per-category
    // defaults. This is what makes a detection's Monitor/Warn/Redact/Block choice
    // in the dashboard actually gate enforcement (an unassigned pack ⇒ Monitor,
    // i.e. log-only). Only meaningful when the installed snapshot is
    // authoritative (rulesComplete) — the bundled-packs fallback keeps the
    // category defaults, since those bundled rule ids have no policy assignment.
    const rulePolicies: Policy[] = installed
      ? [...installed.ruleActions].map(([ruleId, action]) => ({
          id: randomUUID(),
          scope: 'global',
          target: { ruleId },
          action,
          enabled: true,
        }))
      : [];
    // Active exception grants under the CURRENT fingerprint key version —
    // grants written under a rotated-away key are excluded at read. Fail
    // secure: any error (key file, query) omits `exceptions` entirely, so
    // enforcement proceeds as if no grants existed.
    // Read-only key access: the gateway never mints exception.key — grants
    // cannot exist without a key (the ledger/CLI mint it at first use), so an
    // absent key simply means no grants to ship. Minting here would put a key
    // file on every install that pulls a bundle, exceptions user or not.
    let exceptions: PolicyBundle['exceptions'];
    try {
      const key = this.dataDir ? readFingerprintKey(this.dataDir) : null;
      exceptions = key ? await this.db.exceptions.activeBundleEntries(key.version) : undefined;
    } catch {
      exceptions = undefined;
    }
    return {
      version: 'local',
      policies: [...policies, ...rulePolicies],
      rules: installed ? installed.rules : [],
      ...(installed ? { rulesComplete: true } : {}),
      ...(exceptions !== undefined ? { exceptions } : {}),
      customKeywords,
      fetchedAt: new Date().toISOString(),
    };
  }

  // Fail-SECURE consume (see the DataGateway port comment): deliberately not
  // wrapped — a throw must reach the runtime, which treats it as "does not
  // apply". The conditional UPDATE in the repository is the atomic primitive.
  consumeException(id: string): Promise<boolean> {
    return this.db.exceptions.consume(id);
  }

  recordBlockedDetection(entry: BlockedDetectionInput): Promise<void> {
    return this.db.exceptions.recordBlocked(entry);
  }

  // Retention sweep over TERMINAL exception rows (revoked / expired / budget
  // exhausted) — standalone-only store maintenance, invoked from SessionStart,
  // not part of the DataGateway port. Active grants are never touched.
  sweepTerminalExceptions(retentionMs: number): Promise<number> {
    return this.db.exceptions.sweepTerminal(retentionMs);
  }

  // One project-file scan → the local project_file tree (one transaction inside
  // the LocalDatabase, fail-open there). Like the sweep above, this is
  // NOT part of the DataGateway port: the file tree is a local-store read model.
  recordProjectFiles(projectId: string, scan: ProjectFilesScan): Promise<void> {
    this.db.recordProjectFiles(projectId, scan);
    return Promise.resolve();
  }

  // Fold ghost source_project rows minted by the pre-worktree-fix resolver
  // (checkout-path identities) into the repo's canonical row. Standalone-only
  // store maintenance, invoked from SessionStart. Fail-open in the store.
  reconcileWorktreeProjects(
    canonicalId: string,
    headRoot: string,
    worktreeRoot: string,
  ): Promise<void> {
    this.db.reconcileWorktreeProjects(canonicalId, headRoot, worktreeRoot);
    return Promise.resolve();
  }

  /**
   * The stale-session notice (prevention P2): is a NEWER binary than this
   * session's plugin recorded on the available mirror? Old sessions keep
   * executing the plugin generation they started with (Claude Code caches
   * plugin versions), and the write gate makes their installed-pack writes
   * silent no-ops — this is the one-line nudge telling the user WHY, and that
   * a restart picks the newer plugin up. Standalone-only, invoked from
   * SessionStart, not part of the DataGateway port. Fail-open: any error →
   * null (no notice), and unparseable versions compare equal so garbage can
   * never fire it.
   */
  staleBinaryNotice(currentVersion: string): string | null {
    try {
      // newestRecordedBinary() maxes across ALL recorders (plugin + aka-cli), and
      // we compare that directly against THIS session's plugin version. Sound only
      // because the CLI and plugin ship on one shared version line (CLAUDE.md,
      // "normally move together"). If they ever diverge by design — the CLI at
      // 0.0.3 while the plugin line is still 0.0.2-alpha.N — this would fire a
      // spurious nudge (or mask a real one) and must filter by recorder first.
      const newest = this.db.installedPacks.newestRecordedBinary();
      if (newest === null) return null;
      if (compareBinaryVersions(newest.version, currentVersion) <= 0) return null;
      // The call-to-action depends on which binary is ahead. A newer *plugin*
      // generation is loaded by restarting the session. A newer *CLI*, though,
      // can't be cleared by a restart: the plugin on disk is still behind, and the
      // mirror's downgrade guard keeps recorded_by at the CLI stamp, so the notice
      // would just re-fire — the resolving action is bringing the plugin up to the
      // same version line. Exact-match the shared PLUGIN_RECORDER_BINARY (not a
      // `plugin`-prefix) so a future `plugin-*` recorder can't silently route into
      // the plugin branch.
      const remedy =
        newest.binary === PLUGIN_RECORDER_BINARY
          ? 'restart the session to pick up the newer plugin'
          : 'update the AKA plugin to match';
      return (
        `This session's AKA plugin (v${currentVersion}) is older than another binary ` +
        `on this machine (${newest.binary} v${newest.version}) — ${remedy}.`
      );
    } catch {
      return null;
    }
  }

  // The persistence read methods now return promises directly (the cross-mode
  // async ports), so the gateway forwards them instead of re-wrapping.
  recentFindings(opts?: { limit?: number }): Promise<FindingView[]> {
    return this.db.findings.recentFindings(opts);
  }

  healthSummary(): Promise<HealthSummary> {
    return this.db.findings.healthSummary();
  }

  activityByDay(days?: number): Promise<DayActivity[]> {
    return this.db.findings.activityByDay(days);
  }

  tokenReports(): Promise<SessionTokenReport[]> {
    const leaves: LlmCallLeaf[] = [];
    for (const row of this.db.auditEvents.llmCallLeaves()) {
      try {
        leaves.push({
          sessionId: row.sessionId,
          attributes: JSON.parse(row.attributes) as LlmCallAttributes,
        });
      } catch {
        // Corrupt attribute blob → skip this leaf (best-effort read).
      }
    }
    return Promise.resolve(buildTokenReports(leaves, defaultCostModel));
  }

  knownContentHashes(): Promise<Set<string>> {
    return this.db.events.contentHashes();
  }

  scanLedger(rulesetHash: string): Promise<Map<string, ScanLedgerState>> {
    return Promise.resolve(this.db.scanLedger.entriesForRuleset(rulesetHash));
  }

  recordScanned(entries: ScanLedgerEntry[]): Promise<void> {
    this.db.scanLedger.upsertEntries(entries);
    return Promise.resolve();
  }

  openAtRestKeysForPath(path: string): Promise<string[]> {
    return Promise.resolve(this.db.resolutions.openAtRestKeysForPath(path));
  }

  resolvedAtRestKeysForPath(path: string): Promise<string[]> {
    return Promise.resolve(this.db.resolutions.resolvedAtRestKeysForPath(path));
  }

  insertResolution(input: ResolutionInput): Promise<void> {
    this.db.resolutions.insertResolution(input);
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.db.close();
    return Promise.resolve();
  }
}
