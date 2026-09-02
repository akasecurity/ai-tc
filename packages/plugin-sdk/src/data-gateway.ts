import type { BlockedDetectionInput, ResolutionInput } from '@akasecurity/persistence';
import type {
  AuditEventInput,
  ConfigInventoryReport,
  ConfigScanRecord,
  DayActivity,
  DetectedFindingWithKey,
  EgressWriteSummary,
  FindingView,
  HealthSummary,
  IngestEvent,
  InventoryContext,
  InventoryFacets,
  LlmCallInput,
  PolicyBundle,
  ProjectFilesScan,
  RecordProjectEgressInput,
  ResolvedInventory,
  RuleProbeVerdict,
  SessionTokenReport,
  SimpleDetectionPolicy,
  ToolCallInput,
} from '@akasecurity/schema';

// One unit of the atomic capture write: the event plus its already-masked
// findings. Masking happens in the runtime before this reaches a gateway, so the
// data boundary speaks pure @akasecurity/schema (no @akasecurity/detections, no raw secret).
export interface CaptureRecord {
  event: IngestEvent;
  findings: DetectedFindingWithKey[];
  // Dedup policy hint: bulk re-runnable paths (worktree scan, backfill) set
  // 'content-hash' so a re-run doesn't accumulate duplicates. The SQLite
  // gateway ignores it — the local store dedups via knownContentHashes/scan
  // ledger before capture.
  dedupe?: 'content-hash' | undefined;
}

// One worktree-scan ledger record: a file the scanner has processed (clean or
// not) and the ruleset it was scanned under. Structurally identical to
// @akasecurity/persistence's ScanLedgerEntry — persistence cannot depend on the SDK, so
// the port shape lives here and structural typing joins them in plugin-runtime.
export interface ScanLedgerEntry {
  path: string; // absolute path
  mtime: string; // ISO timestamp at scan time
  contentHash: string;
  rulesetHash: string;
}

// The previous scan state the scanner skips against: same mtime → skip without
// reading; same content hash after an mtime-only bump → skip detection.
export interface ScanLedgerState {
  mtime: string;
  contentHash: string;
}

// One rule's cached ReDoS timing verdict. Structurally identical to
// @akasecurity/persistence's RuleProbeCacheEntry — persistence cannot depend
// on the SDK, so the port shape lives here and structural typing joins them
// in plugin-runtime.
export interface RuleProbeVerdictEntry {
  verdict: RuleProbeVerdict;
  worstProbeMs: number;
}

/**
 * The single data port the plugin runtime depends on.
 * `@akasecurity/plugin-runtime` resolves the concrete implementation from PluginConfig:
 * a SQLite-backed gateway (via @akasecurity/persistence). Every method is
 * async so the implementation can resolve synchronous node:sqlite calls
 * into promises.
 *
 * `getPolicyBundle` is the "pull the rules" surface: it returns the ruleset +
 * policies the runtime detects with, synthesized from the local policies
 * table. The dashboard reads power /findings, /health and /audit.
 *
 * `recordCapture` is deliberately ONE atomic operation (the event plus its
 * findings) rather than separate add-event / log-finding / add-audit calls:
 * the two rows must commit together (a single SQLite transaction), and there
 * is no separate audit record — the persisted findings ARE the audit trail.
 */
export interface DataGateway {
  recordCapture(record: CaptureRecord): Promise<void>;
  // Idempotent upsert of a session's resolved Inventory dimensions (host /
  // harness / project), returning the content-addressed ids to stamp onto a
  // Session audit row. The writer adds the local user account. Fail-open.
  ensureInventory(ctx: InventoryContext): Promise<ResolvedInventory>;
  // Append an audit-event fact (e.g. the Session root opened on SessionStart)
  // to the local store. Fail-open.
  recordAuditEvent(event: AuditEventInput): Promise<void>;
  // Append one transcript-derived `llm_call` leaf (token usage for one assistant
  // API response). Distinct from `recordAuditEvent` because the row id is minted
  // from the natural key (`sessionId` + `messageId`) inside the persistence layer
  // — the reconciler must not import `@akasecurity/persistence` to mint it. Idempotent
  // (deterministic id + `INSERT OR IGNORE`): re-reading the same transcript no-ops.
  // The caller must ensure the session root exists first (FK-safety).
  // Fail-open.
  recordLlmCall(input: LlmCallInput): Promise<void>;
  // Append a BATCH of `llm_call` leaves as ONE atomic reconcile pass: all
  // inserts run in a single SQLite transaction (one lock acquisition + WAL
  // fsync), and a contended SQLITE_BUSY rejects so the caller drops
  // the whole pass and recovers it idempotently next time. Same UPSERT-max
  // idempotency as `recordLlmCall`. The caller must ensure the session
  // root exists first (FK-safety).
  recordLlmCalls(inputs: readonly LlmCallInput[]): Promise<void>;
  // Append a BATCH of transcript-derived `tool_call` leaves as ONE atomic reconcile
  // pass (mirrors `recordLlmCalls`). The row id is minted from the natural key
  // (`sessionId` + `toolUseId`) inside persistence; a tool call is an immutable fact
  // so the write is a plain INSERT OR IGNORE (no MAX-merge), with the whole
  // batch in one SQLite transaction. The
  // caller must ensure the session root exists first (FK-safety) — the
  // usage pass, which runs first per session, is what ensures it. Fail-open.
  recordToolCalls(inputs: readonly ToolCallInput[]): Promise<void>;
  // Record one config-inventory scan ATOMICALLY: the skill/hook inventory
  // upserts, the `config_scan` audit event they're seen by, and any
  // posture definitions/findings referencing it. One method so a torn scan
  // (rows without their scan event) never persists — the whole record commits
  // in a single SQLite transaction. Fail-open.
  recordConfigScan(record: ConfigScanRecord): Promise<void>;
  // The Skills & Hooks read surface: live config inventory (seen by the latest
  // scan), with statuses DERIVED at read time from open posture findings —
  // never stored.
  configInventoryReport(): Promise<ConfigInventoryReport>;
  // Read the `provider` snapshotted onto a session root. The
  // reconciler ensures the root then reads provider back from it, rather than
  // re-resolving live env (which would mislabel backfilled history). Returns
  // undefined when the root/attribute is absent — the caller falls back to the
  // model-id heuristic.
  readSessionProvider(sessionId: string): Promise<string | undefined>;
  // Filter-facet values for the read surfaces, read from the small Inventory
  // dimension, never the audit fact.
  facets(): Promise<InventoryFacets>;
  getPolicyBundle(): Promise<PolicyBundle>;
  // Atomically claim one use of a detection-exception grant. True means the
  // grant applies to this capture. Unlike everything else on this port this is
  // fail-SECURE, not fail-open: false — or a throw, which callers must treat
  // identically — means the grant does NOT apply and the detection is enforced
  // as usual. A bypass is never granted on doubt. Implemented as a
  // conditional-UPDATE consume against the local store.
  consumeException(id: string): Promise<boolean>;
  // Best-effort bookkeeping for the CLI approve flow: record a just-enforced
  // detection (keyed fingerprint + masked preview, never the raw value) into
  // the short-lived blocked-detections ledger, so a grant can be created from
  // the stored fingerprint without the user retyping the value. Fail-open —
  // a failed write never affects the enforcement decision.
  recordBlockedDetection(entry: BlockedDetectionInput): Promise<void>;
  recentFindings(opts?: { limit?: number }): Promise<FindingView[]>;
  healthSummary(): Promise<HealthSummary>;
  activityByDay(days?: number): Promise<DayActivity[]>;
  // Per-session token rollups for the /aka:tokens read surface, derived at read
  // time from the `llm_call` leaves (counts + per-(provider, model) grouping) with
  // USD cost priced per leaf via the cost model — never stored.
  tokenReports(): Promise<SessionTokenReport[]>;
  // Content hashes of already-recorded events, so the historical backfill can
  // skip messages it has stored before — making a re-run idempotent.
  knownContentHashes(): Promise<Set<string>>;
  // Worktree-scan ledger, keyed by absolute path. Unlike knownContentHashes it
  // covers CLEAN files too (which are never recorded as events under
  // persist: 'with-findings'), so a scan re-run skips unchanged files without
  // re-reading them. Entries recorded under a different rulesetHash are omitted —
  // a new detection rule invalidates every skip.
  scanLedger(rulesetHash: string): Promise<Map<string, ScanLedgerState>>;
  recordScanned(entries: ScanLedgerEntry[]): Promise<void>;
  // The one-time ReDoS timing verdict for a regex rule (keyed by a content
  // hash of its pattern+flags), so a rule already measured safe — or
  // quarantined — is never re-measured on a later hook invocation. Only
  // pulled/custom-pack regex rules are ever looked up here; bundled rules are
  // gated by the CI adversarial battery instead and never reach this cache.
  getRuleProbeVerdict(ruleKey: string): Promise<RuleProbeVerdictEntry | undefined>;
  setRuleProbeVerdict(
    ruleKey: string,
    verdict: RuleProbeVerdict,
    worstProbeMs: number,
  ): Promise<void>;
  // The re-scan resolver's read side: at-rest finding_keys for `path` whose
  // LATEST disposition is not 'resolved' (SqliteResolutionsRepository.
  // openAtRestKeysForPath — latest-resolution-wins, not "any row exists"; see
  // that class's doc comment).
  openAtRestKeysForPath(path: string): Promise<string[]>;
  // The re-scan resolver's redetect side: the complement of
  // openAtRestKeysForPath — at-rest finding_keys for `path` whose LATEST
  // disposition IS 'resolved' (SqliteResolutionsRepository.
  // resolvedAtRestKeysForPath). The scanner intersects this with the keys it
  // just produced for `path` to find ones that need a superseding status:'open'
  // resolution (a redetected finding must not stay silently "caught" under a
  // stale resolved row).
  resolvedAtRestKeysForPath(path: string): Promise<string[]>;
  // The re-scan resolver's write side: record one disposition for a finding_key
  // (SqliteResolutionsRepository.insertResolution) — the
  // resolutions ledger is local, like the scan ledger it derives from.
  insertResolution(input: ResolutionInput): Promise<void>;
  // Record one project's statically-extracted egress (destinations, endpoints,
  // call sites) into the local store. Unlike most gateway writes this THROWS
  // on failure rather than swallowing it: the caller pairs a failed write with
  // skipping its scan-ledger commit, so the next scan retries the same files
  // instead of treating them as already processed.
  //
  // The summary comes back rather than being discarded because a write can
  // succeed while still declining some of its input: `droppedFiles` names the
  // files the per-write cap left unrecorded, and a ledger-keeping caller must
  // withhold exactly those ledger entries or it will never read them again.
  recordProjectEgress(input: RecordProjectEgressInput): Promise<EgressWriteSummary>;
  close(): Promise<void>;
}

/**
 * Maintenance a gateway can offer when it owns a local store of its own.
 *
 * Deliberately NOT part of `DataGateway`: these are retention passes and
 * read-model repairs, not data recording, and they only mean something to an
 * implementation with a store to maintain. A gateway that has none simply does
 * not provide them, and callers skip the work.
 *
 * Some members are synchronous — they complete inside a single store
 * transaction and have nothing to await.
 */
export interface LocalStoreMaintenance {
  /** Purge terminal exception rows past retention. Returns the row count. */
  sweepTerminalExceptions(retentionMs: number): Promise<number>;
  /** One-shot cap of block/redact enforcement rows to warn. */
  capWarnEraEnforcement(policyMode: SimpleDetectionPolicy): { capped: number };
  /** Commit one project-file scan into the local file tree. */
  recordProjectFiles(projectId: string, scan: ProjectFilesScan): Promise<void>;
  /** Fold checkout-path project rows into the repo's canonical row. */
  reconcileWorktreeProjects(
    canonicalId: string,
    headRoot: string,
    worktreeRoot: string,
  ): Promise<void>;
  /** The stale-session notice, or null when this session is current. */
  staleBinaryNotice(currentVersion: string): string | null;
  /**
   * Stamp a capture the live forward already delivered.
   *
   * On this interface rather than `DataGateway` because it is meaningless in
   * standalone: nothing forwards there, so nothing is ever delivered and
   * nothing stamps. It is the attached decorator that needs the local store to
   * hold delivery state, which is exactly what this surface is for.
   *
   * Takes the EVENT, not a row id. The id is derived from the event inside the
   * store, by the one function the write already uses, so a caller cannot
   * derive it differently and stamp a row that does not exist.
   */
  markCaptureDelivered(event: IngestEvent, atMs: number): void;
  /**
   * Record that a live forward did NOT deliver this capture, so the outbox owes
   * it. The attached gateway's counterpart to markCaptureDelivered; standalone
   * never calls it, which is what keeps a detached machine's captures out of the
   * drain by construction rather than by a date.
   */
  markCaptureOwed(event: IngestEvent): void;

  /**
   * Stamp structural events the live forward already delivered.
   *
   * The sibling of `markCaptureDelivered` for the lane the partition actually
   * counts. Without it a `session`/`llm_call`/`tool_call` row the live path
   * forwarded SUCCESSFULLY stays NULL — indistinguishable from one the batch
   * budget discarded — so `queued` reads as "recorded since attach" rather than
   * "owed", which is what `HistorySyncPartition`'s docblock says out loud.
   *
   * Takes the EVENTS, not row ids, for the same reason its sibling does: the
   * caller hands over the very objects it forwarded, so no second derivation of
   * an id exists to drift from the first. Unlike a capture the id needs no
   * derivation at all — `AuditEventInput.id` IS the local row's primary key and
   * the id the plane stores verbatim — but taking the event keeps the rule
   * uniform across both stamps rather than making this one the exception.
   *
   * Which types a read COUNTS is `STRUCTURAL_EVENT_TYPES`' decision, and
   * duplicating that list here is how the two drift — so this does not filter by
   * the counting list. It does refuse ONE thing, and that is a lane boundary
   * rather than a copy of a read's predicate: CAPTURE-GRAIN events are not
   * stampable here. `synced_at` is one column serving two disjoint drains that
   * both filter `synced_at IS NULL`, and `recordAuditEvent` accepts any
   * `AuditEventType` — so a capture routed through it would be stamped on a
   * forward that carried no `content`, and the capture drain would never offer
   * that row again. That is silent, permanent loss of the text, and it is why
   * `markCaptureDelivered` is a separate method. The implementation enforces it;
   * a caller does not have to know.
   */
  markAuditEventsDelivered(events: readonly AuditEventInput[], atMs: number): void;
}

// The member names, derived from the interface rather than restated: a
// `Record` keyed on `keyof LocalStoreMaintenance` fails to compile until a
// member added above is listed here too, so the two cannot drift.
const LOCAL_STORE_MAINTENANCE_MEMBERS: Record<keyof LocalStoreMaintenance, true> = {
  sweepTerminalExceptions: true,
  capWarnEraEnforcement: true,
  recordProjectFiles: true,
  reconcileWorktreeProjects: true,
  staleBinaryNotice: true,
  markCaptureDelivered: true,
  markCaptureOwed: true,
  markAuditEventsDelivered: true,
};

/**
 * Whether a gateway offers ONE named maintenance member.
 *
 * Structural rather than an `instanceof` check: any implementation supplying
 * the member qualifies, including a wrapper that forwards it to an inner
 * gateway.
 *
 * Per member rather than all-or-nothing, because the passes are
 * unrelated — a retention purge, a one-shot legacy cap, a file-tree commit, a
 * read-model repair, a version nudge — and an implementation that owns a store
 * has every reason to supply some and not others. Gating the group on the full
 * set means a gateway missing only the version nudge also stops purging
 * terminal exceptions past retention, which is one of the two tables with any
 * retention policy at all. Every pass is swallowed by design, so that loss is
 * printed nowhere. Callers gate each pass on its own member.
 */
export function offersMaintenance<K extends keyof LocalStoreMaintenance>(
  gateway: DataGateway,
  member: K,
): gateway is DataGateway & Pick<LocalStoreMaintenance, K> {
  return typeof (gateway as Partial<LocalStoreMaintenance>)[member] === 'function';
}

/**
 * Whether a gateway offers the WHOLE local-store maintenance capability.
 *
 * The all-or-nothing form, for a caller that needs every member — the shipped
 * standalone gateway is pinned against it. It is not what session-start
 * gates on; that gates each pass on its own member via `offersMaintenance`.
 */
export function hasLocalStoreMaintenance(
  gateway: DataGateway,
): gateway is DataGateway & LocalStoreMaintenance {
  return Object.keys(LOCAL_STORE_MAINTENANCE_MEMBERS).every((member) =>
    offersMaintenance(gateway, member as keyof LocalStoreMaintenance),
  );
}
