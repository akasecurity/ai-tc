import type { BlockedDetectionInput, ResolutionInput } from '@akasecurity/persistence';
import type {
  AuditEventInput,
  ConfigInventoryReport,
  ConfigScanRecord,
  DayActivity,
  DetectedFindingWithKey,
  FindingView,
  HealthSummary,
  IngestEvent,
  InventoryContext,
  InventoryFacets,
  LlmCallInput,
  PolicyBundle,
  ResolvedInventory,
  RuleProbeVerdict,
  SessionTokenReport,
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
  close(): Promise<void>;
}
