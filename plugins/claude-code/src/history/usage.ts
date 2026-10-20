// Token-usage reconciler. Reads a transcript's
// usage records and writes idempotent `llm_call` audit-event leaves under the
// session root, plus a 30-day backfill that sweeps the transcript window — the
// first real descendant writer for the meta model.
//
// This path does WHOLE-FILE reads only. The parser (`parseTranscriptUsage`) already
// collapses each `message.id` to its terminal (max-output) record, so within a
// single whole-file pass `llmCallId(message.id)` + `INSERT OR IGNORE` is correct
// and idempotent — re-running yields identical row counts. The incremental tail
// read + `UPSERT … DO UPDATE SET output_tokens = MAX(...)` that handles a streaming
// partial split across passes is handled by the tail path.
//
// FK-safety invariant: `audit_events.parent_id` / `root_session_id`
// are enforced FKs to the session root, and the root's host/harness/project FK into
// inventory (`PRAGMA foreign_keys = ON`). SessionStart is fail-open and may never
// have written the root. So for EVERY session, EVERY pass, the reconciler ensures
// inventory then the root (idempotent) BEFORE the leaves — it never trusts
// SessionStart. Provider is then read back off the ensured root,
// never from live env (which would mislabel backfilled history under today's env).
import { sessionAccountsDir } from '@akasecurity/persistence';
import { accountScopeOf, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import {
  createPolicyResolver,
  createVaultGlue,
  providerFromModelId,
  resolveInventoryContext,
  resolveRepoNwo,
  scanText,
  scopeKeyMemo,
  sessionRootScopeKey,
  toolCallScopeKey,
} from '@akasecurity/plugin-sdk';
import type { AttributionResult } from '@akasecurity/plugin-sdk/account';
import {
  attributeRecords,
  credentialOrgAt,
  holdDecision,
  NO_ATTRIBUTION_CARRY,
  readObservations,
} from '@akasecurity/plugin-sdk/account';
import type {
  AuditEventInput,
  InventoryContext,
  LlmCallAttributes,
  LlmCallInput,
  ResolvedInventory,
  ToolCallAttributes,
  ToolCallInput,
  ToolCallInspectionInput,
} from '@akasecurity/schema';
import {
  harnessFromTool,
  isAgentScopeKey,
  isVaultConsentValid,
  SOURCE_TOOL,
} from '@akasecurity/schema';

import { pluginBuild } from '../build-info.ts';
import { platformRedactionScope } from '../remediation/redact.ts';
import { planFollowUp, scheduleFollowUp } from './reconcile-trigger.ts';
import type { UsageOffset } from './tail.ts';
import { readOffset, readTail, writeOffset } from './tail.ts';
import { scrubTranscriptTail } from './tail-scrub.ts';
import {
  accountTrace,
  type AssistantUsageRecord,
  iterateUsageAndToolCalls,
  parseTranscriptToolCalls,
  parseTranscriptUsage,
  type ToolCallRecord,
  type UsageAccountTrace,
  type UsageRecord,
} from './transcripts.ts';

// An absolute path with no `.git` ancestor — used when a transcript record carries
// no cwd, so `resolveRepoIdentity` resolves no project (rather than a relative path
// climbing into the reconciler's own git root). The filesystem root has no `.git`,
// so the git-root walk from here terminates at `/` with no match.
const NO_PROJECT_CWD = '/nonexistent/aka-reconciler/no-project';

// The longest (masked) tool target we store — a Bash heredoc or an MCP payload can be
// huge, and the point is "which call", not the whole body. Applied AFTER masking (see
// `reconcileSessionToolCalls`) so a truncated redaction marker leaks nothing, whereas
// truncating the RAW target first could split a secret across the cap and leak its
// unmasked prefix.
const MAX_TARGET_LEN = 500;
const truncateTarget = (s: string): string =>
  s.length > MAX_TARGET_LEN ? `${s.slice(0, MAX_TARGET_LEN)}…` : s;

// The reconciler's `ensureInventory` can win the hourly posture throttle just
// as SessionStart's can, so its gateway resolution carries the same build
// identity — an attached posture report without it clears the control plane's
// plugin columns. A manifest miss passes through as an explicit undefined,
// which the meta shape tolerates.
function reconcileGateway(config: PluginConfig): DataGateway {
  return resolveDataGateway(config, { pluginBuild: pluginBuild() });
}

export interface ReconcileSummary {
  sessions: number; // distinct sessions reconciled this run
  llmCalls: number; // llm_call leaves written (or re-written idempotently)
  skipped: number; // assistant usage records dropped (e.g. mid-walk gateway error)
  toolCalls: number; // tool_call leaves written (or re-written idempotently)
}

// Per-session reconcile result. `lastPromptId` is the most recent `promptId` seen
// in this record window (in file order) — the live `Stop` path persists it beside
// the byte offset so the NEXT tail pass can attribute a `run_key` even when the
// turn's parent user record was already consumed in a prior pass. undefined when
// the window held no user record.
export interface SessionReconcileResult {
  llmCalls: number;
  skipped: number;
  lastPromptId: string | undefined;
}

export interface ReconcileSessionOptions {
  // Seed for the run_key carry-forward: the last `promptId` persisted by a prior
  // tail pass. An incremental tail can start mid-turn (its parent user record is
  // before the offset), so an assistant whose `parentUuid` isn't in THIS window
  // attributes to this seeded promptId rather than dropping run_key. Never
  // fabricated — only ever a real promptId carried forward.
  seedPromptId?: string | undefined;
  // The pass's scope-key memo (plugin-sdk's scopeKeyMemo). A caller that
  // reconciles several sessions in one pass hands every call the same one, so a
  // directory shared across sessions is walked once and keyed identically
  // everywhere. When omitted, the call builds its own.
  scopeKeyOf?: ((cwd: string | undefined) => string | undefined) | undefined;
  // The account key each assistant line ran under, by its uuid. Each row is
  // stamped for that account through the gateway's account scope, and the session
  // root is keyed from the first line that has one; without one (backfill, a
  // gateway with no account scope) every row keeps its repository key and the
  // root is keyed from the first line.
  accountOf?: ((uuid: string) => string | undefined) | undefined;
  // The account key the session is in once these lines are written. When no line
  // has an account of its own it keys the session root, which carries the first
  // line's directory; the rows of those lines keep their repository keys.
  closingAccount?: string | undefined;
}

// Reconcile ONE session's usage records into `llm_call` leaves. `records` are the
// parsed usage records for a single session in file order (the parser preserves
// order so the `run_key` carry-forward is correct). Ensures inventory + the session
// root first (FK-safety), reads the provider back off the root, then writes one
// `llm_call` per assistant usage record. Returns the per-session counts plus the
// last `promptId` seen (for the Stop-path carry-forward across tail boundaries).
//
// Exported so the live `Stop` path and tests can reconcile a single session
// without the directory walk.
export async function reconcileSession(
  gateway: DataGateway,
  sessionId: string,
  records: readonly UsageRecord[],
  opts: ReconcileSessionOptions = {},
): Promise<SessionReconcileResult> {
  // The last promptId in file order across the whole window — the carry-forward
  // value the next tail pass seeds with. Starts at the prior pass's seed so an
  // empty/assistant-only tail still propagates the last known turn.
  let lastPromptId = opts.seedPromptId;
  for (const r of records) if (r.kind === 'user') lastPromptId = r.promptId;

  const assistants = records.filter((r): r is AssistantUsageRecord => r.kind === 'assistant');
  // A session with no usage-bearing assistant record contributes no leaves and no
  // root — nothing to anchor, so skip it entirely (no empty root rows). Still return
  // the carried-forward lastPromptId so a user-only tail seeds the next pass.
  if (assistants.length === 0) return { llmCalls: 0, skipped: 0, lastPromptId };

  // run_key map: every `user` record (prompts AND tool results) carries the turn's
  // `promptId`. The assistant's `parentUuid` points at its parent user record, so
  // `parentUuid → promptId` is the run grouping key. NOT `parentUuid`
  // itself, which fragments a turn ~per tool call.
  const promptIdByUuid = new Map<string, string>();
  for (const r of records) {
    if (r.kind === 'user') promptIdByUuid.set(r.uuid, r.promptId);
  }

  // FK-safety: ensure inventory + the session root BEFORE any leaf.
  // Build the inventory context from the transcript's OWN fields (the anchor
  // record carries cwd/version/gitBranch/entrypoint) — never live env.
  const first = assistants[0];
  if (first === undefined) return { llmCalls: 0, skipped: 0, lastPromptId };
  // Every row's key is stamped for the account its line ran under (accountOf).
  const stamp = stamperFor(gateway, opts.accountOf);
  // The anchor is the first reply the pass attributes to an account, else the
  // first reply. A leaf forwards only when its root does, so a root keyed from a
  // reply no account claims would hold back every later reply the account does
  // own. The root's key is the anchor's directory, stamped for the anchor's
  // account, or with no reply attributed for the account the session is in. It
  // lands only on a root no one wrote yet; a root SessionStart wrote keeps its
  // own key.
  const { reply: anchor, accountKey: rootAccount } = rootAnchorOf(gateway, first, assistants, opts);
  const rootKey = accountStamperFor(gateway)(sessionRootScopeKey(anchor.cwd), rootAccount);
  // The transcript's OWN cwd resolves the session's repo — never the reconciler's
  // own cwd (a relative/empty path would resolve a git root from the reconciler's
  // process cwd and mis-attribute the session). When cwd is absent we skip project
  // resolution entirely; host + harness still anchor the root for FK-safety.
  const ctx = resolveInventoryContext({
    cwd: anchor.cwd ?? NO_PROJECT_CWD,
    tool: SOURCE_TOOL.ClaudeCode,
    harnessVersion: anchor.version,
    harnessInterface: anchor.entrypoint,
  });
  // A root keyed by a session's agent key sends its inventory under that key.
  const resolved = isAgentScopeKey(rootKey)
    ? await gateway.ensureInventory(ctx, { scopeKey: rootKey })
    : await gateway.ensureInventory(ctx);

  // Provider for a root the reconciler is creating: model-id heuristic, else
  // 'unknown' — never live env. If SessionStart already wrote the
  // root with the contemporaneous env-provider, that row wins (a session root
  // is written through upsertSessionRootStmt, which only ever fills an
  // attribute-less STUB — an already-populated root is left alone) and our
  // heuristic value is dropped. A stub planted by an earlier capture does NOT
  // win: the root written just above heals it.
  const heuristicProvider = providerFromModelId(anchor.model);
  await gateway.recordAuditEvent(
    buildSessionRoot(
      sessionId,
      ctx,
      resolved,
      anchor,
      heuristicProvider,
      rootKey,
      first.occurredAt,
    ),
  );

  // Read the EFFECTIVE provider back off the ensured root: env-provider
  // if SessionStart won, else our just-written heuristic. Denormalized onto each leaf.
  const provider = (await gateway.readSessionProvider(sessionId)) ?? heuristicProvider;

  // Build every leaf for this pass first, then write them in ONE transaction
  // one lock acquisition + WAL fsync, minimal contention. run_key
  // seeds from the carry-forward map (which may include a promptId seen in a prior
  // tail pass) and never fabricates — null if unknown.
  // Each leaf is keyed by its OWN record's cwd, never by the root's. A session
  // that starts in an enrolled checkout and wanders into a personal directory
  // keys every call by where that call ran.
  const scopeKeyOf = opts.scopeKeyOf ?? scopeKeyMemo();
  const inputs: LlmCallInput[] = assistants.map((rec) => {
    // Prefer the in-window parent → promptId mapping; fall back to the seeded
    // carry-forward (a prior tail pass's last promptId) when the parent user record
    // was consumed in an earlier pass; null if still unknown — never fabricated.
    const runKey =
      (rec.parentUuid !== undefined ? promptIdByUuid.get(rec.parentUuid) : undefined) ??
      opts.seedPromptId;
    return {
      sessionId,
      messageId: rec.messageId,
      parentId: sessionId,
      rootSessionId: sessionId,
      startedAt: rec.occurredAt,
      attributes: buildAttributes(rec, provider, runKey, stamp(scopeKeyOf(rec.cwd), rec.uuid)),
    };
  });

  try {
    await gateway.recordLlmCalls(inputs);
    return { llmCalls: inputs.length, skipped: 0, lastPromptId };
  } catch {
    // Fail-open: a contended pass (SQLITE_BUSY) rolls back whole and is recovered on
    // the next idempotent pass — never break the session.
    return { llmCalls: 0, skipped: inputs.length, lastPromptId };
  }
}

// Reconcile ONE session's transcript `tool_call` records into `tool_call` leaves.
// SEPARATE from the usage pass (which owns the session root + provider): it runs
// AFTER `reconcileSession` per session, so the root the leaves FK into is already
// ensured — a tool call never appears without a usage-bearing
// assistant turn in the same session. `usageRecords` supplies the `parentUuid →
// promptId` map so a tool call attributes the SAME `run_key` as its sibling
// `llm_call`. Fail-open: a contended (SQLITE_BUSY) or FK-violating batch is dropped
// whole and recovered idempotently on the next pass (deterministic id +
// INSERT OR IGNORE). Returns the count written for the run summary.
export async function reconcileSessionToolCalls(
  gateway: DataGateway,
  sessionId: string,
  toolCalls: readonly ToolCallRecord[],
  usageRecords: readonly UsageRecord[],
  opts: ReconcileSessionOptions = {},
): Promise<number> {
  if (toolCalls.length === 0) return 0;

  // Same run_key grouping as the llm_call pass: every `user` record (prompts AND
  // tool results) carries the turn's promptId; a tool call's assistant record points
  // at its parent user record via `parentUuid`.
  const promptIdByUuid = new Map<string, string>();
  for (const r of usageRecords) if (r.kind === 'user') promptIdByUuid.set(r.uuid, r.promptId);

  // Per-rule installed-pack versions, so a transcript finding cites the pack
  // version that actually fired instead of the rule file's format version.
  // Read once for the whole pass. Best-effort: an unreadable bundle leaves the
  // map undefined and scanText falls back to its previous behavior, which is a
  // less precise version string — never a missed detection.
  let ruleVersions: Record<string, string> | undefined;
  try {
    ruleVersions = (await gateway.getPolicyBundle()).ruleVersions;
  } catch {
    ruleVersions = undefined;
  }

  const scopeKeyOf = opts.scopeKeyOf ?? scopeKeyMemo();
  const stamp = stamperFor(gateway, opts.accountOf);
  const inputs: ToolCallInput[] = toolCalls.map((tc) => {
    const runKey =
      (tc.parentUuid !== undefined ? promptIdByUuid.get(tc.parentUuid) : undefined) ??
      opts.seedPromptId;
    const attributes: ToolCallAttributes = { tool_name: tc.toolName, tool_use_id: tc.toolUseId };
    // Scan the salient input ONCE → the masked target (Layer 2a, queryable "which
    // WebFetch / which Bash") plus the per-secret findings (Layer 2b). scanText is
    // fail-secure: a scan failure over-redacts and yields no findings, never leaks.
    // Mask the FULL raw target, THEN size-cap the masked value: masking first
    // guarantees any secret is redacted whole before truncation, so a secret can't
    // straddle the cap and leak an unmasked prefix.
    let inspections: ToolCallInspectionInput[] = [];
    if (tc.target !== undefined) {
      const { masked, findings } = scanText(tc.target, ruleVersions, {
        locate: true,
        features: {},
      });
      if (masked !== '') attributes.target = truncateTarget(masked);
      // actionTaken = 'log': these are observed post-hoc from the transcript, not
      // enforced at the time (the tool already ran) — an audit record, not a block.
      inspections = findings.map((f) => ({
        ruleId: f.ruleId,
        ruleName: f.ruleName,
        ruleVersion: f.ruleVersion,
        category: f.category,
        severity: f.severity,
        span: f.span,
        maskedMatch: f.maskedMatch,
        actionTaken: 'log',
        confidence: f.confidence,
        line: f.location.line,
        col: f.location.col,
        context: f.location.context,
        ...(f.variableName === undefined ? {} : { variableName: f.variableName }),
        ...(f.features === undefined ? {} : { features: f.features }),
      }));
    }
    if (tc.isError !== undefined) attributes.is_error = tc.isError;
    if (tc.inputSize !== undefined) attributes.input_size = tc.inputSize;
    if (tc.outputSize !== undefined) attributes.output_size = tc.outputSize;
    if (tc.uuid !== undefined) attributes.uuid = tc.uuid;
    if (tc.parentUuid !== undefined) attributes.parent_uuid = tc.parentUuid;
    if (runKey !== undefined) attributes.run_key = runKey;
    // See toolCallScopeKey: a call that names a file or a search root is keyed by
    // the repository of what it names, as the hooks key a captured file or Grep
    // (the hooks read a search root only for Grep; a Glob or LS leaf follows the
    // same rule); any other call is keyed by the cwd of the record that issued it.
    // That key is stamped for the account the issuing line ran under.
    const scopeKey = stamp(toolCallScopeKey(tc, scopeKeyOf), tc.uuid);
    if (scopeKey !== undefined) attributes.scope_key = scopeKey;
    return {
      sessionId,
      toolUseId: tc.toolUseId,
      parentId: sessionId,
      rootSessionId: sessionId,
      startedAt: tc.occurredAt,
      attributes,
      inspections,
    };
  });

  try {
    await gateway.recordToolCalls(inputs);
    return inputs.length;
  } catch {
    // Fail-open (see reconcileSession): drop the whole pass; recovered idempotently.
    return 0;
  }
}

// Group the flattened tool-call stream into per-session buckets (file order within
// each). Every `ToolCallRecord` carries its own `sessionId` (from the assistant
// record bearing the `tool_use`), so this is a plain partition — no user-record
// replication like `groupBySession` needs.
function groupToolCallsBySession(records: Iterable<ToolCallRecord>): Map<string, ToolCallRecord[]> {
  const bySession = new Map<string, ToolCallRecord[]>();
  for (const rec of records) {
    const bucket = bySession.get(rec.sessionId);
    if (bucket) bucket.push(rec);
    else bySession.set(rec.sessionId, [rec]);
  }
  return bySession;
}

// Backfill: sweep the transcript window and reconcile every session's usage into
// `llm_call` leaves. Mirrors `scanHistory` (./scan.ts): resolve ONE gateway, walk,
// reconcile per session, `finally close()`. Idempotent — deterministic ids +
// `INSERT OR IGNORE` make a re-run yield identical row counts.
export async function reconcileHistory(
  config: PluginConfig,
  opts: { dir?: string; windowDays?: number; now?: number } = {},
): Promise<ReconcileSummary> {
  const gateway = reconcileGateway(config);
  let sessions = 0;
  let llmCalls = 0;
  let skipped = 0;
  let toolCalls = 0;
  try {
    // ONE walk of the transcript window feeds both reconcilers: per file we parse the
    // usage records (→ llm_call) and the tool-call records (→ tool_call) together, so a
    // heavy history is read from disk once, not twice. Collect both, then group each by
    // session — the tool-I/O pass runs right after that session's usage pass (which
    // ensures the root the tool_call leaves FK into).
    const usageRecords: UsageRecord[] = [];
    const toolCallRecords: ToolCallRecord[] = [];
    for (const file of iterateUsageAndToolCalls(opts)) {
      usageRecords.push(...file.usage);
      toolCallRecords.push(...file.toolCalls);
    }
    const toolCallsBySession = groupToolCallsBySession(toolCallRecords);
    // One scope-key memo for the whole sweep: sessions that share a directory
    // share its one `.git` walk and its one key.
    const scopeKeyOf = scopeKeyMemo();
    // Group usage by `sessionId` so each session is reconciled as a unit (the root +
    // provider are per-session). uuids are globally unique, so the per-session
    // `parentUuid → promptId` map is correct regardless of cross-file interleave.
    // We iterate `groupBySession(usageRecords)` — i.e. ONLY sessions with ≥1 billable
    // assistant usage record — and drain each session's tool-call bucket inside it. This
    // couples tool-call writes to sessions that also have a billable turn: a session with
    // tool_calls but no billable llm_call (every assistant record <synthetic>/zero-usage)
    // is never visited and its tool calls are dropped. That is intentional and safe — the
    // session root is ensured only by the usage pass, so writing tool_calls for an
    // unvisited session would FK-fail anyway (and in practice a `tool_use` rides an
    // assistant record that carries real usage, so the case shouldn't arise).
    for (const [sessionId, records] of groupBySession(usageRecords)) {
      sessions++;
      const result = await reconcileSession(gateway, sessionId, records, { scopeKeyOf });
      llmCalls += result.llmCalls;
      skipped += result.skipped;
      toolCalls += await reconcileSessionToolCalls(
        gateway,
        sessionId,
        toolCallsBySession.get(sessionId) ?? [],
        records,
        { scopeKeyOf },
      );
    }
  } finally {
    await gateway.close();
  }
  return { sessions, llmCalls, skipped, toolCalls };
}

// The live per-turn capture path (primary trigger). Reconcile ONLY the
// new tail of one session's transcript — the bytes appended since the last pass —
// rather than the whole file. Invoked by the detached `reconcile.js` worker the Stop
// hook spawns (and the SessionStart catch-up), it is handed the session id + the
// transcript path directly (no path reconstruction).
//
// Flow per pass: read the persisted byte offset (+ run_key carry-forward seed) →
// read the new tail up to the last complete line → parse just that chunk → reconcile
// it as a single-session pass (ensures inventory+root, writes leaves in one txn) →
// persist the advanced offset + the last promptId. Idempotent and crash-safe: the
// offset only advances after a successful read, and a re-read is a no-op via the
// UPSERT-max / INSERT OR IGNORE writes — so a dropped pass is recovered next time.
//
// On a gateway with an account scope, each record is attributed to the account its
// reply ran under, from the session's observation log. A pass writes nothing, up to
// three passes and fifteen minutes, while a record's closing observation is not
// written yet, and while the session root is unwritten and the session is in a work
// account whose key is not in scope yet, with work subscriptions on: a check at the
// session's next prompt learns the key, and the root, first-write-wins, is then keyed
// for the account instead of the repository. A pass that holds spawns a follow-up
// pass (see planFollowUp), so the hold is spent and the tail written within that
// budget even when no hook of the session fires again. `followUpDue` names the
// follow-up this pass is, by the due time its checkpoint recorded; a follow-up
// whose hold was released or replaced meanwhile does nothing.
//
// Resolves its OWN gateway and always `close()`s it in a finally, so a
// single worker invocation is self-contained. Fully fail-open.
export async function reconcileSessionTail(
  config: PluginConfig,
  sessionId: string,
  transcriptPath: string,
  now: () => number = Date.now,
  followUpDue?: number,
): Promise<{ llmCalls: number; skipped: number; toolCalls: number }> {
  const checkpoint = readOffset(config.dataDir, sessionId);
  if (followUpDue !== undefined && checkpoint.pending?.followUpAt !== followUpDue) {
    return { llmCalls: 0, skipped: 0, toolCalls: 0 };
  }
  const { chunk, nextOffset, from } = readTail(transcriptPath, checkpoint.offset);
  // Nothing new (or only a half-written final line) → don't even open the store.
  // Still re-persist the offset in case a rotation reset it (nextOffset may differ).
  if (chunk === '') {
    if (nextOffset !== checkpoint.offset) {
      writeOffset(config.dataDir, sessionId, {
        offset: nextOffset,
        lastPromptId: checkpoint.lastPromptId,
      });
    }
    return { llmCalls: 0, skipped: 0, toolCalls: 0 };
  }

  // Parse ONLY the consumed chunk: the collapse-by-message.id runs within this tail,
  // and the cross-pass partial/final convergence is handled by UPSERT-max downstream.
  // The tool-call parse reads the same chunk (a third independent pass).
  //
  // A tool_call is an IMMUTABLE fact (INSERT OR IGNORE, no partial/final convergence),
  // so is_error/output_size — which come from the LATER `tool_result` user record — can
  // only be filled if the `tool_use` and its `tool_result` land in the SAME chunk. This
  // worker runs at turn/session boundaries (Stop + SessionStart catch-up), so by then the
  // turn is USUALLY fully written and both land together; a re-read then no-ops on the
  // deterministic id.
  //
  // ACCEPTED gap ("document + accept", not converged): this is NOT
  // guaranteed. Because of the flush race the final `tool_result` may still be unflushed
  // even at a Stop boundary; if the offset advances past a chunk holding the `tool_use`
  // but not yet its `tool_result`, this pass writes the row with is_error/output_size =
  // undefined and — because the row is immutable — NO later pass (nor a full backfill)
  // can attach them (the deterministic id no-ops). Only those two enrichment fields are
  // at risk; the row, tool name, masked target, and secret findings are always correct.
  // (`llm_call` avoids this with UPSERT-take-MAX; tool_call intentionally has no
  // equivalent — see `insertToolCall`.) A future mid-turn trigger would widen this gap,
  // so keep the reconciler on turn boundaries. Covered by the tail-path test below.
  //
  // The same parse records the account trace: the session's org lines and its
  // assistant lines, in file order.
  const trace = accountTrace(from, sessionId);
  const records = parseTranscriptUsage(chunk, 0, trace);
  const toolCallRecords = parseTranscriptToolCalls(chunk);

  const gateway = reconcileGateway(config);
  // One scope-key memo for this tail pass, shared by both leaf kinds.
  const scopeKeyOf = scopeKeyMemo();
  try {
    // The carried attribution state belongs to the offset it was written at, so a
    // tail that starts anywhere else is attributed afresh: a transcript shorter
    // than the stored offset is read from 0, and the scrub rewrite below stores
    // offset 0. A replaced transcript longer than the stored offset is not noticed.
    // A call already written can be read again in either case. In the local store
    // its llm_call row has its attributes bag and ended_at replaced, and every other
    // column keeps its first write, when its output count has grown (or, for a row
    // with a usage source and no output count, when its bag differs): the fresh scope
    // key arrives with the fresh run_key, uuid and parent_uuid of the re-read, not
    // alone. An equal count keeps the first-written bag, scope key included, even if
    // the fresh attribution differs. A tool_call row there keeps its first key. Row
    // counts do not change.
    const attribution = attributeTail(
      gateway,
      config.dataDir,
      sessionId,
      transcriptPath,
      trace,
      from === checkpoint.offset ? checkpoint : undefined,
    );
    const waiting = await waitingTimes(
      gateway,
      sessionId,
      attribution,
      trace,
      records,
      toolCallRecords,
    );
    const passAt = now();
    const hold =
      waiting.length === 0
        ? undefined
        : holdDecision({ pendingTimes: waiting, pending: checkpoint.pending, now: passAt });
    if (hold?.hold === true) {
      // A record waits for its closing observation, or the session's account key is
      // not in scope yet: no root and no row is written, the transcript offset stays
      // where it is, and the next pass reads this tail again. The scrub of the
      // transcript file below does not run either, so a held pass strikes nothing: a
      // raw secret in these lines stays until the pass that writes, and is struck
      // there only under vault consent. That wait is bounded: while no earlier
      // follow-up is outstanding, a held pass asks for one 30 s, 2 min or 6 min after
      // the first, second or third hold, and the pass that finds the budget spent
      // writes within about 8.5 minutes; a pass once every waiting record is fifteen
      // minutes old writes regardless (holdDecision). If a follow-up never runs (the
      // spawn fails, or the host goes down mid-hold) the lines wait for a later pass
      // of the session, which writes once the budget is spent or the records are
      // fifteen minutes old, so only a session that never runs a pass again leaves
      // its rows unwritten.
      const plan = planFollowUp({
        held: hold.pending,
        before: checkpoint.pending,
        ownDue: followUpDue,
        now: passAt,
      });
      writeOffset(config.dataDir, sessionId, {
        ...checkpoint,
        ...(attribution?.logReset === true
          ? { logOffset: 0, logStartedAt: undefined, carried: undefined }
          : {}),
        pending: plan.pending,
      });
      if (plan.dueAt !== undefined) scheduleFollowUp(sessionId, transcriptPath, plan.dueAt);
      return { llmCalls: 0, skipped: 0, toolCalls: 0 };
    }
    const accountOf =
      attribution === undefined
        ? undefined
        : (uuid: string): string | undefined => {
            const record = attribution.records.get(uuid);
            return record?.status === 'account' ? record.key : undefined;
          };
    const result = await reconcileSession(gateway, sessionId, records, {
      seedPromptId: checkpoint.lastPromptId,
      scopeKeyOf,
      accountOf,
      closingAccount: attribution?.closingAccount,
    });
    // Tool calls after the usage pass (which ensured the root); shares the same
    // run_key carry-forward seed, scope-key memo and attribution as the llm_call leaves.
    const toolCalls = await reconcileSessionToolCalls(
      gateway,
      sessionId,
      toolCallRecords,
      records,
      {
        seedPromptId: checkpoint.lastPromptId,
        scopeKeyOf,
        accountOf,
      },
    );
    // Persist the advanced offset + the run_key carry-forward for the next tail pass.
    // Done AFTER the write so a failed pass leaves the offset at its prior value and
    // the same tail is retried (idempotently) next time. The observation log's offset
    // and the carried attribution state advance with it.
    writeOffset(config.dataDir, sessionId, {
      offset: nextOffset,
      lastPromptId: result.lastPromptId,
      ...(attribution === undefined
        ? {}
        : {
            logOffset: attribution.logOffset,
            logStartedAt: attribution.logStartedAt,
            carried: attribution.carry,
          }),
    });
    // The store now reflects this tail; scrub the transcript FILE itself so a raw
    // secret in the new lines (Claude Code logs a prompt even when a hook blocked
    // it) does not stay at rest in plaintext. Two gates, and they answer
    // different questions.
    //
    // VAULT CONSENT decides whether a struck value may be KEPT recoverably, and
    // it is deliberately not historicalAccess, which governs reading pre-install
    // history: this tail is the live session's own data, and gating the scrub on
    // historical access would leave session-only users' residue permanently
    // unscrubbed. Without consent nothing here runs and no vault is constructed.
    //
    // The PACK POLICY decides what may be touched at all. Without it the glue
    // self-scans and rewrites every span the bundled rules match, so a detection
    // the user assigned Monitor has its value pulled out of their transcript and
    // vaulted on the strength of having matched — which is what the resolver
    // below exists to stop. A bundle we cannot read therefore scrubs NOTHING and
    // leaves the transcript byte-identical rather than falling back to scrubbing
    // everything: the next pass repeats a skipped scrub, where a rewrite against
    // a policy nobody authored is not undoable.
    //
    // Every failure is swallowed — the reconcile pass never fails because
    // scrubbing did — and an unreadable bundle is one of them.
    if (isVaultConsentValid(config.settings.vaultConsent)) {
      try {
        const resolver = createPolicyResolver(await gateway.getPolicyBundle());
        const glue = createVaultGlue();
        const scrubbed = await scrubTranscriptTail(transcriptPath, {
          tokenizeText: (text) =>
            glue.tokenizeText(text, {
              resolver,
              sighting: { location: transcriptPath, kind: 'transcript' },
            }),
          scope: platformRedactionScope(),
        });
        // A rewrite changes the file's byte layout, so the just-persisted offset
        // no longer marks a line boundary. Reset it: the next pass re-reads the
        // whole (now pointer-bearing) file and attributes it afresh.
        if (scrubbed !== null && scrubbed.rewritten > 0) {
          writeOffset(config.dataDir, sessionId, {
            offset: 0,
            lastPromptId: result.lastPromptId,
          });
        }
      } catch {
        // Best-effort at-rest scrub — never break the reconcile pass.
      }
    }
    return { llmCalls: result.llmCalls, skipped: result.skipped, toolCalls };
  } finally {
    await gateway.close();
  }
}

// Group the flattened usage stream into per-session buckets, preserving file order
// within each. An assistant record carries its `sessionId` directly; a `user` record
// does not (the parser surfaces only its `uuid` + `promptId`), so user records are
// replicated into every bucket. uuids are globally unique, so a user record only ever
// matches the one assistant whose `parentUuid` equals its `uuid` — replicating the
// (small) user set keeps the run_key lookup correct without a separate user→session
// attribution pass. The common case is one session per file, so this is negligible.
function groupBySession(records: Iterable<UsageRecord>): Map<string, UsageRecord[]> {
  const all = [...records];
  const sessionIds = new Set<string>();
  for (const rec of all) if (rec.kind === 'assistant') sessionIds.add(rec.sessionId);

  const bySession = new Map<string, UsageRecord[]>();
  for (const sessionId of sessionIds) {
    const bucket = all.filter((rec) => rec.kind === 'user' || rec.sessionId === sessionId);
    bySession.set(sessionId, bucket);
  }
  return bySession;
}

// The Session root audit event for a root the reconciler may be CREATING — keyed on
// the session id (so a SessionStart-written root is left alone: session roots go
// through the fill-the-stub UPSERT, which only ever populates an attribute-less
// STUB, and this row carries attributes), stamped with the resolved inventory FKs
// and the volatile attrs snapshotted from the transcript's own fields. Mirrors
// `handleSessionStart`'s `buildSessionRoot` but sources os_version/harness_version
// from the transcript record (not live os/env) and provider from the model-id
// heuristic.
//
// Also stamps the Activity-DISPLAY attributes (harness/cwd/version/host/project/
// repo/branches) — the same set SessionStart writes — sourced from the
// transcript's own fields (cwd/version/gitBranch on the anchor) + the resolved
// inventory `ctx`. This is what makes a session reconstructed purely from history
// (no SessionStart, e.g. a backfill) show a project/cwd/branch instead of blank.
//
// `scopeKey` is the root's key as reconcileSession stamped it.
function buildSessionRoot(
  sessionId: string,
  ctx: InventoryContext,
  resolved: ResolvedInventory,
  anchor: AssistantUsageRecord,
  provider: string,
  scopeKey: string | undefined,
  startedAt: string,
): AuditEventInput {
  const attributes: Record<string, unknown> = {};
  const osVersion = ctx.host?.attributes.os_version;
  if (typeof osVersion === 'string') attributes.os_version = osVersion;
  if (anchor.version !== undefined) attributes.harness_version = anchor.version;
  attributes.provider = provider;

  // Activity-display attributes (read verbatim by the Activity page).
  attributes.harness = harnessFromTool(SOURCE_TOOL.ClaudeCode);
  if (anchor.cwd !== undefined) attributes.cwd = anchor.cwd;
  if (anchor.version !== undefined) attributes.version = anchor.version;
  const hostName = ctx.host?.attributes.host_name;
  if (typeof hostName === 'string') attributes.host = hostName;
  // `project` is the bare slug; `repo` the owner/repo NWO (remote only) — kept
  // distinct so the two display fields don't collapse to one value.
  if (ctx.project) attributes.project = ctx.project.name;
  const nwo = anchor.cwd !== undefined ? resolveRepoNwo(anchor.cwd) : undefined;
  if (nwo !== undefined) attributes.repo = nwo;
  if (anchor.gitBranch !== undefined) attributes.branches = [anchor.gitBranch];
  // The session's scope key: the repository key of the anchor's own cwd
  // (sessionRootScopeKey), stamped for the anchor's account, or for the session's
  // when no reply has one, which makes it the session's agent key for a recognised
  // work subscription whose repository is not enrolled. It lands only on a root no
  // one wrote yet: when SessionStart's root landed first it wins. Absent for a
  // relative or empty cwd, a remoteless repository and a record that names no cwd,
  // when no account applies.
  if (scopeKey !== undefined) attributes.scope_key = scopeKey;

  const event: AuditEventInput = {
    id: sessionId,
    eventType: 'session',
    // The earliest assistant record's timestamp is the best span start we have
    // without SessionStart; the root's started_at is best-effort first-seen anyway
    // (no authoritative span is stored on the structural parent).
    startedAt,
  };
  if (resolved.hostId) event.hostId = resolved.hostId;
  if (resolved.harnessId) event.harnessId = resolved.harnessId;
  if (resolved.sourceProjectId) event.sourceProjectId = resolved.sourceProjectId;
  if (Object.keys(attributes).length > 0) event.attributes = attributes;
  return event;
}

// Build the `LlmCallAttributes` bag for one assistant usage record.
// Only fields actually present are set — non-Anthropic gateways omit the
// cache/Tier-2 keys, which the all-`.optional()` schema tolerates. `model`/`provider`
// + the four headline token counts are the Tier-1 (generated-column) fields; the
// cache split, server-tool requests, service_tier and the correlation ids ride the bag.
function buildAttributes(
  rec: AssistantUsageRecord,
  provider: string,
  runKey: string | undefined,
  scopeKey: string | undefined,
): LlmCallAttributes {
  const usage = rec.usage;
  const attrs: LlmCallAttributes = {
    model: rec.model,
    provider,
    message_id: rec.messageId,
    uuid: rec.uuid,
  };
  if (rec.parentUuid !== undefined) attrs.parent_uuid = rec.parentUuid;
  if (runKey !== undefined) attrs.run_key = runKey;

  // Tier 1 — headline token counts (also promoted to generated columns).
  setNum(attrs, 'input_tokens', usage.input_tokens);
  setNum(attrs, 'output_tokens', usage.output_tokens);
  setNum(attrs, 'cache_creation_input_tokens', usage.cache_creation_input_tokens);
  setNum(attrs, 'cache_read_input_tokens', usage.cache_read_input_tokens);

  // Tier 2 — 1h vs 5m cache writes are priced differently (usage.cache_creation.*).
  const cacheCreation = usage.cache_creation;
  if (isRecord(cacheCreation)) {
    setNum(attrs, 'ephemeral_1h_input_tokens', cacheCreation.ephemeral_1h_input_tokens);
    setNum(attrs, 'ephemeral_5m_input_tokens', cacheCreation.ephemeral_5m_input_tokens);
  }
  // Server-tool requests are billed per request, separate from tokens.
  const serverToolUse = usage.server_tool_use;
  if (isRecord(serverToolUse)) {
    setNum(attrs, 'web_search_requests', serverToolUse.web_search_requests);
    setNum(attrs, 'web_fetch_requests', serverToolUse.web_fetch_requests);
  }
  // standard/batch/priority → price multiplier.
  if (typeof usage.service_tier === 'string') attrs.service_tier = usage.service_tier;
  // Local-only, and every forward strips it. See scopeKeyMemo (plugin-sdk) for
  // where it comes from.
  if (scopeKey !== undefined) attrs.scope_key = scopeKey;
  return attrs;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Set a numeric attribute only when the source is a finite number — keeps absent
// gateway fields out of the bag rather than coercing them to 0 (which would
// mis-report a non-Anthropic provider as having made cache writes it never did).
function setNum(attrs: LlmCallAttributes, key: string, value: unknown): void {
  if (typeof value === 'number' && Number.isFinite(value)) attrs[key] = value;
}

// The account each assistant line of the tail ran under, from the session's
// observation log, or undefined where this gateway stamps no account keys: every
// row then keeps its repository key. The log is read from its start, with no
// carried state, when it is absent, shorter than the stored offset, or its first
// line is not at the stored time: a log cleared and grown again is another log,
// whatever its size. A stored log offset with no stored time restarts the read
// too. The returned offsets and time are the ones to store.
function attributeTail(
  gateway: DataGateway,
  dataDir: string,
  sessionId: string,
  transcriptPath: string,
  trace: UsageAccountTrace,
  carry: Pick<UsageOffset, 'logOffset' | 'logStartedAt' | 'carried'> | undefined,
):
  (AttributionResult & { readonly logReset: boolean; readonly logStartedAt?: number }) | undefined {
  try {
    const scope = accountScopeOf(gateway);
    if (scope === undefined) return undefined;
    const stateDir = sessionAccountsDir(dataDir);
    const startedAt = logStartedAtOf(stateDir, sessionId);
    let carried = carry?.carried ?? NO_ATTRIBUTION_CARRY;
    let logOffset = carry?.logOffset ?? 0;
    let log = readObservations(stateDir, sessionId, logOffset);
    const sameLog = startedAt !== undefined && startedAt === carry?.logStartedAt;
    const logReset = logOffset > 0 && (log.size < logOffset || !sameLog);
    if (logReset) {
      carried = NO_ATTRIBUTION_CARRY;
      logOffset = 0;
      log = readObservations(stateDir, sessionId, 0);
    }
    const orgAt = (pos: number | undefined): string | undefined =>
      pos === undefined ? undefined : credentialOrgAt(transcriptPath, sessionId, pos);
    const attribution = attributeRecords({
      marks: trace.marks,
      observations: log.entries,
      logOffset,
      carry: carried,
      anchorOrg: orgAt(carried.anchorAt),
      lastOrg: orgAt(carried.lastOrgAt),
      bindingHash: scope.bindingHash,
      inScope: (accountKey) => scope.stamp(undefined, accountKey) !== undefined,
    });
    return {
      ...attribution,
      logReset,
      ...(attribution.logOffset > 0 && startedAt !== undefined ? { logStartedAt: startedAt } : {}),
    };
  } catch {
    return undefined;
  }
}

// A log line is a few hundred bytes at most, so the first one is inside this window.
const LOG_FIRST_LINE_WINDOW_BYTES = 4096;

// The time of the first line of a session's observation log, which names the log
// for as long as it lives: the log is append-only, and a log that is cleared and
// written again starts at a later time. Undefined when there is no log or no
// line of it is readable in the window.
function logStartedAtOf(stateDir: string, sessionId: string): number | undefined {
  return readObservations(stateDir, sessionId, 0, LOG_FIRST_LINE_WINDOW_BYTES).entries[0]
    ?.observation.t;
}

// The times of the tail's lines that will be written as rows and `keep` names: the
// lines that become llm_call rows and the lines that carry a tool call, whose
// tool_call rows are stamped for the account their own line ran under. A line that
// writes neither, such as a synthetic or zero-usage record with no tool call, is
// never one.
function writtenTimes(
  trace: UsageAccountTrace,
  records: readonly UsageRecord[],
  toolCalls: readonly ToolCallRecord[],
  keep: (id: string) => boolean = () => true,
): number[] {
  const written = new Set([
    ...records.flatMap((rec) => (rec.kind === 'assistant' ? [rec.uuid] : [])),
    ...toolCalls.flatMap((call) => (call.uuid === undefined ? [] : [call.uuid])),
  ]);
  return trace.marks.flatMap((mark) =>
    mark.kind === 'record' && written.has(mark.id) && keep(mark.id) ? [mark.t] : [],
  );
}

// The times of the lines the pass waits on: the lines still waiting for their closing
// observation or, with none, every line it would write while the session root is
// unwritten and the session is in an account whose key is not in scope yet, when a
// check can still learn it. A line that writes no row never holds the pass.
async function waitingTimes(
  gateway: DataGateway,
  sessionId: string,
  attribution: AttributionResult | undefined,
  trace: UsageAccountTrace,
  records: readonly UsageRecord[],
  toolCalls: readonly ToolCallRecord[],
): Promise<number[]> {
  if (attribution === undefined) return [];
  const pending = writtenTimes(
    trace,
    records,
    toolCalls,
    (id) => attribution.records.get(id)?.status === 'pending',
  );
  if (pending.length > 0 || attribution.unscopedAccount === undefined || !learnsKeys(gateway)) {
    return pending;
  }
  return (await rootIsWritten(gateway, sessionId)) ? [] : writtenTimes(trace, records, toolCalls);
}

// Whether a check can put a key in scope on this gateway: the identity record learns
// no key while work subscriptions are off.
function learnsKeys(gateway: DataGateway): boolean {
  try {
    return accountScopeOf(gateway)?.context.workSubscriptionsOn === true;
  } catch {
    return false;
  }
}

// Whether the session root is written: the stub a session start leaves for a deferred
// root carries no provider. A store that cannot be read counts as written, so the pass
// does not wait on it.
async function rootIsWritten(gateway: DataGateway, sessionId: string): Promise<boolean> {
  try {
    return (await gateway.readSessionProvider(sessionId)) !== undefined;
  } catch {
    return true;
  }
}

// The reply the session root is anchored on, and the account it is keyed for: the
// first reply `accountOf` names an account for, with that account; else the first
// reply, with the account the session is in. A gateway with no account scope, no
// `accountOf` and a fault name no account.
function rootAnchorOf(
  gateway: DataGateway,
  first: AssistantUsageRecord,
  assistants: readonly AssistantUsageRecord[],
  opts: ReconcileSessionOptions,
): { readonly reply: AssistantUsageRecord; readonly accountKey: string | undefined } {
  try {
    const { accountOf } = opts;
    if (accountOf === undefined || accountScopeOf(gateway) === undefined) {
      return { reply: first, accountKey: undefined };
    }
    for (const reply of assistants) {
      const accountKey = accountOf(reply.uuid);
      if (accountKey !== undefined) return { reply, accountKey };
    }
    return { reply: first, accountKey: opts.closingAccount };
  } catch {
    return { reply: first, accountKey: undefined };
  }
}

// `repoKey` stamped, through the gateway's account scope, for `accountKey`. A
// gateway with no account scope, no account and a fault keep the repository key.
function accountStamperFor(
  gateway: DataGateway,
): (repoKey: string | undefined, accountKey: string | undefined) => string | undefined {
  const scope = accountScopeOf(gateway);
  return (repoKey, accountKey) => {
    try {
      if (scope === undefined) return repoKey;
      return accountKey === undefined ? scope.stamp(repoKey) : scope.stamp(repoKey, accountKey);
    } catch {
      return repoKey;
    }
  };
}

// A row's key: `repoKey` stamped for the account the line `uuid` ran under.
function stamperFor(
  gateway: DataGateway,
  accountOf: ReconcileSessionOptions['accountOf'],
): (repoKey: string | undefined, uuid: string | undefined) => string | undefined {
  const stampAccount = accountStamperFor(gateway);
  return (repoKey, uuid) => {
    try {
      return stampAccount(repoKey, uuid === undefined ? undefined : accountOf?.(uuid));
    } catch {
      return repoKey;
    }
  };
}
