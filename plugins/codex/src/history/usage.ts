// Token-usage reconciler for Codex CLI. Reads a rollout file's usage records
// and writes idempotent `llm_call` audit-event leaves under the session root,
// plus a 30-day backfill that sweeps the transcript window. Structurally
// mirrors plugins/claude-code/src/history/usage.ts, but simpler: Codex stamps
// a `turn_id` directly on each event (see ./transcripts.ts), so there is no
// Claude-Code-style uuid→promptId join pass, and no per-message streaming
// collapse (one `token_count` event already IS one usage-bearing unit —
// see the module comment in ./transcripts.ts).
//
// This path does WHOLE-FILE reads only for the backfill sweep; the incremental
// tail read (`reconcileSessionTail`) handles the live per-turn path.
//
// FK-safety invariant: `audit_events.parent_id` / `root_session_id` are
// enforced FKs to the session root, and the root's host/harness/project FK
// into inventory (`PRAGMA foreign_keys = ON`). SessionStart is fail-open and
// may never have written the root. So for EVERY session, EVERY pass, the
// reconciler ensures inventory then the root (idempotent) BEFORE the leaves —
// it never trusts SessionStart. Provider is then read back off the ensured
// root, never from live env (which would mislabel backfilled history under
// today's env).
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import {
  codexProviderFromModelId,
  resolveInventoryContext,
  scanText,
} from '@akasecurity/plugin-sdk';
import type {
  AuditEventInput,
  InventoryContext,
  LlmCallAttributes,
  LlmCallInput,
  ResolvedInventory,
  ToolCallAttributes,
  ToolCallInput,
  ToolCallInspection,
} from '@akasecurity/schema';
import { harnessFromTool, SOURCE_TOOL } from '@akasecurity/schema';

import { readOffset, readTail, writeOffset } from './tail.ts';
import {
  iterateUsageAndToolCalls,
  parseTranscriptToolCalls,
  parseTranscriptUsage,
  type ToolCallRecord,
  type UsageRecord,
} from './transcripts.ts';

// An absolute path with no `.git` ancestor — used when a transcript record carries
// no cwd, so `resolveRepoIdentity` resolves no project. Mirrors the Claude Code
// reconciler's NO_PROJECT_CWD sentinel.
const NO_PROJECT_CWD = '/nonexistent/aka-reconciler/no-project';

// The longest (masked) tool target we store — see usage.ts (claude-code) for
// why this is applied AFTER masking.
const MAX_TARGET_LEN = 500;
const truncateTarget = (s: string): string =>
  s.length > MAX_TARGET_LEN ? `${s.slice(0, MAX_TARGET_LEN)}…` : s;

export interface ReconcileSummary {
  sessions: number;
  llmCalls: number;
  skipped: number;
  toolCalls: number;
}

export interface SessionReconcileResult {
  llmCalls: number;
  skipped: number;
  lastPromptId: string | undefined; // last runKey (turn_id) seen, carried to the next tail pass
}

export interface ReconcileSessionOptions {
  seedPromptId?: string | undefined;
}

// Reconcile ONE session's usage records into `llm_call` leaves. `records` are
// the parsed usage records for a single session in file order. Ensures
// inventory + the session root first (FK-safety), reads the provider back off
// the root, then writes one `llm_call` per usage record.
export async function reconcileSession(
  gateway: DataGateway,
  sessionId: string,
  records: readonly UsageRecord[],
  opts: ReconcileSessionOptions = {},
): Promise<SessionReconcileResult> {
  let lastPromptId = opts.seedPromptId;
  for (const r of records) if (r.runKey !== undefined) lastPromptId = r.runKey;

  if (records.length === 0) return { llmCalls: 0, skipped: 0, lastPromptId };

  // FK-safety: ensure inventory + the session root BEFORE any leaf. Build the
  // inventory context from the transcript's OWN fields — never live env.
  const anchor = records[0];
  if (anchor === undefined) return { llmCalls: 0, skipped: 0, lastPromptId };
  const ctx = resolveInventoryContext({
    cwd: anchor.cwd ?? NO_PROJECT_CWD,
    tool: SOURCE_TOOL.Codex,
    harnessVersion: anchor.version,
    // Descriptive only (never hashed, never forks the harness dimension) —
    // distinguishes e.g. 'codex_desktop' (Codex inside the ChatGPT desktop
    // app) from 'codex_cli_rs'/'codex-tui'/'codex_exec' (terminal entry
    // points). See transcripts.ts's UsageEventRecord.originator doc comment.
    harnessInterface: anchor.originator,
  });
  const resolved = await gateway.ensureInventory(ctx);

  const heuristicProvider =
    anchor.model !== undefined ? codexProviderFromModelId(anchor.model) : 'unknown';
  await gateway.recordAuditEvent(
    buildSessionRoot(sessionId, ctx, resolved, anchor, heuristicProvider),
  );

  const provider = (await gateway.readSessionProvider(sessionId)) ?? heuristicProvider;

  const inputs: LlmCallInput[] = records.map((rec) => ({
    sessionId,
    // No stable message id in Codex's usage event — key on the record's own
    // synthetic eventKey (see transcripts.ts), which is stable across re-reads
    // of the SAME file range and unique per event within a session.
    messageId: rec.eventKey,
    parentId: sessionId,
    rootSessionId: sessionId,
    startedAt: rec.occurredAt,
    // A record with no in-chunk turn_context (a tail chunk that starts
    // mid-turn) falls back to the seeded promptId carried by the offset
    // checkpoint, so its run_key attribution survives the chunk boundary.
    attributes: buildAttributes(
      rec.runKey === undefined && opts.seedPromptId !== undefined
        ? { ...rec, runKey: opts.seedPromptId }
        : rec,
      provider,
    ),
  }));

  try {
    await gateway.recordLlmCalls(inputs);
    return { llmCalls: inputs.length, skipped: 0, lastPromptId };
  } catch {
    return { llmCalls: 0, skipped: inputs.length, lastPromptId };
  }
}

// Reconcile ONE session's transcript tool-call records into `tool_call` leaves.
// Runs AFTER `reconcileSession` (which ensures the root). Fail-open: a
// contended (SQLITE_BUSY) or FK-violating batch is dropped whole and
// recovered idempotently on the next pass.
export async function reconcileSessionToolCalls(
  gateway: DataGateway,
  sessionId: string,
  toolCalls: readonly ToolCallRecord[],
  opts: { seedPromptId?: string | undefined } = {},
): Promise<number> {
  if (toolCalls.length === 0) return 0;

  const inputs: ToolCallInput[] = toolCalls.map((tc) => {
    const attributes: ToolCallAttributes = { tool_name: tc.toolName, tool_use_id: tc.toolUseId };
    let inspections: ToolCallInspection[] = [];
    if (tc.target !== undefined) {
      // Mask the FULL raw target, THEN size-cap the masked value — see the
      // Claude Code reconciler's identical comment for why order matters.
      const { masked, findings } = scanText(tc.target);
      if (masked !== '') attributes.target = truncateTarget(masked);
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
      }));
    }
    if (tc.isError !== undefined) attributes.is_error = tc.isError;
    if (tc.inputSize !== undefined) attributes.input_size = tc.inputSize;
    if (tc.outputSize !== undefined) attributes.output_size = tc.outputSize;
    // Same chunk-boundary seed fallback as reconcileSession's llm_call pass.
    const runKey = tc.runKey ?? opts.seedPromptId;
    if (runKey !== undefined) attributes.run_key = runKey;
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
    return 0;
  }
}

function groupToolCallsBySession(records: Iterable<ToolCallRecord>): Map<string, ToolCallRecord[]> {
  const bySession = new Map<string, ToolCallRecord[]>();
  for (const rec of records) {
    const bucket = bySession.get(rec.sessionId);
    if (bucket) bucket.push(rec);
    else bySession.set(rec.sessionId, [rec]);
  }
  return bySession;
}

function groupBySession(records: Iterable<UsageRecord>): Map<string, UsageRecord[]> {
  const bySession = new Map<string, UsageRecord[]>();
  for (const rec of records) {
    const bucket = bySession.get(rec.sessionId);
    if (bucket) bucket.push(rec);
    else bySession.set(rec.sessionId, [rec]);
  }
  return bySession;
}

// Backfill: sweep the transcript window and reconcile every session's usage
// into `llm_call` leaves. Idempotent — deterministic ids + `INSERT OR IGNORE`
// make a re-run yield identical row counts.
export async function reconcileHistory(
  config: PluginConfig,
  opts: { dir?: string; windowDays?: number; now?: number } = {},
): Promise<ReconcileSummary> {
  const gateway = resolveDataGateway(config);
  let sessions = 0;
  let llmCalls = 0;
  let skipped = 0;
  let toolCalls = 0;
  try {
    const usageRecords: UsageRecord[] = [];
    const toolCallRecords: ToolCallRecord[] = [];
    for (const file of iterateUsageAndToolCalls(opts)) {
      usageRecords.push(...file.usage);
      toolCallRecords.push(...file.toolCalls);
    }
    const toolCallsBySession = groupToolCallsBySession(toolCallRecords);
    for (const [sessionId, records] of groupBySession(usageRecords)) {
      sessions++;
      const result = await reconcileSession(gateway, sessionId, records);
      llmCalls += result.llmCalls;
      skipped += result.skipped;
      toolCalls += await reconcileSessionToolCalls(
        gateway,
        sessionId,
        toolCallsBySession.get(sessionId) ?? [],
      );
    }
  } finally {
    await gateway.close();
  }
  return { sessions, llmCalls, skipped, toolCalls };
}

// The live per-turn capture path (primary trigger). Reconcile ONLY the new
// tail of one session's transcript. Invoked by the detached `reconcile.js`
// worker the Stop hook spawns (and the SessionStart catch-up).
export async function reconcileSessionTail(
  config: PluginConfig,
  sessionId: string,
  transcriptPath: string,
): Promise<{ llmCalls: number; skipped: number; toolCalls: number }> {
  const checkpoint = readOffset(config.dataDir, sessionId);
  const { chunk, nextOffset } = readTail(transcriptPath, checkpoint.offset);
  if (chunk === '') {
    if (nextOffset !== checkpoint.offset) {
      writeOffset(config.dataDir, sessionId, {
        offset: nextOffset,
        lastPromptId: checkpoint.lastPromptId,
      });
    }
    return { llmCalls: 0, skipped: 0, toolCalls: 0 };
  }

  // Seed both parsers with the CALLER-supplied sessionId (straight from the
  // Stop hook payload): a tail chunk past the first pass never contains the
  // rollout file's one-time session_meta header, so without this seed every
  // usage/tool-call record here would be unattributable — see the parser
  // functions' own doc comments for the full explanation.
  const records = parseTranscriptUsage(chunk, 0, sessionId);
  const toolCallRecords = parseTranscriptToolCalls(chunk, 0, sessionId);

  const gateway = resolveDataGateway(config);
  try {
    const result = await reconcileSession(gateway, sessionId, records, {
      seedPromptId: checkpoint.lastPromptId,
    });
    const toolCalls = await reconcileSessionToolCalls(gateway, sessionId, toolCallRecords, {
      seedPromptId: checkpoint.lastPromptId,
    });
    // Advance the offset only when nothing was dropped: a contended
    // (SQLITE_BUSY) batch reports `skipped` (usage) or writes fewer tool
    // calls than parsed, and advancing past it would lose those records for
    // good — the writes are idempotent, so re-reading the same chunk on the
    // next pass simply absorbs the retry.
    const toolCallsDropped = toolCallRecords.length > 0 && toolCalls === 0;
    if (result.skipped === 0 && !toolCallsDropped) {
      writeOffset(config.dataDir, sessionId, {
        offset: nextOffset,
        lastPromptId: result.lastPromptId,
      });
    }
    return { llmCalls: result.llmCalls, skipped: result.skipped, toolCalls };
  } finally {
    await gateway.close();
  }
}

// The Session root audit event for a root the reconciler may be CREATING.
// Mirrors `buildSessionRoot` in plugins/claude-code/src/history/usage.ts, but
// sources cwd/version straight off the Codex usage record (no gitBranch/nwo —
// Codex's rollout format carries no per-event git branch field; `session_meta`
// DOES optionally carry `git.branch`, but that would need threading through
// transcripts.ts's usage parser — left for a follow-up rather than guessed at).
function buildSessionRoot(
  sessionId: string,
  ctx: InventoryContext,
  resolved: ResolvedInventory,
  anchor: UsageRecord,
  provider: string,
): AuditEventInput {
  const attributes: Record<string, unknown> = {};
  const osVersion = ctx.host?.attributes.os_version;
  if (typeof osVersion === 'string') attributes.os_version = osVersion;
  if (anchor.version !== undefined) attributes.harness_version = anchor.version;
  // Snapshotted directly from the transcript's own originator (not read back
  // off the shared harness inventory row — see the identical comment in
  // plugin-runtime's handle-session-start.ts for why that row can't hold a
  // durable per-session fact). Distinguishes a Codex session run inside the
  // ChatGPT desktop app ('codex_desktop') from a terminal one.
  if (anchor.originator !== undefined) attributes.harness_interface = anchor.originator;
  attributes.provider = provider;

  attributes.harness = harnessFromTool(SOURCE_TOOL.Codex);
  if (anchor.cwd !== undefined) attributes.cwd = anchor.cwd;
  if (anchor.version !== undefined) attributes.version = anchor.version;
  const hostName = ctx.host?.attributes.host_name;
  if (typeof hostName === 'string') attributes.host = hostName;
  if (ctx.project) attributes.project = ctx.project.name;

  const event: AuditEventInput = {
    id: sessionId,
    eventType: 'session',
    startedAt: anchor.occurredAt,
  };
  if (resolved.hostId) event.hostId = resolved.hostId;
  if (resolved.harnessId) event.harnessId = resolved.harnessId;
  if (resolved.sourceProjectId) event.sourceProjectId = resolved.sourceProjectId;
  if (Object.keys(attributes).length > 0) event.attributes = attributes;
  return event;
}

function buildAttributes(rec: UsageRecord, provider: string): LlmCallAttributes {
  const usage = rec.usage;
  const attrs: LlmCallAttributes = {
    model: rec.model ?? 'unknown',
    provider,
    message_id: rec.eventKey,
    uuid: rec.eventKey,
  };
  if (rec.runKey !== undefined) attrs.run_key = rec.runKey;
  setNum(attrs, 'input_tokens', usage.input_tokens);
  setNum(attrs, 'output_tokens', usage.output_tokens);
  setNum(attrs, 'cache_read_input_tokens', usage.cache_read_input_tokens);
  if (typeof usage.reasoning_output_tokens === 'number') {
    attrs.reasoning_output_tokens = usage.reasoning_output_tokens;
  }
  return attrs;
}

function setNum(attrs: LlmCallAttributes, key: string, value: unknown): void {
  if (typeof value === 'number' && Number.isFinite(value)) attrs[key] = value;
}
