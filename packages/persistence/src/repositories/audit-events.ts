import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { AuditEventInput, LlmCallInput, ToolCallInput } from '@akasecurity/schema';
import { isoToEpochMillis, toAuditEventRow } from '@akasecurity/schema';

import { llmCallId, toolCallId } from '../ids.ts';
import { parseJsonObject } from '../internal/json.ts';
import { allRows, bindParams, getRow } from '../internal/rows.ts';
import { withTransaction } from '../internal/transactions.ts';

/**
 * Audit event (timeline) fact writer, bound to one open DB + local identity. The
 * insert is a single narrow statement: inventory FKs + tree pointers
 * (`parent_id`, `root_session_id`) come pre-resolved on the input, so the hot
 * path never walks the tree or re-resolves a dimension. `synced_at` is unused
 * bookkeeping in the local store and always defaults NULL.
 */
export class SqliteAuditEventsRepository {
  private readonly insertStmt: StatementSync;
  private readonly upsertLlmCallStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // INSERT OR IGNORE: a re-opened Session root (same session id) is a no-op.
    // Descendant events carry random ids and so never conflict — facts are never
    // deduped, only the keyed root. Session ROOTS stay first-write-wins (structural
    // parents) — only `llm_call` leaves get the monotonic output_tokens merge below.
    this.insertStmt = db.prepare(
      `INSERT OR IGNORE INTO audit_events
         (id, parent_id, root_session_id, event_type,
          host_id, harness_id, source_project_id, started_at, ended_at,
          severity, priority, content, content_hash, attributes)
       VALUES
         (:id, :parentId, :rootSessionId, :eventType,
          :hostId, :harnessId, :sourceProjectId, :startedAt, :endedAt,
          :severity, :priority, :content, :contentHash, :attributes)`,
    );

    // UPSERT-take-MAX(output_tokens) for `llm_call` leaves. The
    // incremental Stop-hook tail can split a message's streaming PARTIAL
    // (small cumulative output) and its TERMINAL (full output) across two passes,
    // so a plain INSERT OR IGNORE would freeze the row at whichever arrived first
    // and under-count a lagging final. Within a `message.id` group input/cache are
    // constant and only output grows, so on conflict we replace the WHOLE attributes
    // bag (the generated token columns recompute from it) — but ONLY when the new
    // output is strictly greater. This converges a lagging final upward, is a no-op
    // on an equal re-read (idempotent), and is order-independent. Scoped to leaves:
    // it is a leaf-local merge of an intrinsic monotonic count, not derived state on
    // a parent. `ended_at` rides along since it tracks the same final.
    this.upsertLlmCallStmt = db.prepare(
      `INSERT INTO audit_events
         (id, parent_id, root_session_id, event_type,
          host_id, harness_id, source_project_id, started_at, ended_at,
          severity, priority, content, content_hash, attributes)
       VALUES
         (:id, :parentId, :rootSessionId, :eventType,
          :hostId, :harnessId, :sourceProjectId, :startedAt, :endedAt,
          :severity, :priority, :content, :contentHash, :attributes)
       ON CONFLICT(id) DO UPDATE SET
         attributes = excluded.attributes,
         ended_at   = excluded.ended_at
       WHERE COALESCE(json_extract(excluded.attributes, '$.output_tokens'), 0)
           > COALESCE(json_extract(audit_events.attributes, '$.output_tokens'), 0)`,
    );
  }

  // Run `fn` inside a single SQLite transaction (BEGIN…COMMIT). One reconcile pass
  // wraps ALL its `llm_call` inserts in one transaction: a single lock
  // acquisition + WAL fsync instead of N, minimal lock-hold. On any error (including
  // a contended SQLITE_BUSY) the transaction ROLLs back and the error propagates so
  // the caller fails open and drops the whole pass — recovered idempotently on the
  // next pass. Nesting-safe is NOT needed: the reconciler is the sole caller.
  runInTransaction(fn: () => void): void {
    withTransaction(this.db, fn);
  }

  insertAuditEvent(input: AuditEventInput): void {
    const row = toAuditEventRow(input);
    this.insertStmt.run(
      bindParams({
        id: row.id,
        parentId: row.parentId,
        rootSessionId: row.rootSessionId,
        eventType: row.eventType,
        hostId: row.hostId,
        harnessId: row.harnessId,
        sourceProjectId: row.sourceProjectId,
        startedAt: row.startedAt,
        endedAt: row.endedAt,
        severity: row.severity,
        priority: row.priority,
        content: row.content,
        contentHash: row.contentHash,
        attributes: row.attributes,
      }),
    );
  }

  // Idempotent stub of a session's structural root. Session-scoped leaves
  // (captures, llm_call, tool_call) FK parent_id/root_session_id onto this row;
  // INSERT OR IGNORE does NOT suppress a foreign-key violation (only
  // UNIQUE/PK/NOT NULL/CHECK), so a session-scoped insert with no root row
  // raises SQLITE_CONSTRAINT and rolls its whole transaction back — silently
  // dropping the write under failOpenTransaction. SessionStart's own root write
  // is itself fail-open and marks "attempted", not "succeeded", so a session
  // with no root row yet is a real, permanent condition, not a transient race.
  // The stub carries no dimensions/attributes; an authoritative root
  // (SessionStart / the reconciler's buildSessionRoot) wins by first-write-wins
  // on the id PK, so the stub never shadows real data. This is the single named
  // home for that FK invariant — call it before writing any session-scoped row.
  ensureSessionRoot(sessionId: string, startedAt: string): void {
    this.insertAuditEvent({ id: sessionId, eventType: 'session', startedAt });
  }

  // Insert one transcript-derived `llm_call` leaf. Unlike `insertAuditEvent`
  // (which takes a caller-supplied random id), the id here is MINTED internally
  // from the natural key — `llmCallId(sessionId, messageId)` — tenant-free like the
  // sibling local-store ids (the local store is single-tenant). The deterministic
  // id + the UPSERT-take-MAX(output_tokens) statement make every re-read idempotent
  // AND converge a streaming partial/final split across two incremental passes:
  // a whole-file re-read no-ops (equal output), a lagging final replaces a
  // partial (greater output), and a stale partial after the final no-ops (smaller).
  insertLlmCall(input: LlmCallInput): void {
    // An unparseable `startedAt` yields NaN, which node:sqlite binds as NULL —
    // violating started_at's NOT NULL and (inside the reconciler's
    // one-transaction pass) rolling back EVERY leaf in the batch, on every
    // future pass too, since the malformed record stays in the transcript.
    // Drop just this leaf instead; the rest of the pass commits.
    const startedAt = isoToEpochMillis(input.startedAt);
    if (!Number.isFinite(startedAt)) return;
    const id = llmCallId(input.sessionId, input.messageId);
    this.upsertLlmCallStmt.run(
      bindParams({
        id,
        parentId: input.parentId,
        rootSessionId: input.rootSessionId,
        eventType: 'llm_call',
        hostId: null,
        harnessId: null,
        sourceProjectId: null,
        startedAt,
        endedAt: null,
        severity: null,
        priority: null,
        content: null,
        contentHash: null,
        attributes: JSON.stringify(input.attributes),
      }),
    );
  }

  // Insert one transcript-derived `tool_call` leaf. Like `insertLlmCall` the id is
  // MINTED internally from the natural key — `toolCallId(sessionId, toolUseId)` —
  // so the plugin never imports `@akasecurity/persistence` to mint it. Unlike an
  // `llm_call` a tool call is an IMMUTABLE fact (no streaming partial/final split to
  // converge), so this is a plain first-write-wins INSERT OR IGNORE via the shared
  // `insertStmt`: a whole-file re-read no-ops on the deterministic id. `content` is
  // NULL in the metadata-only Layer-1 pass; the Layer-2 inspection pass fills the
  // masked content + writes the linked `inspection_findings` separately.
  //
  // ACCEPTED trade-off of the immutability: unlike `insertLlmCall`'s UPSERT-take-MAX,
  // there is NO cross-pass convergence here. `is_error`/`output_size` come from the
  // matching `tool_result` (a later transcript record); if the pass that first writes
  // this row doesn't also hold that record, those two enrichment fields stay `undefined`
  // permanently (the deterministic id no-ops every later pass). The whole-file backfill
  // has both records in one file, so it is unaffected; only the incremental tail can
  // strand them, and only those two fields — the row, tool name, masked target, and
  // secret findings are always correct. Deliberately not converged (see the
  // tail-path note in the reconciler).
  insertToolCall(input: ToolCallInput): void {
    // Same malformed-timestamp guard as insertLlmCall: drop the one bad leaf
    // rather than sinking the whole reconcile transaction on a NOT NULL bind.
    const startedAt = isoToEpochMillis(input.startedAt);
    if (!Number.isFinite(startedAt)) return;
    const id = toolCallId(input.sessionId, input.toolUseId);
    this.insertStmt.run(
      bindParams({
        id,
        parentId: input.parentId,
        rootSessionId: input.rootSessionId,
        eventType: 'tool_call',
        hostId: null,
        harnessId: null,
        sourceProjectId: null,
        startedAt,
        endedAt: null,
        severity: null,
        priority: null,
        content: null,
        contentHash: null,
        attributes: JSON.stringify(input.attributes),
      }),
    );
  }

  findById(id: string): AuditEventRow | undefined {
    return getRow<AuditEventRow>(this.db.prepare('SELECT * FROM audit_events WHERE id = :id'), {
      id,
    });
  }

  // Read the `provider` snapshotted onto a session root's attributes.
  // The reconciler ensures the root, then reads provider back from it — SessionStart's
  // contemporaneous env-provider wins by first-write; a reconciler-created root carries
  // the heuristic/'unknown' the reconciler stamped. Returns undefined when the root or
  // the attribute is absent, so the caller can fall back to the model-id heuristic.
  sessionProvider(sessionId: string): string | undefined {
    const row = this.findById(sessionId);
    if (!row?.attributes) return undefined;
    const provider = parseJsonObject(row.attributes)?.provider;
    if (typeof provider === 'string') return provider;
    return undefined;
  }

  // Every `llm_call` leaf's session id + raw attribute bag, for the read-time token
  // rollups. The caller parses each bag and prices it via the
  // cost model — we stay a thin reader here (no business logic, no cost). `root_session_id`
  // is the leaf's session (the reconciler sets parent_id = root_session_id = sessionId);
  // rows whose attributes blob is NULL are skipped (nothing to roll up).
  llmCallLeaves(): { sessionId: string; attributes: string }[] {
    return allRows<{ sessionId: string; attributes: string }>(
      this.db.prepare(
        `SELECT root_session_id AS sessionId, attributes
           FROM audit_events
          WHERE event_type = 'llm_call' AND attributes IS NOT NULL`,
      ),
    );
  }
}

interface AuditEventRow {
  id: string;
  parent_id: string | null;
  root_session_id: string | null;
  event_type: string;
  host_id: string | null;
  harness_id: string | null;
  source_project_id: string | null;
  started_at: number;
  ended_at: number | null;
  severity: string | null;
  priority: string | null;
  content: string | null;
  content_hash: string | null;
  attributes: string | null;
}
