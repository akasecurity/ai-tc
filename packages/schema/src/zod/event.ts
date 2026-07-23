import { z } from 'zod';

// 'tool_use' is the enforcement record for a tool call whose arguments were
// scanned before it ran (a Bash command, a WebFetch url, an MCP payload) —
// text the tool acts on rather than durable content it authors, which stays
// 'code_change'. Distinct from audit_events' 'tool_call', the reconciler's
// post-hoc structural row: a tool_use event exists because the hook made a
// block/redact/warn decision, so the two never describe the same fact.
export const EventKind = z
  .enum(['prompt', 'response', 'code_change', 'tool_use'])
  .meta({ id: 'EventKind' });
export type EventKind = z.infer<typeof EventKind>;

// Ready-to-interpolate SQL value list of the capture event kinds, derived from
// EventKind so the predicate can never drift from the enum. Every read that
// joins inspection_findings to audit_events (which also holds structural rows)
// must constrain to these kinds; interpolate into `... event_type IN (${…})`.
// A code-defined constant, never user input — direct interpolation is injection-safe.
export const CAPTURE_EVENT_TYPES_SQL = EventKind.options.map((k) => `'${k}'`).join(',');

export const SourceTool = z
  .enum(['claude-code', 'claude-desktop', 'cursor', 'chatgpt', 'github-copilot', 'cli', 'unknown'])
  .meta({ id: 'SourceTool' });
export type SourceTool = z.infer<typeof SourceTool>;

export const EventMetadata = z
  .object({
    sessionId: z.string().optional(),
    repo: z.string().optional(),
    filePath: z.string().optional(),
    // The host tool whose input/output was scanned (e.g. 'Bash', 'WebFetch'),
    // set by the tool-scanning hooks. The tool NAME only — never the tool's
    // arguments or output, which can carry the very value a finding masked
    // (metadata is stored unredacted). Gives findings on non-file captures a
    // display location ("via Bash") when no filePath exists.
    toolName: z.string().optional(),
    // Set (true) by the worktree scanner when the file is excluded by the
    // repo's .gitignore. Gitignored files ARE still scanned — local scratch and
    // generated code can leak real secrets — but the provenance is recorded so
    // policy/dashboards can treat those findings as informational rather than
    // blocking. Omitted (not false) for tracked files and non-scan events.
    gitignored: z.boolean().optional(),
    // Set (true) ONLY when the event's `content` is the COMPLETE file at
    // capture time (a worktree scan reading from disk). Hook-captured edits
    // (e.g. an Edit tool's new_string) are partial fragments and MUST NOT set
    // this. The resolver-on-ingest keys its fixed-at-source dropout
    // diff on this marker: only a whole-file snapshot can prove a previously
    // open finding is gone; a fragment's absence proves nothing (the secret
    // may live outside the hunk). Omitted (not false) for fragments and
    // non-scan events, so pre-marker clients safely default to the
    // non-authoritative path.
    wholeFile: z.boolean().optional(),
    model: z.string().optional(),
    turnIndex: z.number().int().nonnegative().optional(),
    // Distributed-tracing correlation. `correlationId` ties a recorded event back
    // to the request that captured/ingested it (a UUID, generated independently of
    // the trace id); `traceId` is the W3C trace id (32 lowercase hex chars) of the
    // originating span when telemetry is enabled. Both optional + backward
    // compatible — populated by the plugin (see @akasecurity/plugin-sdk).
    correlationId: z.uuid().optional(),
    traceId: z
      .string()
      .regex(/^[0-9a-f]{32}$/)
      .optional(),
    // Ids of the detection exceptions that downgraded findings in this capture
    // to 'allow' — the enforcement audit trail's link back to the grant that
    // authorized the bypass. Absent on captures where no exception applied.
    exceptionIds: z.array(z.guid()).optional(),
  })
  .meta({ id: 'EventMetadata' });
export type EventMetadata = z.infer<typeof EventMetadata>;

// The canonical open-source event shape AND the public OpenAPI component 'Event'.
// Tenant-free — the public API contract carries no scoping columns. Consumed
// directly by @akasecurity/persistence and the web-ui.
export const Event = z
  .object({
    id: z.guid(),
    sourceTool: SourceTool,
    kind: EventKind,
    occurredAt: z.iso.datetime(),
    contentHash: z.string(),
    content: z.string(),
    metadata: EventMetadata.optional(),
  })
  .meta({ id: 'Event' });
export type Event = z.infer<typeof Event>;

// Ingest wire shape. In OSS, ingest === stored (both tenant-free), so it is just
// the base with its own OpenAPI id retained.
export const IngestEvent = Event.meta({ id: 'IngestEvent' });
export type IngestEvent = z.infer<typeof IngestEvent>;

export const IngestBatch = z
  .object({
    events: z.array(IngestEvent).min(1).max(100),
    // Dedup policy for this batch. Id-dedup ALWAYS applies. 'content-hash'
    // additionally rejects any event whose contentHash the store has already
    // recorded — for re-runnable bulk ingest (worktree scan, transcript
    // backfill), where a re-run mints fresh event ids for identical content and
    // would otherwise accumulate duplicates. Live hook traffic must NOT set it:
    // two genuinely separate prompts can be byte-identical and both belong on
    // the timeline.
    dedupe: z.literal('content-hash').optional(),
  })
  .meta({ id: 'IngestBatch' });
export type IngestBatch = z.infer<typeof IngestBatch>;
