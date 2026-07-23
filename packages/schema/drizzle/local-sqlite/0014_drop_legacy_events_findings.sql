-- Custom migration: drops the frozen legacy `events`/`findings` tables
-- (superseded by audit_events/inspection_definitions/inspection_findings) and
-- replaces them with read-only views of the same name.
--
-- persistence's migrations.ts applies this migration ONLY once the batched
-- history backfill (see runLegacyHistoryBackfill) has fully drained both
-- tables, and only after copying the live file aside — see
-- backupBeforeLegacyDrop in packages/persistence/src/migrations.ts. A store
-- still mid-copy keeps its real tables and this migration stays pending.
--
-- The views exist for skew: the `aka` CLI and the Claude Code plugin update
-- independently against one shared store, so an older, already-installed
-- binary can open a store a newer binary already dropped these tables on.
-- Every already-shipped repository constructor prepares its SQL eagerly at
-- open time, so a bare "table not found" would fail the WHOLE open, not just
-- a findings-specific read — these views keep `prepare()` succeeding so an
-- old binary's unrelated features keep working; its own reads stay truthful,
-- and its rare (already fail-open) writes fail at run time instead.
--
-- The 0009/0010 expression indexes existed only over the legacy `events`
-- table; DROP TABLE below would remove them implicitly, but they are
-- dropped explicitly first so the intent reads clearly. IF EXISTS so a store
-- that reached here with an index missing out of band (an adopted-tag store
-- whose physical index was never built) does not throw a deterministic "no
-- such index" out of the fail-open drop path.
DROP INDEX IF EXISTS `idx_events_code_change_path`;
--> statement-breakpoint
DROP INDEX IF EXISTS `idx_events_session_id`;
--> statement-breakpoint
-- `findings.event_id` references `events.id` — drop the child first.
DROP TABLE `findings`;
--> statement-breakpoint
DROP TABLE `events`;
--> statement-breakpoint
-- Legacy `events` shape, projected from audit_events: `kind`/`occurred_at`/
-- `source_tool` become real columns again (source_tool round-trips through
-- the attributes bag, the only place a capture-typed audit row keeps it);
-- `metadata` is reconstructed as the old camelCase JSON object from the new
-- snake_case attributes bag, with `root_session_id` folded back in as
-- `sessionId` (the one legacy metadata key that became a column, never an
-- attribute, on the new table). Constrained to the four capture kinds so
-- structural rows (session/run/tool_call/llm_call/source_lookup/config_scan)
-- never leak into a legacy reader's result set — the old `events` table
-- never held them either.
CREATE VIEW `events` AS
SELECT
  id,
  json_extract(attributes, '$.source_tool') AS source_tool,
  event_type AS kind,
  started_at AS occurred_at,
  content_hash,
  content,
  -- Plugin-local bookkeeping column that `ensureSyncedAtColumn` adds to the
  -- real `events` table at open time. A pre-cutover binary runs that probe on
  -- EVERY open; without this projection its `columnNames('events')` check
  -- misses `synced_at` and issues `ALTER TABLE events ADD COLUMN` against this
  -- view, which SQLite rejects ("Cannot add a column to a view") — a hard,
  -- non-fail-open crash of the whole open, the exact skew failure these views
  -- exist to prevent. Projecting it (always NULL; no reader consumes it)
  -- short-circuits that ALTER.
  NULL AS synced_at,
  json_object(
    'sessionId', root_session_id,
    'repo', json_extract(attributes, '$.repo'),
    'filePath', json_extract(attributes, '$.file_path'),
    'toolName', json_extract(attributes, '$.tool_name'),
    'gitignored', json_extract(attributes, '$.gitignored'),
    'wholeFile', json_extract(attributes, '$.whole_file'),
    'model', json_extract(attributes, '$.model'),
    'turnIndex', json_extract(attributes, '$.turn_index'),
    'correlationId', json_extract(attributes, '$.correlation_id'),
    'traceId', json_extract(attributes, '$.trace_id'),
    'exceptionIds', json_extract(attributes, '$.exception_ids')
  ) AS metadata
FROM audit_events
WHERE event_type IN ('prompt', 'response', 'code_change', 'tool_use');
--> statement-breakpoint
-- A plain single-row INSERT (the old writer's shape — no ON CONFLICT) is
-- accepted by prepare() against a view once an INSTEAD OF INSERT trigger
-- exists, so it fails at run time instead of at open — landing in the same
-- fail-open path the caller already wraps its write in.
CREATE TRIGGER `trg_events_ro`
INSTEAD OF INSERT ON `events`
BEGIN SELECT RAISE(ABORT, 'events is read-only; write to audit_events instead'); END;
--> statement-breakpoint
-- Legacy `findings` shape: rule_id/category/severity come from the joined
-- inspection_definitions row (the legacy table inlined them per-row; the
-- generalized schema normalizes them out into the shared definition). A view
-- has no rowid of its own, so the underlying table's rowid is re-exposed
-- explicitly under that name — a legacy reader ordering by `f.rowid` would
-- otherwise fail to resolve the column at all. Joined to audit_events for the
-- same four-capture-kind constraint as the events view above (a finding
-- attached to a tool_call/config_scan row never existed in the legacy table
-- either — see the persistence findings repository's identical predicate).
CREATE VIEW `findings` AS
SELECT
  f.id AS id,
  f.rowid AS rowid,
  f.audit_event_id AS event_id,
  d.rule_id AS rule_id,
  d.category AS category,
  d.severity AS severity,
  f.span_start AS span_start,
  f.span_end AS span_end,
  f.masked_match AS masked_match,
  f.action_taken AS action_taken,
  f.confidence AS confidence,
  f.finding_key AS finding_key,
  f.first_detected_at AS first_detected_at
FROM inspection_findings f
JOIN audit_events e ON e.id = f.audit_event_id
JOIN inspection_definitions d ON d.id = f.inspection_definition_id
WHERE e.event_type IN ('prompt', 'response', 'code_change', 'tool_use');
--> statement-breakpoint
-- Defense in depth only: SQLite refuses to plan ANY upsert against a view
-- ("cannot UPSERT a view") no matter what trigger exists, so this can never
-- rescue the real legacy writer, which always used
-- `ON CONFLICT (finding_key) DO UPDATE` — that statement still fails at
-- prepare() on an old binary, same as it would with no trigger at all. This
-- only covers a plain-INSERT shape, should one ever exist.
CREATE TRIGGER `trg_findings_ro`
INSTEAD OF INSERT ON `findings`
BEGIN SELECT RAISE(ABORT, 'findings is read-only; write to inspection_findings instead'); END;
