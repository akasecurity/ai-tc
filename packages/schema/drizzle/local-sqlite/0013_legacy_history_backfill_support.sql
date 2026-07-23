-- Legacy-to-generalized backfill support: the schema the resumable
-- events/findings -> audit_events/inspection_findings copy needs (the row
-- copy itself runs as a batched post-migration installer, not here — see
-- @akasecurity/persistence's migrations.ts), plus the audit_events read-path
-- indexes replacing the ones the legacy events table carried (0009/0010).

-- Tracks how far the batched, resumable copy has advanced through each legacy
-- table, by rowid, so a copy interrupted mid-run resumes instead of
-- restarting, and a completed copy is a cheap no-op on every later open.
CREATE TABLE `legacy_copy_watermark` (
	`source` text PRIMARY KEY NOT NULL,
	`last_rowid` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
-- Serves the time-range read family that scans a single event_type across a
-- start/end window (e.g. the Activity timeline) without a full-table scan.
CREATE INDEX `idx_audit_type_t` ON `audit_events` (`event_type`,`started_at`);
--> statement-breakpoint
-- Partial expression index mirroring `idx_events_code_change_path` (0009) for
-- the generalized audit_events/attributes pair: file-path reads filter
-- `event_type = 'code_change' AND json_extract(attributes, '$.file_path') = :path`.
CREATE INDEX `idx_audit_code_change_path` ON `audit_events` (json_extract(`attributes`, '$.file_path')) WHERE `event_type` = 'code_change';
--> statement-breakpoint
-- Synthesizes a stub session root (event_type = 'session', no attributes) for
-- every legacy `events.metadata.sessionId` that has no audit_events row yet.
-- audit_events.root_session_id is a self-FK, enforced with foreign-key
-- checking on, and INSERT OR IGNORE does not suppress a foreign-key violation
-- (only UNIQUE/PK/NOT NULL/CHECK) — so this must run before the events copy
-- resolves root_session_id, or every session-scoped row's insert fails.
-- started_at takes the earliest legacy occurred_at recorded under that
-- session, so the stub root's own timeline position is never later than
-- anything it will end up parenting.
INSERT INTO audit_events (id, event_type, root_session_id, started_at)
SELECT
	json_extract(metadata, '$.sessionId'),
	'session',
	NULL,
	min(occurred_at)
FROM events
WHERE json_extract(metadata, '$.sessionId') IS NOT NULL
	AND json_extract(metadata, '$.sessionId') NOT IN (SELECT id FROM audit_events)
GROUP BY json_extract(metadata, '$.sessionId');
