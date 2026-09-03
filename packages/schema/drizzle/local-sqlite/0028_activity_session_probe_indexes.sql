CREATE INDEX `idx_audit_session_prompt` ON `audit_events` (`root_session_id`) WHERE event_type = 'prompt';--> statement-breakpoint
CREATE INDEX `idx_audit_session_share` ON `audit_events` (`root_session_id`) WHERE event_type = 'share';--> statement-breakpoint
CREATE INDEX `idx_audit_ended_at` ON `audit_events` (`ended_at`,`root_session_id`) WHERE ended_at IS NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_audit_session_ended` ON `audit_events` (`root_session_id`,`ended_at`) WHERE ended_at IS NOT NULL;--> statement-breakpoint
-- Expression index for the activity list's turns rollup: a live-captured
-- session's turns are the DISTINCT `run_key` across its `llm_call` leaves, and
-- carrying the extracted key in the index answers that count from the index
-- alone instead of parsing every leaf's attribute bag. Written by hand, as
-- 0013's `idx_audit_code_change_path` was: drizzle-kit cannot emit an
-- expression containing a comma, so this index is not declared in sqlite.ts.
CREATE INDEX `idx_audit_session_run_key` ON `audit_events` (`root_session_id`, json_extract(`attributes`, '$.run_key')) WHERE `event_type` = 'llm_call';
