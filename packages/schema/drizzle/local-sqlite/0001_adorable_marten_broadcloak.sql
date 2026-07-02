ALTER TABLE `audit_events` ADD `input_tokens` integer GENERATED ALWAYS AS (json_extract(attributes, '$.input_tokens')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `output_tokens` integer GENERATED ALWAYS AS (json_extract(attributes, '$.output_tokens')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `cache_creation_input_tokens` integer GENERATED ALWAYS AS (json_extract(attributes, '$.cache_creation_input_tokens')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `cache_read_input_tokens` integer GENERATED ALWAYS AS (json_extract(attributes, '$.cache_read_input_tokens')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `model` text GENERATED ALWAYS AS (json_extract(attributes, '$.model')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `provider` text GENERATED ALWAYS AS (json_extract(attributes, '$.provider')) VIRTUAL;--> statement-breakpoint
CREATE INDEX `idx_audit_session_type` ON `audit_events` (`root_session_id`,`started_at`) WHERE event_type = 'llm_call';