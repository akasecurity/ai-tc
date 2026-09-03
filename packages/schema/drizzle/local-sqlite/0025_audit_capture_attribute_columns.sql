ALTER TABLE `audit_events` ADD `source_tool` text GENERATED ALWAYS AS (json_extract(attributes, '$.source_tool')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `repo` text GENERATED ALWAYS AS (json_extract(attributes, '$.repo')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `file_path` text GENERATED ALWAYS AS (json_extract(attributes, '$.file_path')) VIRTUAL;--> statement-breakpoint
ALTER TABLE `audit_events` ADD `tool_name` text GENERATED ALWAYS AS (json_extract(attributes, '$.tool_name')) VIRTUAL;