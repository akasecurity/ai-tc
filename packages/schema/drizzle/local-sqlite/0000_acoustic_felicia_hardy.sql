CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`parent_id` text,
	`root_session_id` text,
	`event_type` text NOT NULL,
	`host_id` text,
	`harness_id` text,
	`source_project_id` text,
	`started_at` integer NOT NULL,
	`ended_at` integer,
	`severity` text,
	`priority` text,
	`content` text,
	`content_hash` text,
	`attributes` text,
	FOREIGN KEY (`parent_id`) REFERENCES `audit_events`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`root_session_id`) REFERENCES `audit_events`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`host_id`) REFERENCES `inventory`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`harness_id`) REFERENCES `inventory`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_project_id`) REFERENCES `source_project`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_audit_parent` ON `audit_events` (`parent_id`);--> statement-breakpoint
CREATE INDEX `idx_audit_session` ON `audit_events` (`root_session_id`,`started_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_harness_t` ON `audit_events` (`harness_id`,`started_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_project_t` ON `audit_events` (`source_project_id`,`started_at`);--> statement-breakpoint
CREATE TABLE `classified_data` (
	`id` text PRIMARY KEY NOT NULL,
	`class` text NOT NULL,
	`label` text,
	`attributes` text
);
--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`source_tool` text NOT NULL,
	`kind` text NOT NULL,
	`occurred_at` integer NOT NULL,
	`content_hash` text NOT NULL,
	`content` text NOT NULL,
	`metadata` text
);
--> statement-breakpoint
CREATE INDEX `idx_events_occurred` ON `events` (`occurred_at`);--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`rule_id` text NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`span_start` integer NOT NULL,
	`span_end` integer NOT NULL,
	`masked_match` text NOT NULL,
	`action_taken` text NOT NULL,
	`confidence` real NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_findings_event` ON `findings` (`event_id`);--> statement-breakpoint
CREATE TABLE `inspection_definitions` (
	`id` text PRIMARY KEY NOT NULL,
	`rule_id` text NOT NULL,
	`name` text NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`definition` text NOT NULL,
	`version` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `inspection_findings` (
	`id` text PRIMARY KEY NOT NULL,
	`audit_event_id` text NOT NULL,
	`inspection_definition_id` text NOT NULL,
	`classified_data_id` text,
	`span_start` integer NOT NULL,
	`span_end` integer NOT NULL,
	`masked_match` text NOT NULL,
	`action_taken` text NOT NULL,
	`confidence` real NOT NULL,
	FOREIGN KEY (`audit_event_id`) REFERENCES `audit_events`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`inspection_definition_id`) REFERENCES `inspection_definitions`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`classified_data_id`) REFERENCES `classified_data`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_inspection_findings_event` ON `inspection_findings` (`audit_event_id`);--> statement-breakpoint
CREATE TABLE `installed_packs` (
	`id` text PRIMARY KEY NOT NULL,
	`namespace` text NOT NULL,
	`pack_id` text NOT NULL,
	`version` text NOT NULL,
	`name` text NOT NULL,
	`rules_json` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`policy_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_installed_packs_pack` ON `installed_packs` (`namespace`,`pack_id`);--> statement-breakpoint
CREATE TABLE `inventory` (
	`id` text PRIMARY KEY NOT NULL,
	`object_type` text NOT NULL,
	`location` text,
	`title` text,
	`host_id` text,
	`attributes` text NOT NULL,
	`os_version` text GENERATED ALWAYS AS (json_extract(attributes, '$.os_version')) VIRTUAL,
	`harness_version` text GENERATED ALWAYS AS (json_extract(attributes, '$.harness_version')) VIRTUAL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL,
	FOREIGN KEY (`host_id`) REFERENCES `inventory`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_inventory_type` ON `inventory` (`object_type`);--> statement-breakpoint
CREATE INDEX `idx_inventory_type_osver` ON `inventory` (`object_type`,`os_version`);--> statement-breakpoint
CREATE INDEX `idx_inventory_type_harnessver` ON `inventory` (`object_type`,`harness_version`);--> statement-breakpoint
CREATE TABLE `policies` (
	`id` text PRIMARY KEY NOT NULL,
	`scope` text DEFAULT 'global' NOT NULL,
	`target` text NOT NULL,
	`action` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`custom_keywords` text,
	`name` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_policies_scope_target` ON `policies` (`scope`,`target`);--> statement-breakpoint
CREATE TABLE `source_project` (
	`id` text PRIMARY KEY NOT NULL,
	`url` text,
	`name` text,
	`attributes` text NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL
);
