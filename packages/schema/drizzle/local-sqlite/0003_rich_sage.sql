CREATE TABLE `egress_decision_override` (
	`id` text PRIMARY KEY NOT NULL,
	`destination_id` text NOT NULL,
	`decision` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`destination_id`) REFERENCES `share_destination`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_egress_decision_override` ON `egress_decision_override` (`destination_id`);--> statement-breakpoint
CREATE TABLE `file_access_override` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`path` text NOT NULL,
	`access` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `source_project`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_file_access_override_project` ON `file_access_override` (`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_file_access_override` ON `file_access_override` (`project_id`,`path`);--> statement-breakpoint
CREATE TABLE `harness_asset` (
	`id` text PRIMARY KEY NOT NULL,
	`harness_id` text NOT NULL,
	`asset_id` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`harness_id`) REFERENCES `inventory`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`asset_id`) REFERENCES `inventory_asset`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_harness_asset_harness` ON `harness_asset` (`harness_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_harness_asset` ON `harness_asset` (`harness_id`,`asset_id`);--> statement-breakpoint
CREATE TABLE `inventory_asset` (
	`id` text PRIMARY KEY NOT NULL,
	`asset_type` text NOT NULL,
	`name` text NOT NULL,
	`sub` text,
	`description` text,
	`flags_json` text DEFAULT '[]' NOT NULL,
	`meta_json` text DEFAULT '{}' NOT NULL,
	`trust` text,
	`tools_json` text,
	`provenance` text DEFAULT 'scan' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_inventory_asset_type` ON `inventory_asset` (`asset_type`);--> statement-breakpoint
CREATE TABLE `mcp_trust_override` (
	`id` text PRIMARY KEY NOT NULL,
	`asset_id` text NOT NULL,
	`trust` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`asset_id`) REFERENCES `inventory_asset`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_mcp_trust_override` ON `mcp_trust_override` (`asset_id`);--> statement-breakpoint
CREATE TABLE `project_file` (
	`id` text PRIMARY KEY NOT NULL,
	`project_id` text NOT NULL,
	`path` text NOT NULL,
	`name` text NOT NULL,
	`origin` text NOT NULL,
	`default_access` text NOT NULL,
	`findings_count` integer DEFAULT 0 NOT NULL,
	`blocked_at` integer,
	`note` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`project_id`) REFERENCES `source_project`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_project_file_project` ON `project_file` (`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_project_file` ON `project_file` (`project_id`,`path`);--> statement-breakpoint
CREATE TABLE `share_call_site` (
	`id` text PRIMARY KEY NOT NULL,
	`endpoint_id` text NOT NULL,
	`project` text NOT NULL,
	`file` text NOT NULL,
	`line` integer NOT NULL,
	`snippet` text NOT NULL,
	`dynamic` integer DEFAULT false NOT NULL,
	`vendored` integer DEFAULT false NOT NULL,
	`project_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`endpoint_id`) REFERENCES `share_endpoint`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_share_call_site_endpoint` ON `share_call_site` (`endpoint_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_share_call_site` ON `share_call_site` (`endpoint_id`,`project`,`file`,`line`);--> statement-breakpoint
CREATE TABLE `share_destination` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`name` text NOT NULL,
	`host` text NOT NULL,
	`category` text NOT NULL,
	`trust` text NOT NULL,
	`note` text,
	`network_json` text,
	`last_seen` integer NOT NULL,
	`provenance` text DEFAULT 'scan' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_share_destination_kind` ON `share_destination` (`kind`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_share_destination_host` ON `share_destination` (`host`);--> statement-breakpoint
CREATE TABLE `share_endpoint` (
	`id` text PRIMARY KEY NOT NULL,
	`destination_id` text NOT NULL,
	`method` text NOT NULL,
	`transport` text NOT NULL,
	`url` text NOT NULL,
	`template` integer DEFAULT false NOT NULL,
	`data_class` text NOT NULL,
	`last_seen` integer NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`destination_id`) REFERENCES `share_destination`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_share_endpoint_dest` ON `share_endpoint` (`destination_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_share_endpoint` ON `share_endpoint` (`destination_id`,`method`,`url`);