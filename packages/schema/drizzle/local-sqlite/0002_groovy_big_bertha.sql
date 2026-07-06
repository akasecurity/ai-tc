CREATE TABLE `exceptions` (
	`id` text PRIMARY KEY NOT NULL,
	`rule_id` text NOT NULL,
	`category` text NOT NULL,
	`value_fingerprint` text NOT NULL,
	`key_version` integer NOT NULL,
	`masked_value` text NOT NULL,
	`scope` text NOT NULL,
	`expires_at` integer,
	`max_uses` integer,
	`use_count` integer DEFAULT 0 NOT NULL,
	`last_used_at` integer,
	`justification` text NOT NULL,
	`conditions` text,
	`created_by` text NOT NULL,
	`created_via` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`revoked_at` integer,
	`revoked_by` text,
	`revoke_reason` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_exceptions_active` ON `exceptions` (`rule_id`,`value_fingerprint`,`key_version`) WHERE revoked_at IS NULL;