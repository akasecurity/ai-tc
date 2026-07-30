CREATE TABLE `secret_vault` (
	`pointer_id` text PRIMARY KEY NOT NULL,
	`value_fingerprint` text NOT NULL,
	`fingerprint_key_version` integer NOT NULL,
	`key_version` integer NOT NULL,
	`category` text NOT NULL,
	`rule_id` text NOT NULL,
	`masked_match` text NOT NULL,
	`provider` text,
	`ciphertext` text NOT NULL,
	`nonce` text NOT NULL,
	`auth_tag` text NOT NULL,
	`occurrence_count` integer DEFAULT 1 NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_secret_vault_value` ON `secret_vault` (`value_fingerprint`);--> statement-breakpoint
CREATE TABLE `secret_vault_deref` (
	`id` text PRIMARY KEY NOT NULL,
	`pointer_id` text NOT NULL,
	`at` integer NOT NULL,
	`target` text NOT NULL,
	`reason` text NOT NULL,
	`outcome` text NOT NULL,
	`grant_id` text,
	`pointer_count` integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_secret_vault_deref_pointer` ON `secret_vault_deref` (`pointer_id`);--> statement-breakpoint
CREATE INDEX `idx_secret_vault_deref_reason_at` ON `secret_vault_deref` (`reason`,`at`);