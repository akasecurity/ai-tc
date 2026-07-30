CREATE TABLE `secret_vault_sighting` (
	`id` text PRIMARY KEY NOT NULL,
	`pointer_id` text NOT NULL,
	`location` text NOT NULL,
	`kind` text NOT NULL,
	`first_seen` integer NOT NULL,
	`last_seen` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_secret_vault_sighting` ON `secret_vault_sighting` (`pointer_id`,`location`);