CREATE TABLE `available_packs` (
	`id` text PRIMARY KEY NOT NULL,
	`namespace` text NOT NULL,
	`pack_id` text NOT NULL,
	`version` text NOT NULL,
	`name` text NOT NULL,
	`rules_json` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_available_packs_pack` ON `available_packs` (`namespace`,`pack_id`);