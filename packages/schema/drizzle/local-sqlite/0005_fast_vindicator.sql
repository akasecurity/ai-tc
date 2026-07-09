PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_mcp_trust_override` (
	`id` text PRIMARY KEY NOT NULL,
	`asset_id` text NOT NULL,
	`trust` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
INSERT INTO `__new_mcp_trust_override`("id", "asset_id", "trust", "created_at", "updated_at") SELECT "id", "asset_id", "trust", "created_at", "updated_at" FROM `mcp_trust_override`;--> statement-breakpoint
DROP TABLE `mcp_trust_override`;--> statement-breakpoint
ALTER TABLE `__new_mcp_trust_override` RENAME TO `mcp_trust_override`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_mcp_trust_override` ON `mcp_trust_override` (`asset_id`);