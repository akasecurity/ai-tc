CREATE TABLE `finding_resolution` (
	`id` text PRIMARY KEY NOT NULL,
	`finding_key` text NOT NULL,
	`status` text NOT NULL,
	`method` text NOT NULL,
	`resolved_at` integer NOT NULL,
	`evidence` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_finding_resolution_key` ON `finding_resolution` (`finding_key`);--> statement-breakpoint
ALTER TABLE `findings` ADD `finding_key` text;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_findings_key` ON `findings` (`finding_key`);