ALTER TABLE `inspection_findings` ADD `finding_key` text;--> statement-breakpoint
ALTER TABLE `inspection_findings` ADD `first_detected_at` integer;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_inspection_findings_key` ON `inspection_findings` (`finding_key`);