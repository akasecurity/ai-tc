ALTER TABLE `inspection_findings` ADD `line` integer;--> statement-breakpoint
ALTER TABLE `inspection_findings` ADD `col` integer;--> statement-breakpoint
ALTER TABLE `inspection_findings` ADD `context` text;--> statement-breakpoint
CREATE INDEX `idx_inspection_findings_context` ON `inspection_findings` (`first_detected_at`) WHERE context IS NOT NULL;