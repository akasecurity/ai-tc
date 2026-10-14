ALTER TABLE `inspection_findings` ADD `variable_name` text;--> statement-breakpoint
CREATE INDEX `idx_inspection_findings_variable_name` ON `inspection_findings` (`first_detected_at`) WHERE variable_name IS NOT NULL;--> statement-breakpoint
ALTER TABLE `secret_vault` ADD `variable_name` text;