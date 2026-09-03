DROP INDEX IF EXISTS `idx_finding_resolution_key`;--> statement-breakpoint
CREATE INDEX `idx_finding_resolution_key_created` ON `finding_resolution` (`finding_key`,`created_at`);