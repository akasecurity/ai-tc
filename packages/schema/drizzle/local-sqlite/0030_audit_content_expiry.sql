ALTER TABLE `audit_events` ADD `content_expired_at` integer;--> statement-breakpoint
CREATE INDEX `idx_audit_expirable_body` ON `audit_events` (`started_at`) WHERE content IS NOT NULL;