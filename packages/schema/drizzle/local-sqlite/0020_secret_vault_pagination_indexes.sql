CREATE INDEX `idx_secret_vault_last_seen` ON `secret_vault` (`last_seen`,`pointer_id`);--> statement-breakpoint
CREATE INDEX `idx_secret_vault_reuse` ON `secret_vault` (`occurrence_count`,`pointer_id`);--> statement-breakpoint
CREATE INDEX `idx_secret_vault_deref_at` ON `secret_vault_deref` (`at`,`id`);