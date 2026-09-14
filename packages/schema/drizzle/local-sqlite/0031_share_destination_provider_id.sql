ALTER TABLE `share_destination` ADD `provider_id` text;--> statement-breakpoint
CREATE INDEX `idx_share_destination_provider` ON `share_destination` (`provider_id`) WHERE `provider_id` IS NOT NULL;