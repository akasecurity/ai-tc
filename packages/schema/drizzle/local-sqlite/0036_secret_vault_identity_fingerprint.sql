ALTER TABLE `secret_vault` ADD `value_identity_fingerprint` text DEFAULT '' NOT NULL;--> statement-breakpoint
UPDATE `secret_vault` SET `value_identity_fingerprint` = `value_fingerprint`;
