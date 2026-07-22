-- Stable per-project reconcile key for egress call sites, plus a host-keyed
-- egress decision override that survives destination pruning.
--
-- DROP INDEX IF EXISTS, not a bare DROP: the applier replays a pending
-- migration's non-index statements verbatim, so a store that lost
-- uq_share_call_site out of band would throw here — and on the plugin hook path
-- that throw is swallowed fail-open, silently stopping capture.
--
-- egress_decision_override.destination_id becomes nullable with ON DELETE SET
-- NULL, which SQLite can only do by rebuilding the table. `host` is ADDed
-- before the rebuild so the copy has a column to read and so the migration
-- still presents two probeable columns to the applier's evidence check.
ALTER TABLE `share_call_site` ADD `project_key` text DEFAULT '' NOT NULL;--> statement-breakpoint
DROP INDEX IF EXISTS `uq_share_call_site`;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_share_call_site` ON `share_call_site` (`endpoint_id`,`project_key`,`file`,`line`);--> statement-breakpoint
ALTER TABLE `egress_decision_override` ADD `host` text;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_egress_decision_override` (
	`id` text PRIMARY KEY NOT NULL,
	`destination_id` text,
	`host` text,
	`decision` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`destination_id`) REFERENCES `share_destination`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
INSERT INTO `__new_egress_decision_override`("id", "destination_id", "host", "decision", "created_at", "updated_at") SELECT "id", "destination_id", "host", "decision", "created_at", "updated_at" FROM `egress_decision_override`;--> statement-breakpoint
DROP TABLE `egress_decision_override`;--> statement-breakpoint
ALTER TABLE `__new_egress_decision_override` RENAME TO `egress_decision_override`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_egress_decision_override` ON `egress_decision_override` (`destination_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_egress_decision_override_host` ON `egress_decision_override` (`host`) WHERE `host` IS NOT NULL;
