-- Stable per-project reconcile key for egress call sites, plus a host-keyed
-- egress decision override that survives destination pruning.
--
-- DROP INDEX IF EXISTS, not a bare DROP: the applier replays a pending
-- migration's non-index statements verbatim, so a store that lost
-- uq_share_call_site out of band would throw here — and on the plugin hook path
-- that throw is swallowed fail-open, silently stopping capture.
ALTER TABLE `share_call_site` ADD `project_key` text DEFAULT '' NOT NULL;--> statement-breakpoint
DROP INDEX IF EXISTS `uq_share_call_site`;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_share_call_site` ON `share_call_site` (`endpoint_id`,`project_key`,`file`,`line`);--> statement-breakpoint
ALTER TABLE `egress_decision_override` ADD `host` text;--> statement-breakpoint
CREATE UNIQUE INDEX `uq_egress_decision_override_host` ON `egress_decision_override` (`host`) WHERE `host` IS NOT NULL;
