CREATE TABLE `_pack_write_gate` (
	`id` integer PRIMARY KEY NOT NULL,
	`open` integer DEFAULT 0 NOT NULL,
	CONSTRAINT "ck_pack_write_gate_single_row" CHECK("_pack_write_gate"."id" = 1)
);
--> statement-breakpoint
ALTER TABLE `available_packs` ADD `recorded_by` text;--> statement-breakpoint
INSERT OR IGNORE INTO _pack_write_gate (id, open) VALUES (1, 0);
--> statement-breakpoint
CREATE TRIGGER trg_installed_packs_write_gate
BEFORE UPDATE OF version, name, rules_json ON installed_packs
WHEN (SELECT open FROM _pack_write_gate WHERE id = 1) IS NOT 1
BEGIN SELECT RAISE(IGNORE); END;