import type { DatabaseSync } from 'node:sqlite';

import { getRow } from '../internal/rows.ts';

/** The three columns every consumer of the current config scan reads. */
export interface LatestConfigScanRow {
  id: string;
  started_at: number;
  attributes: string | null;
}

/**
 * The single definition of "the current config scan": the newest `config_scan`
 * audit event, newest `started_at` first with `id` as the tie-break. The
 * Skills & Hooks report and the Inventory asset projection must share this
 * query so they can never disagree about which scan is current.
 */
export function latestConfigScan(db: DatabaseSync): LatestConfigScanRow | undefined {
  return getRow<LatestConfigScanRow>(
    db.prepare(
      `SELECT id, started_at, attributes FROM audit_events
          WHERE event_type = 'config_scan'
          ORDER BY started_at DESC, id DESC LIMIT 1`,
    ),
  );
}
