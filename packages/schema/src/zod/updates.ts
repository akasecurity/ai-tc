// Update-status DTOs for the local CLI/plugin update surface. Plain TS
// interfaces (no Zod, no .meta) — these are read-projections of npm + the
// Claude Code plugin ledger, shared by the CLI's update commands and the OSS
// web-ui's Updates page, and deliberately kept out of the generated OpenAPI.

export type ComponentKind = 'cli' | 'plugin';

// A row in the update table: what's installed vs. the latest published.
// `installed` is null when the component isn't installed; `latest` is null when
// it couldn't be resolved (offline / no registry auth).
export interface ComponentStatus {
  id: string;
  name: string;
  kind: ComponentKind;
  installed: string | null;
  latest: string | null;
  updateAvailable: boolean;
}

// An available agent plugin the user has NOT installed yet — surfaced so they
// learn a new integration exists.
export interface AvailablePlugin {
  id: string;
  name: string;
  latest: string | null;
}

export interface UpdateReport {
  statuses: ComponentStatus[];
  availablePlugins: AvailablePlugin[];
}

// The passive-notice cache persisted at ~/.aka/data/update-check.json.
export interface UpdateCache {
  checkedAt: number;
  report: UpdateReport;
  notifiedPluginIds: string[];
}
