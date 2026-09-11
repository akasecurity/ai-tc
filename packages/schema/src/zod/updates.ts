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
  // The version the host would actually INSTALL, which is not always npm's
  // latest: a plugin resolved through a marketplace manifest that names an
  // exact version can only reach that version. Null when it could not be
  // resolved at all (offline / no registry auth).
  latest: string | null;
  updateAvailable: boolean;
  // Present only when `latest` came from a marketplace pin rather than from
  // npm, which is what lets a surface explain a machine that is current
  // against its own marketplace while npm has moved on. Without it the two
  // cases render identically — "up to date" beside a version the user can see
  // is behind — and the difference is exactly what a reader needs.
  marketplacePin?: MarketplacePin;
}

// Where a pinned `latest` came from, and what npm said instead.
export interface MarketplacePin {
  // The marketplace whose manifest carries the pin, so the message can name
  // the thing the user would have to move.
  marketplace: string;
  // npm's own latest for the same package, or null when it could not be read.
  // Carried rather than recomputed because a surface that re-derived it would
  // ask the registry a second time to explain one line of output.
  npmLatest: string | null;
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
