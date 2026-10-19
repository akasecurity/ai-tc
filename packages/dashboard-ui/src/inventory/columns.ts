// Column sets for the inventory tables: one per asset type, plus the mixed set a
// harness's table uses. Each column reads one value for sorting and searching and
// may format it differently for display.
import type { AssetSummary, AssetType, ProjectSummary } from '@akasecurity/schema';
import {
  type ASSET_LIST_META_KEYS,
  MCP_TOOLS_USED_WINDOW_DAYS,
  PROJECT_FINDINGS_WINDOW_DAYS,
} from '@akasecurity/schema';

import { relativeTime } from '../lib/relativeTime.ts';
import {
  endpointCountText,
  type InventoryRow,
  isProjectRow,
  metaText,
  rowType,
  TRUST,
  typeMeta,
} from './data.ts';

export interface Column {
  key: string;
  label: string;
  value: (row: InventoryRow) => string | number | null;
  display?: (row: InventoryRow, now: number) => string;
  /** A short tag shown after the cell's text, e.g. "2 versions". */
  chip?: (row: InventoryRow) => string | null;
  mono?: boolean;
  num?: boolean;
  wide?: boolean;
}

type ColumnOptions = Pick<Column, 'mono' | 'num' | 'wide' | 'display'>;

function projectColumn(
  key: string,
  label: string,
  get: (p: ProjectSummary) => string | number | null,
  options: ColumnOptions = {},
): Column {
  return { key, label, value: (row) => (isProjectRow(row) ? get(row) : null), ...options };
}

function assetColumn(
  key: string,
  label: string,
  get: (a: AssetSummary) => string | number | null,
  options: ColumnOptions = {},
): Column {
  return { key, label, value: (row) => (isProjectRow(row) ? null : get(row)), ...options };
}

/** A `meta` key an asset list carries for `T`: a column can read no other. */
type ListedKey<T extends keyof typeof ASSET_LIST_META_KEYS> =
  (typeof ASSET_LIST_META_KEYS)[T][number];

function metaColumn<T extends keyof typeof ASSET_LIST_META_KEYS>(
  _type: T,
  key: ListedKey<T>,
  label: string,
  options: ColumnOptions = {},
): Column {
  return assetColumn(key, label, (a) => metaText(a.meta, key), options);
}

const relative: ColumnOptions['display'] = (row, now) => {
  const iso = isProjectRow(row) ? row.updatedAt : metaText(row.meta, 'updatedAt');
  return iso ? relativeTime(iso, now) : '';
};

/** A remote MCP server's host, or a local one's command. */
function mcpEndpoint(asset: AssetSummary): string | null {
  const url = metaText(asset.meta, 'url');
  if (url) {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  }
  return metaText(asset.meta, 'command');
}

export const TYPE_COLUMNS: Record<AssetType, Column[]> = {
  project: [
    projectColumn('repo', 'Repository', (p) => p.repo, { mono: true, wide: true }),
    projectColumn('language', 'Language', (p) => p.language || null),
    projectColumn(
      'findings',
      `Findings · ${String(PROJECT_FINDINGS_WINDOW_DAYS)}d`,
      (p) => p.findingsCount,
      { num: true },
    ),
    projectColumn('updatedAt', 'Updated', (p) => p.updatedAt, { display: relative }),
  ],
  skill: [
    metaColumn('skill', 'source', 'Source', { mono: true, wide: true }),
    metaColumn('skill', 'scope', 'Scope'),
    metaColumn('skill', 'installedVersion', 'Installed', { mono: true }),
    metaColumn('skill', 'latestVersion', 'Latest', { mono: true }),
    metaColumn('skill', 'updatedAt', 'Updated', { display: relative }),
  ],
  mcp: [
    metaColumn('mcp', 'transport', 'Transport'),
    assetColumn('endpoint', 'Host', mcpEndpoint, { mono: true, wide: true }),
    metaColumn('mcp', 'scope', 'Scope'),
    assetColumn('trust', 'Trust', (a) => (a.trust ? TRUST[a.trust].label : null)),
  ],
  hook: [
    metaColumn('hook', 'event', 'Event', { mono: true }),
    metaColumn('hook', 'matcher', 'Matcher', { mono: true }),
    metaColumn('hook', 'scope', 'Scope'),
    metaColumn('hook', 'status', 'State'),
  ],
  config: [
    metaColumn('config', 'kind', 'Kind'),
    metaColumn('config', 'scope', 'Scope'),
    metaColumn('config', 'path', 'Path', { mono: true, wide: true }),
    metaColumn('config', 'updatedAt', 'Changed', { display: relative }),
  ],
};

export const MIXED_COLUMNS: Column[] = [
  {
    key: 'type',
    label: 'Type',
    value: (row) => typeMeta(rowType(row)).one,
  },
  {
    key: 'detail',
    label: 'Detail',
    value: (row) => (isProjectRow(row) ? row.repo : row.sub),
    mono: true,
    wide: true,
  },
];

export const NAME_COLUMN: Column = { key: 'name', label: 'Name', value: (row) => row.name };

/**
 * How many endpoints report the row. A table shows it only when its rows carry
 * the count, which a store that records who reports what does.
 */
export const ENDPOINTS_COLUMN: Column = {
  key: 'machines',
  label: 'Endpoints',
  value: (row) => row.machines ?? null,
  display: (row) => (row.machines === undefined ? '' : endpointCountText(row.machines, true)),
  chip: (row) =>
    !isProjectRow(row) && row.variants !== undefined && row.variants > 1
      ? `${String(row.variants)} versions`
      : null,
  num: true,
};

/** The distinct tools called through an MCP server, shown when the rows carry the count. */
export const TOOLS_USED_COLUMN: Column = assetColumn(
  'toolsUsed',
  `Tools used · ${String(MCP_TOOLS_USED_WINDOW_DAYS)}d`,
  (a) => a.toolsUsed ?? null,
  { num: true },
);

/**
 * The row columns a table shows: the type's own, Tools used on an MCP table and
 * Endpoints on any, each when the rows carry it.
 */
export function tableColumns(type: AssetType | null, rows: readonly InventoryRow[]): Column[] {
  const columns = [...(type === null ? MIXED_COLUMNS : TYPE_COLUMNS[type])];
  if (type === 'mcp' && rows.some((r) => !isProjectRow(r) && r.toolsUsed !== undefined)) {
    columns.push(TOOLS_USED_COLUMN);
  }
  if (rows.some((r) => r.machines !== undefined)) columns.push(ENDPOINTS_COLUMN);
  return columns;
}
