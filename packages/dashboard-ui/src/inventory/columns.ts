// Column sets for the inventory tables: one per asset type, plus the mixed set a
// harness's table uses. Each column reads one value for sorting and searching and
// may format it differently for display.
import type { AssetSummary, AssetType, ProjectSummary } from '@akasecurity/schema';

import { relativeTime } from '../lib/relativeTime.ts';
import { type InventoryRow, isProjectRow, metaText, rowType, TRUST, typeMeta } from './data.ts';

export interface Column {
  key: string;
  label: string;
  value: (row: InventoryRow) => string | number | null;
  display?: (row: InventoryRow, now: number) => string;
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

const metaColumn = (key: string, label: string, options: ColumnOptions = {}): Column =>
  assetColumn(key, label, (a) => metaText(a.meta, key), options);

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
    projectColumn('visibility', 'Visibility', (p) => p.visibility),
    projectColumn('findings', 'Findings', (p) => p.findingsCount, { num: true }),
    projectColumn('updatedAt', 'Updated', (p) => p.updatedAt, { display: relative }),
  ],
  skill: [
    metaColumn('source', 'Source', { mono: true, wide: true }),
    metaColumn('scope', 'Scope'),
    metaColumn('installedVersion', 'Installed', { mono: true }),
    metaColumn('latestVersion', 'Latest', { mono: true }),
    metaColumn('updatedAt', 'Updated', { display: relative }),
  ],
  mcp: [
    metaColumn('transport', 'Transport'),
    assetColumn('endpoint', 'Host', mcpEndpoint, { mono: true, wide: true }),
    metaColumn('scope', 'Scope'),
    assetColumn('trust', 'Trust', (a) => (a.trust ? TRUST[a.trust].label : null)),
  ],
  hook: [
    metaColumn('event', 'Event', { mono: true }),
    metaColumn('matcher', 'Matcher', { mono: true }),
    metaColumn('scope', 'Scope'),
    metaColumn('status', 'State'),
  ],
  config: [
    metaColumn('kind', 'Kind'),
    metaColumn('scope', 'Scope'),
    metaColumn('path', 'Path', { mono: true, wide: true }),
    metaColumn('updatedAt', 'Changed', { display: relative }),
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
    value: (row) => (isProjectRow(row) ? `${row.repo} · ${row.visibility}` : row.sub),
    mono: true,
    wide: true,
  },
];

export const NAME_COLUMN: Column = { key: 'name', label: 'Name', value: (row) => row.name };
