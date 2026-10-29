// Presentation descriptors for the Inventory page. The data itself (projects,
// assets, harnesses, events) arrives as props, typed by `@akasecurity/schema`.
// This module holds the label/icon/colour lookups the schema shapes don't carry,
// the page's selection model, and a few pure presentation helpers.
import type {
  AssetGroup,
  AssetSummary,
  AssetType,
  DetectionCategory,
  Flag,
  HarnessEventKind,
  HarnessSummary,
  ProjectSummary,
  TrustLevel,
} from '@akasecurity/schema';
import { INVENTORY_LIST_COUNT_CAP, isAttentionTrust } from '@akasecurity/schema';
import type { BadgeProps } from '@akasecurity/ui-kit';

import { formatDateTime } from '../lib/dateFormat.ts';
import type { IconName } from './icons.ts';

type Tone = NonNullable<BadgeProps['variant']>;

// ─── MCP trust ────────────────────────────────────────────────────────────────
export interface TrustMeta {
  label: string;
  icon: IconName;
  tone: Tone;
  fg: string;
  bg: string;
  iconBg: string;
  desc: string;
}
export const TRUST: Record<TrustLevel, TrustMeta> = {
  'known-good': {
    label: 'Known good',
    icon: 'shield-check',
    tone: 'success',
    fg: 'text-ok-ink',
    bg: 'bg-ok-fill',
    iconBg: 'bg-ok-ink',
    desc: 'Reviewed & allow-listed. Agents may call it freely.',
  },
  risky: {
    label: 'Risky',
    icon: 'alert',
    tone: 'high',
    fg: 'text-sev-high-ink',
    bg: 'bg-sev-high-fill',
    iconBg: 'bg-sev-high-ink',
    desc: 'Allowed, but reaches sensitive systems or external hosts. Use with care.',
  },
  unapproved: {
    label: 'Unapproved',
    icon: 'x-circle',
    tone: 'critical',
    fg: 'text-sev-critical-ink',
    bg: 'bg-sev-critical-fill',
    iconBg: 'bg-sev-critical-ink',
    desc: 'Not reviewed or explicitly denied — calls are blocked at the proxy.',
  },
};
export const TRUST_ORDER: TrustLevel[] = ['known-good', 'risky', 'unapproved'];

// ─── Attention flags ──────────────────────────────────────────────────────────
export interface FlagMeta {
  label: string;
  short: string;
  icon: IconName;
  tone: Tone;
}
export const FLAG: Record<Flag, FlagMeta> = {
  update: { label: 'Update available', short: 'Update', icon: 'arrow-up', tone: 'high' },
  stale: { label: 'Stale', short: 'Stale', icon: 'clock', tone: 'default' },
  conflict: { label: 'Conflict', short: 'Conflict', icon: 'branch', tone: 'critical' },
  unknown: { label: 'Unverified', short: 'Unverified', icon: 'help', tone: 'critical' },
  change: { label: 'Changed', short: 'Changed', icon: 'edit', tone: 'low' },
  untracked: { label: 'Untracked', short: 'Untracked', icon: 'eye-off', tone: 'high' },
  risk: { label: 'Security risk', short: 'Risk', icon: 'alert', tone: 'critical' },
  findings: { label: 'Sensitive data', short: 'Findings', icon: 'alert', tone: 'critical' },
};

// ─── Row status ───────────────────────────────────────────────────────────────
/** What a row can need attention for: an asset flag, or an MCP server's trust below known-good. */
export type StatusKey = Flag | Exclude<TrustLevel, 'known-good'>;

/** Most to least severe; the status filters and badges list keys in this order. */
export const STATUS_ORDER: StatusKey[] = [
  'unapproved',
  'risk',
  'conflict',
  'unknown',
  'findings',
  'risky',
  'change',
  'untracked',
  'update',
  'stale',
];

export const STATUS: Record<StatusKey, FlagMeta> = {
  ...FLAG,
  unapproved: { label: 'Unapproved', short: 'Unapproved', icon: 'x-circle', tone: 'critical' },
  risky: { label: 'Risky', short: 'Risky', icon: 'alert', tone: 'high' },
};

// ─── Asset-type presentation (icon · colours · label) ─────────────────────────
export interface TypeMeta {
  type: AssetType;
  label: string;
  /** Singular form, e.g. "Skill". */
  one: string;
  icon: IconName;
  fg: string;
  bg: string;
}
export const PROJECT_GROUP: TypeMeta = {
  type: 'project',
  one: 'Project',
  label: 'Projects',
  icon: 'repo',
  fg: 'text-primary',
  bg: 'bg-primary-tint',
};
/** Single source of per-asset-type presentation (label · icon · colors). */
export const ASSET_META = {
  skill: {
    type: 'skill',
    one: 'Skill',
    label: 'Skills',
    icon: 'sparkles',
    fg: 'text-violet-ink',
    bg: 'bg-violet-fill',
  },
  mcp: {
    type: 'mcp',
    one: 'MCP server',
    label: 'MCP servers',
    icon: 'server',
    fg: 'text-teal-ink',
    bg: 'bg-teal-fill',
  },
  hook: {
    type: 'hook',
    one: 'Hook',
    label: 'Hooks',
    icon: 'route',
    fg: 'text-sev-low-ink',
    bg: 'bg-sev-low-fill',
  },
  config: {
    type: 'config',
    one: 'Configuration file',
    label: 'Configuration',
    icon: 'sliders',
    fg: 'text-teal-ink',
    bg: 'bg-surface-2',
  },
} satisfies Record<Exclude<AssetType, 'project'>, TypeMeta>;
export const GROUPS: TypeMeta[] = [
  PROJECT_GROUP,
  ASSET_META.skill,
  ASSET_META.mcp,
  ASSET_META.hook,
  ASSET_META.config,
];
/** A label for use mid-sentence: "Skills" → "skills", an acronym like "MCP servers" kept. */
export const inlineLabel = (label: string): string =>
  label.replace(/^[A-Z](?=[a-z])/, (c) => c.toLowerCase());

export const typeMeta = (type: AssetType): TypeMeta =>
  type === 'project' ? PROJECT_GROUP : ASSET_META[type];
/** Icon + colours for an asset tile — the API's AssetSummary carries no presentation. */
export const assetTile = (type: AssetType): { icon: IconName; fg: string; bg: string } => {
  const { icon, fg, bg } = typeMeta(type);
  return { icon, fg, bg };
};

// ─── Sensitive-data categories ────────────────────────────────────────────────
/** Icon + colours for a category of finding on a project's page. */
export const SENSITIVE_CATEGORY: Record<
  DetectionCategory,
  { icon: IconName; fg: string; bg: string }
> = {
  secret: { icon: 'key', fg: 'text-sev-critical-ink', bg: 'bg-sev-critical-fill' },
  pii: { icon: 'user', fg: 'text-sev-low-ink', bg: 'bg-sev-low-fill' },
  phi: { icon: 'user', fg: 'text-sev-low-ink', bg: 'bg-sev-low-fill' },
  financial: { icon: 'database', fg: 'text-sev-high-ink', bg: 'bg-sev-high-fill' },
  code_context: { icon: 'code', fg: 'text-violet-ink', bg: 'bg-violet-fill' },
  code_flaw: { icon: 'alert', fg: 'text-sev-high-ink', bg: 'bg-sev-high-fill' },
  custom: { icon: 'flag', fg: 'text-text-2', bg: 'bg-surface-2' },
  config: { icon: 'sliders', fg: 'text-teal-ink', bg: 'bg-teal-fill' },
};

// ─── Date formatting ──────────────────────────────────────────────────────────
const DATE_TIME: Intl.DateTimeFormatOptions = {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
};

/** Compact local datetime for inventory captions, e.g. when a file was withheld. */
export function fmtDateTime(iso: string, locale: string): string {
  return formatDateTime(Date.parse(iso), locale, DATE_TIME);
}

// ─── Harness enforcement-event kinds ──────────────────────────────────────────
export interface EventKindMeta {
  label: string;
  icon: IconName;
  tone: Tone;
  fg: string;
  bg: string;
}
export const EVENT_KIND: Record<HarnessEventKind, EventKindMeta> = {
  block: {
    label: 'Blocked',
    icon: 'slash-circle',
    tone: 'critical',
    fg: 'text-sev-critical-ink',
    bg: 'bg-sev-critical-fill',
  },
  redact: {
    label: 'Redacted',
    icon: 'redact',
    tone: 'teal',
    fg: 'text-teal-ink',
    bg: 'bg-teal-fill',
  },
  warn: {
    label: 'Warned',
    icon: 'alert',
    tone: 'high',
    fg: 'text-sev-high-ink',
    bg: 'bg-sev-high-fill',
  },
};

// ─── Table rows ───────────────────────────────────────────────────────────────
/** One row of an inventory table: a project, or a skill / MCP server / hook / config asset. */
export type InventoryRow = ProjectSummary | AssetSummary;

export const isProjectRow = (row: InventoryRow): row is ProjectSummary => !('type' in row);

export const rowType = (row: InventoryRow): AssetType => (isProjectRow(row) ? 'project' : row.type);

/** The row's attention reasons, most severe first; empty when the row is OK. */
export function statusKeys(row: InventoryRow): StatusKey[] {
  if (isProjectRow(row)) return (row.findingsCount ?? 0) > 0 ? ['findings'] : [];
  const keys = new Set<StatusKey>(row.flags);
  if (row.type === 'mcp' && isAttentionTrust(row.trust)) {
    keys.add(row.trust);
  }
  return STATUS_ORDER.filter((k) => keys.has(k));
}

export const needsAttention = (row: InventoryRow): boolean => statusKeys(row).length > 0;

/** Every row a harness lists: its projects, then its assets category by category. */
export function harnessRows(harness: HarnessSummary): InventoryRow[] {
  return [...harness.projects, ...harness.categories.flatMap((c) => c.assets)];
}

/** Every row of one type across the whole inventory. */
export function typeRows(
  type: AssetType,
  projects: ProjectSummary[],
  assetGroups: AssetGroup[],
): InventoryRow[] {
  if (type === 'project') return projects;
  return assetGroups.find((g) => g.type === type)?.items ?? [];
}

/** An endpoint count as display text. A list stops counting at the cap, so a list count there reads "100+". */
export function endpointCountText(count: number, fromList: boolean): string {
  return fromList && count >= INVENTORY_LIST_COUNT_CAP
    ? `${String(INVENTORY_LIST_COUNT_CAP)}+`
    : String(count);
}

/** "1 endpoint", "12 endpoints", "100+ endpoints". */
export function endpointsText(count: number, fromList: boolean): string {
  return `${endpointCountText(count, fromList)} ${count === 1 ? 'endpoint' : 'endpoints'}`;
}

/** A `meta` value as display text: scalars as-is, string lists comma-joined, anything else null. */
export function metaText(meta: Record<string, unknown>, key: string): string | null {
  const v = meta[key];
  if (typeof v === 'string') return v === '' ? null : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
    return v.length > 0 ? v.join(', ') : null;
  }
  return null;
}

// ─── Selection ────────────────────────────────────────────────────────────────
export type InventoryView = 'harness' | 'type';

/** A row opened from a table into its details page. */
export interface InventoryItem {
  type: AssetType;
  id: string;
}

/**
 * The page's selection: which list the left panel shows, the harness and the type
 * last picked in each list, and the row opened from the table (null = the table).
 */
export interface Selection {
  view: InventoryView;
  harness: HarnessSummary['id'] | null;
  type: AssetType;
  item: InventoryItem | null;
}

export const DEFAULT_SELECTION: Selection = {
  view: 'harness',
  harness: null,
  type: 'project',
  item: null,
};

/** The minimal shape resolveInventorySelection needs from each nav dataset. */
export interface InventoryNavData {
  harnesses: {
    id: HarnessSummary['id'];
    projects: { id: string }[];
    categories: { type: AssetType; assets: { id: string }[] }[];
  }[];
  projects: { id: string }[];
  assetGroups: { type: AssetType; items: { id: string }[] }[];
}

/**
 * Resolve the active selection against the loaded data: a harness that is gone
 * falls back to the first harness (null when there are none), and an opened row
 * that is gone closes back to its table.
 */
export function resolveInventorySelection(requested: Selection, data: InventoryNavData): Selection {
  const harness =
    requested.harness !== null && data.harnesses.some((h) => h.id === requested.harness)
      ? requested.harness
      : (data.harnesses[0]?.id ?? null);
  const item = requested.item;
  const itemPresent =
    item !== null &&
    (item.type === 'project'
      ? data.projects.some((p) => p.id === item.id) ||
        data.harnesses.some((h) => h.projects.some((p) => p.id === item.id))
      : data.assetGroups.some(
          (g) => g.type === item.type && g.items.some((it) => it.id === item.id),
        ) ||
        data.harnesses.some((h) =>
          h.categories.some(
            (c) => c.type === item.type && c.assets.some((it) => it.id === item.id),
          ),
        ));
  return { ...requested, harness, item: itemPresent ? item : null };
}
