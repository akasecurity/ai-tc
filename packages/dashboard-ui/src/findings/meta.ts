// Presentational lookups for the findings views. Persistence responses
// are SEMANTIC (enums only — no colors/icons/labels); the view layer owns the
// mapping. Lives in @akasecurity/dashboard-ui so every consuming app renders
// the same category/action styling.
import type {
  FindingAction,
  FindingCategory,
  FindingGroup,
  FindingInstance,
  FindingStatus,
  Severity,
} from '@akasecurity/schema';

import type { IconComponent } from '../lib/icons.ts';
import {
  AlertIcon,
  CheckIcon,
  CodeIcon,
  DatabaseIcon,
  ExternalShareIcon,
  EyeIcon,
  KeyIcon,
  RedactIcon,
  ServerIcon,
  ShieldIcon,
  SlashCircleIcon,
  UserIcon,
} from '../shared/icons.tsx';

/** Severities in display order — drives the Severity filter. */
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Human-readable label per API detection category. */
export const CATEGORY_LABEL: Record<FindingCategory, string> = {
  secret: 'Secret',
  pii: 'PII',
  source_code: 'Source code',
  external_share: 'External share',
  mcp_server: 'MCP server',
  customer_data: 'Customer data',
  financial: 'Financial',
  phi: 'PHI',
  custom: 'Custom',
};

/** Per-category icon (falls back to KeyIcon for forward-compatible categories). */
export const CATEGORY_ICON: Record<FindingCategory, IconComponent> = {
  secret: KeyIcon,
  pii: UserIcon,
  source_code: CodeIcon,
  external_share: ExternalShareIcon,
  mcp_server: ServerIcon,
  customer_data: DatabaseIcon,
  financial: DatabaseIcon,
  phi: UserIcon,
  custom: KeyIcon,
};

/** Per-category icon-tile fill + text color (falls back to a neutral surface tone). */
export const CATEGORY_STYLE: Record<FindingCategory, string> = {
  secret: 'bg-sev-critical-fill text-sev-critical',
  pii: 'bg-sev-low-fill text-sev-low',
  source_code: 'bg-violet-fill text-violet',
  external_share: 'bg-teal-fill text-teal',
  mcp_server: 'bg-sev-high-fill text-sev-high',
  customer_data: 'bg-sev-high-fill text-sev-high',
  financial: 'bg-sev-high-fill text-sev-high',
  phi: 'bg-sev-low-fill text-sev-low',
  custom: 'bg-surface-2 text-text-2',
};

// The maps are exhaustive over FindingCategory (adding a member is a compile
// error), but a response isn't runtime-validated against the enum — an off-enum
// category would otherwise yield `undefined` and crash a cell. These string-keyed
// views make the fallbacks genuinely reachable. The icon lookup is a member
// access at the call site (`CATEGORY_ICON_FALLBACK[cat] ?? KeyIcon`), NOT a
// component-returning function call, so the render-created-component lint rule
// (react-hooks/static-components) stays satisfied.
export const CATEGORY_ICON_FALLBACK: Record<string, IconComponent | undefined> = CATEGORY_ICON;

export const categoryStyle = (category: string): string =>
  (CATEGORY_STYLE as Record<string, string | undefined>)[category] ?? 'bg-surface-2 text-text-2';

/** Per-action pill label + icon + tinted classes. */
export const ACTION_META: Record<
  FindingAction,
  { label: string; icon: IconComponent; className: string }
> = {
  blocked: {
    label: 'Blocked',
    icon: SlashCircleIcon,
    className: 'bg-sev-critical-fill text-sev-critical',
  },
  redacted: { label: 'Redacted', icon: RedactIcon, className: 'bg-primary-tint text-primary' },
  warned: { label: 'Warned', icon: AlertIcon, className: 'bg-sev-high-fill text-sev-high' },
  allowed: { label: 'Allowed', icon: CheckIcon, className: 'bg-ok-fill text-ok' },
  monitored: { label: 'Monitored', icon: EyeIcon, className: 'bg-surface-3 text-text-2' },
  quarantined: {
    label: 'Quarantined',
    icon: ShieldIcon,
    className: 'bg-sev-critical-fill text-sev-critical',
  },
};

/** The findings table's column identity + header, in display order. */
export interface FindingColumn {
  id: 'severity' | 'subtype' | 'sources' | 'locations' | 'action' | 'status' | 'latest';
  header: string;
}

export const FINDINGS_COLUMNS: FindingColumn[] = [
  { id: 'severity', header: 'Severity' },
  { id: 'subtype', header: 'Type' },
  { id: 'sources', header: 'Sources' },
  { id: 'locations', header: 'Locations' },
  { id: 'action', header: 'Action' },
  { id: 'status', header: 'Status' },
  { id: 'latest', header: 'Latest' },
];

/** Lifecycle-status pill label + Badge variant (see @akasecurity/ui-kit's Badge). */
export interface FindingStatusMeta {
  label: string;
  badge: 'high' | 'primary' | 'success' | 'default';
}

export const FINDING_STATUS_META: Record<FindingStatus, FindingStatusMeta> = {
  open: { label: 'Open', badge: 'high' },
  handled: { label: 'Handled', badge: 'primary' },
  resolved: { label: 'Resolved', badge: 'success' },
  dismissed: { label: 'Dismissed', badge: 'default' },
};

/** Status filter options in display order, 'all' first (the default/no-op filter). */
export const STATUS_FILTER_OPTIONS: { value: FindingStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'open', label: 'Open' },
  { value: 'handled', label: 'Handled' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'dismissed', label: 'Dismissed' },
];

/**
 * Filters groups by their derived (group-level) status. 'all' or omitting the
 * filter returns every group unchanged; a specific status keeps only groups
 * whose `status` matches exactly — a group with no status (legacy, predates
 * the resolution feature) never matches a specific status filter.
 */
export function filterGroupsByStatus(
  groups: FindingGroup[],
  status: FindingStatus | 'all' | undefined,
): FindingGroup[] {
  if (!status || status === 'all') return groups;
  return groups.filter((g) => g.status === status);
}

/**
 * Filters a single group's instances by the SAME status filter that decided
 * the group itself is visible under `filterGroupsByStatus`. Without this, an
 * expanded group under an active filter shows every instance regardless of
 * status — including ones that don't match — which is confusing under a
 * filter that promised to narrow the view down to one status.
 *
 * Never returns empty for a group `filterGroupsByStatus` already deemed
 * visible: `foldGroupStatus` (findings-group-build.ts) only ever assigns a
 * group's status to a candidate value when at least one instance actually
 * carries it, so a group whose status equals `status` is guaranteed to have
 * at least one matching instance.
 */
export function filterInstancesByStatus(
  instances: FindingInstance[],
  status: FindingStatus | 'all' | undefined,
): FindingInstance[] {
  if (!status || status === 'all') return instances;
  return instances.filter((i) => i.status === status);
}

/** The four multi-select filter dimensions of the findings toolbar. */
export interface FindingsFilters {
  severity: string[];
  type: string[];
  provider: string[];
  action: string[];
}

export const EMPTY_FILTERS: FindingsFilters = {
  severity: [],
  type: [],
  provider: [],
  action: [],
};

/** Column-visibility map: column id → visible. Absent id ⇒ visible. */
export type ColumnVisibility = Partial<Record<FindingColumn['id'], boolean>>;

/** The findings drawer target: a group, optionally narrowed to one instance. */
export interface Selection {
  finding: FindingGroup;
  /** When present the drawer shows a single location; otherwise the grouped view. */
  instance?: FindingInstance;
}
