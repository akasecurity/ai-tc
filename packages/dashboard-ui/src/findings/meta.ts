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
import { type Tone, TONE_SOFT } from '@akasecurity/ui-kit';

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
  // Distinct from 'source_code': that is code as sensitive CONTENT, this is a
  // vulnerability found in code.
  code_flaw: 'Code flaw',
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
  code_flaw: AlertIcon,
  external_share: ExternalShareIcon,
  mcp_server: ServerIcon,
  customer_data: DatabaseIcon,
  financial: DatabaseIcon,
  phi: UserIcon,
  custom: KeyIcon,
};

/** Per-category icon-tile tone (falls back to a neutral surface tone). */
export const CATEGORY_TONE: Record<FindingCategory, Tone> = {
  secret: 'critical',
  pii: 'low',
  source_code: 'violet',
  code_flaw: 'high',
  external_share: 'teal',
  mcp_server: 'high',
  customer_data: 'high',
  financial: 'high',
  phi: 'low',
  custom: 'neutral',
};

// The maps are exhaustive over FindingCategory (adding a member is a compile
// error), but a response isn't runtime-validated against the enum — an off-enum
// category would otherwise yield `undefined` and crash a cell. These string-keyed
// views make the fallbacks genuinely reachable. The icon lookup is a member
// access at the call site (`CATEGORY_ICON_FALLBACK[cat] ?? KeyIcon`), NOT a
// component-returning function call, so the render-created-component lint rule
// (react-hooks/static-components) stays satisfied.
export const CATEGORY_ICON_FALLBACK: Record<string, IconComponent | undefined> = CATEGORY_ICON;

// Returns the CLASS pair rather than the tone: every caller feeds it straight
// into `cn()` beside layout classes, and the off-enum fallback has to resolve
// somewhere — doing it here keeps that one place.
export const categoryStyle = (category: string): string => {
  // Object.hasOwn guards the widened lookup, exactly as policyMeta does: a category
  // arrives as a plain string, so it can collide with an Object.prototype member
  // ('__proto__', 'constructor', 'toString', …). The inherited member must NOT
  // resolve — it is truthy, so `?? 'neutral'` never fires, and TONE_SOFT has no such
  // key, leaving categoryStyle returning undefined despite its `: string` type. Read
  // through the widened view only after the guard.
  const table: Partial<Record<string, Tone>> = CATEGORY_TONE;
  const tone = Object.hasOwn(CATEGORY_TONE, category) ? table[category] : undefined;
  return TONE_SOFT[tone ?? 'neutral'];
};

/** Per-action pill label + icon + tinted classes. */
export const ACTION_META: Record<
  FindingAction,
  { label: string; icon: IconComponent; className: string }
> = {
  blocked: { label: 'Blocked', icon: SlashCircleIcon, className: TONE_SOFT.critical },
  redacted: { label: 'Redacted', icon: RedactIcon, className: TONE_SOFT.primary },
  warned: { label: 'Warned', icon: AlertIcon, className: TONE_SOFT.high },
  allowed: { label: 'Allowed', icon: CheckIcon, className: TONE_SOFT.ok },
  // The quietest of the six, and the only one carrying no family colour:
  // `neutral` is the untinted pair.
  monitored: { label: 'Monitored', icon: EyeIcon, className: TONE_SOFT.neutral },
  quarantined: { label: 'Quarantined', icon: ShieldIcon, className: TONE_SOFT.critical },
};

/**
 * Display label for an instance's location: the file path when the capture
 * had one, else the producing tool ("via Bash") for file-less captures
 * (prompts, tool output), else an em dash.
 */
export function instanceLocationLabel(instance: FindingInstance): string {
  if (instance.file) return instance.file;
  if (instance.toolName) return `via ${instance.toolName}`;
  return '—';
}

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

/**
 * Statuses in display order — drives the Status filter. Derived from
 * FINDING_STATUS_META (an exhaustive Record over FindingStatus, so adding an
 * enum member is a compile error there and automatically appears here); the
 * literal's key order IS the display order.
 */
export const FINDING_STATUSES = Object.keys(FINDING_STATUS_META) as FindingStatus[];

/**
 * Filters a single group's instances by the SAME statuses that decided the
 * group itself is visible (the store matches a group's derived status against
 * them — see applyFindingFilters). Without this, an expanded group under an
 * active filter shows every instance regardless of status — including ones
 * that don't match — which is confusing under a filter that promised to narrow
 * the view down to those statuses. An empty/absent selection is a no-op.
 *
 * CAN return empty for a group the store correctly kept: the group's status
 * folds over EVERY instance, while `group.instances` is only a preview of the
 * newest — every instance carrying a requested status may be older than the
 * preview window (the store pre-narrows the preview the same way, so this is
 * a pass-through then). Views render an explicit notice for that case rather
 * than an empty expansion.
 */
export function filterInstancesByStatus(
  instances: FindingInstance[],
  statuses: readonly string[] | undefined,
): FindingInstance[] {
  if (!statuses || statuses.length === 0) return instances;
  return instances.filter((i) => i.status !== undefined && statuses.includes(i.status));
}

/** The five multi-select filter dimensions of the findings toolbar. */
export interface FindingsFilters {
  severity: string[];
  type: string[];
  provider: string[];
  action: string[];
  status: string[];
}

export const EMPTY_FILTERS: FindingsFilters = {
  severity: [],
  type: [],
  provider: [],
  action: [],
  status: [],
};

/**
 * How the findings list is grouped. `grouped` folds by rule (which rules are
 * firing), `flat` lists one row per finding newest-first (what happened most
 * recently), `files` folds by repository and file (where findings live).
 *
 * Lives beside FindingsFilters because it is part of the same URL vocabulary —
 * a consumer parsing `?view=` validates against this list rather than
 * re-spelling the values.
 */
export const FINDINGS_VIEWS = ['grouped', 'flat', 'files'] as const;
export type FindingsView = (typeof FINDINGS_VIEWS)[number];

/** The default view — what an absent `?view=` means. */
export const DEFAULT_FINDINGS_VIEW: FindingsView = 'grouped';

export function isFindingsView(value: string): value is FindingsView {
  return (FINDINGS_VIEWS as readonly string[]).includes(value);
}

/** Toggle labels, and what each view counts — the units differ per view. */
export const FINDINGS_VIEW_LABEL: Record<FindingsView, string> = {
  grouped: 'By type',
  flat: 'All findings',
  files: 'By location',
};

/** Column-visibility map: column id → visible. Absent id ⇒ visible. */
export type ColumnVisibility = Partial<Record<FindingColumn['id'], boolean>>;

/** The findings drawer target: a group, optionally narrowed to one instance. */
export interface Selection {
  finding: FindingGroup;
  /** When present the drawer shows a single location; otherwise the grouped view. */
  instance?: FindingInstance;
}
