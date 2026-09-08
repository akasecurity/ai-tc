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
// category would otherwise yield `undefined` and crash a cell, or (for the icon
// table) resolve an inherited Object.prototype member and crash the render
// outright: React throws on an element type of `object`, rather than merely
// losing a tint. Unlike categoryStyle's and categoryLabel's tables, this one
// can't be guarded with an Object.hasOwn wrapper function: the result is
// rendered as a JSX tag (`<Icon />`), and a component derived from a function
// call — even one assigned to a const first — trips the render-created-component
// lint rule (react-hooks/static-components), which cannot see that the
// underlying icon reference is module-level and stable either way. A
// null-prototype table has no prototype chain to resolve an inherited member
// from, so the ordinary `CATEGORY_ICON_FALLBACK[cat] ?? KeyIcon` member access
// at each call site is safe without a guard, function or otherwise.
export const CATEGORY_ICON_FALLBACK: Record<string, IconComponent | undefined> = Object.assign(
  Object.create(null) as Record<string, IconComponent | undefined>,
  CATEGORY_ICON,
);

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

// Same guard, over the label table. Mirrors the off-enum category itself back
// as the label (matching policyMeta's unknown-id convention) rather than
// inventing copy for a value the enum doesn't name.
export const categoryLabel = (category: string): string => {
  const table: Partial<Record<string, string>> = CATEGORY_LABEL;
  const label = Object.hasOwn(CATEGORY_LABEL, category) ? table[category] : undefined;
  return label ?? category;
};

/** Per-action pill label + icon + tinted classes. */
export interface ActionMeta {
  label: string;
  icon: IconComponent;
  className: string;
}

export const ACTION_META: Record<FindingAction, ActionMeta> = {
  blocked: { label: 'Blocked', icon: SlashCircleIcon, className: TONE_SOFT.critical },
  redacted: { label: 'Redacted', icon: RedactIcon, className: TONE_SOFT.primary },
  warned: { label: 'Warned', icon: AlertIcon, className: TONE_SOFT.high },
  allowed: { label: 'Allowed', icon: CheckIcon, className: TONE_SOFT.ok },
  // The quietest of the six, and the only one carrying no family colour:
  // `neutral` is the untinted pair.
  monitored: { label: 'Monitored', icon: EyeIcon, className: TONE_SOFT.neutral },
  quarantined: { label: 'Quarantined', icon: ShieldIcon, className: TONE_SOFT.critical },
};

// ACTION_META is exhaustive over FindingAction but, like the category tables
// above, reads an unvalidated persistence string at the call site: an action of
// 'constructor' resolves the Object function (truthy), so `meta.icon` is
// undefined and `<Icon />` throws "element type is invalid". Guard it the same
// way, echoing the raw action back as the label for an off-enum value.
export const actionMeta = (action: string): ActionMeta => {
  const table: Partial<Record<string, ActionMeta>> = ACTION_META;
  const meta = Object.hasOwn(ACTION_META, action) ? table[action] : undefined;
  return meta ?? { label: action, icon: KeyIcon, className: TONE_SOFT.neutral };
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

/**
 * What the User column actually asserts.
 *
 * Attribution is the principal that INGESTED the capturing event — the session
 * user, or the OWNER of the api key that posted it. For a per-developer key
 * that is the developer; for an org-level ingest key (CI, a server-side
 * producer) it is whoever minted the key, so the column names the key's owner
 * rather than whoever ran the job.
 *
 * Stated on the surface rather than only in the backend's repository docblock:
 * a header reading a bare "User" on a security dashboard is read as "the person
 * who did this", and naming someone who did not run the job is worse than
 * naming nobody.
 */
export const USER_COLUMN_TITLE =
  'Ingested by — the session user, or the owner of the api key that posted the event. An org-level ingest key names the key’s owner, not whoever ran the job.';

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

// Same guard as actionMeta, over the status table: an off-enum status (or one
// colliding with an Object.prototype member) must not resolve `.badge` as
// undefined into Badge's variant prop. 'default' is already this file's
// muted/no-opinion badge variant (see `dismissed`), so it doubles as the
// off-enum fallback rather than inventing a second one.
export const findingStatusMeta = (status: string): FindingStatusMeta => {
  const table: Partial<Record<string, FindingStatusMeta>> = FINDING_STATUS_META;
  const meta = Object.hasOwn(FINDING_STATUS_META, status) ? table[status] : undefined;
  return meta ?? { label: status, badge: 'default' };
};

/**
 * Statuses in display order — drives the Status filter. Derived from
 * FINDING_STATUS_META (an exhaustive Record over FindingStatus, so adding an
 * enum member is a compile error there and automatically appears here); the
 * literal's key order IS the display order.
 */
export const FINDING_STATUSES = Object.keys(FINDING_STATUS_META) as FindingStatus[];

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
// The view vocabulary lives in ./views.ts, which imports nothing — this module
// reaches ui-kit and the icon set, and a router that only needs the view names
// must not pay for either. Re-exported here so existing imports are unaffected.
export {
  DEFAULT_FINDINGS_VIEW,
  FINDINGS_VIEWS,
  type FindingsView,
  isFindingsView,
} from './views.ts';
// Imported as well as re-exported: a re-export does not bind the name locally,
// and this module still annotates with it below.
import type { FindingsView } from './views.ts';

/** Toggle labels, and what each view counts — the units differ per view. */
export const FINDINGS_VIEW_LABEL: Record<FindingsView, string> = {
  grouped: 'By type',
  flat: 'All findings',
  files: 'By location',
};

/** The findings drawer target: a group, optionally narrowed to one instance. */
export interface Selection {
  finding: FindingGroup;
  /** When present the drawer shows a single location; otherwise the grouped view. */
  instance?: FindingInstance;
}
