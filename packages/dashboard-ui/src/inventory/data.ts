// Presentation descriptors for the Inventory page. The data itself (projects,
// assets, harnesses, file trees, events) is fetched from the control-plane
// inventory API (/v1/inventory/*) and typed by `@akasecurity/schema` — this module
// only holds the label/icon/colour lookups the API shapes don't carry, plus a
// couple of pure-presentation helpers. No dummy data, no view-model types that
// duplicate a schema shape.
import type {
  AccessLevel,
  AssetType,
  Flag,
  HarnessEventKind,
  Origin,
  TrustLevel,
  Visibility,
} from '@akasecurity/schema';
import type { BadgeProps } from '@akasecurity/ui-kit';

import type { IconName } from './icons.ts';

type Tone = NonNullable<BadgeProps['variant']>;

// ─── Access (per-file LLM access) ────────────────────────────────────────────
export interface AccessMeta {
  label: string;
  icon: IconName;
  fg: string;
  bg: string;
  bar: string;
  desc: string;
}
export const ACCESS: Record<AccessLevel, AccessMeta> = {
  open: {
    label: 'Any LLM',
    icon: 'cloud',
    fg: 'text-ok',
    bg: 'bg-ok-fill',
    bar: 'bg-ok',
    desc: 'Allowed to any model — including public, consumer LLMs.',
  },
  approved: {
    label: 'Approved only',
    icon: 'shield-check',
    fg: 'text-primary',
    bg: 'bg-primary-tint',
    bar: 'bg-primary',
    desc: 'Allowed only to approved, governed models.',
  },
  blocked: {
    label: 'No LLM',
    icon: 'slash-circle',
    fg: 'text-sev-critical',
    bg: 'bg-sev-critical-fill',
    bar: 'bg-sev-critical',
    desc: 'Never sent to any model. Blocked at the proxy.',
  },
};
export const ACCESS_ORDER: AccessLevel[] = ['open', 'approved', 'blocked'];

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
    fg: 'text-ok',
    bg: 'bg-ok-fill',
    iconBg: 'bg-ok',
    desc: 'Reviewed & allow-listed. Agents may call it freely.',
  },
  risky: {
    label: 'Risky',
    icon: 'alert',
    tone: 'high',
    fg: 'text-sev-high',
    bg: 'bg-sev-high-fill',
    iconBg: 'bg-sev-high',
    desc: 'Allowed, but reaches sensitive systems or external hosts. Use with care.',
  },
  unapproved: {
    label: 'Unapproved',
    icon: 'x-circle',
    tone: 'critical',
    fg: 'text-sev-critical',
    bg: 'bg-sev-critical-fill',
    iconBg: 'bg-sev-critical',
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
/**
 * Severity-ish priority order used when rolling flags up into chips. Excludes
 * the project-only `findings` flag, which is surfaced separately (projects don't
 * carry the generic asset flags).
 */
export const FLAG_ORDER: Flag[] = [
  'risk',
  'conflict',
  'unknown',
  'change',
  'untracked',
  'update',
  'stale',
];

// ─── File origin ──────────────────────────────────────────────────────────────
export interface OriginMeta {
  short: string;
  label: string;
  icon: IconName;
}
export const originMeta: Record<Origin, OriginMeta> = {
  source: { short: 'Source', label: 'First-party source code', icon: 'code' },
  'public-dep': { short: 'Public dep', label: 'Public dependency · open source', icon: 'cloud' },
  vendored: { short: 'Vendored', label: 'Vendored third-party', icon: 'layers' },
  config: { short: 'Config', label: 'Configuration', icon: 'settings' },
  data: { short: 'Data', label: 'Data · fixtures', icon: 'database' },
  docs: { short: 'Docs', label: 'Documentation', icon: 'book' },
  generated: { short: 'Generated', label: 'Generated artifact', icon: 'bolt' },
};

// ─── Asset-type presentation (icon · colours · label) ─────────────────────────
export interface TypeMeta {
  type: AssetType;
  label: string;
  icon: IconName;
  fg: string;
  bg: string;
}
export const PROJECT_GROUP: TypeMeta = {
  type: 'project',
  label: 'Projects',
  icon: 'repo',
  fg: 'text-primary',
  bg: 'bg-primary-tint',
};
/** Single source of per-asset-type presentation (label · icon · colors). */
export const ASSET_META = {
  skill: {
    type: 'skill',
    label: 'Skills',
    icon: 'sparkles',
    fg: 'text-violet',
    bg: 'bg-violet-fill',
  },
  mcp: { type: 'mcp', label: 'MCP servers', icon: 'server', fg: 'text-teal', bg: 'bg-teal-fill' },
  hook: { type: 'hook', label: 'Hooks', icon: 'route', fg: 'text-sev-low', bg: 'bg-sev-low-fill' },
  config: {
    type: 'config',
    label: 'Configuration',
    icon: 'sliders',
    fg: 'text-teal',
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
/** Icon + colours for an asset tile — the API's AssetSummary carries no presentation. */
export const assetTile = (type: AssetType): { icon: IconName; fg: string; bg: string } => {
  const { icon, fg, bg } = type === 'project' ? PROJECT_GROUP : ASSET_META[type];
  return { icon, fg, bg };
};

// ─── Date formatting ──────────────────────────────────────────────────────────
/**
 * Compact local datetime for inventory captions (file drawer "Last activity",
 * blocked-strip "blocked …"). The API returns ISO timestamps, not relative
 * strings, so both call sites format them the same way through here.
 */
export function fmtDateTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
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
    fg: 'text-sev-critical',
    bg: 'bg-sev-critical-fill',
  },
  redact: { label: 'Redacted', icon: 'redact', tone: 'teal', fg: 'text-teal', bg: 'bg-teal-fill' },
  warn: {
    label: 'Warned',
    icon: 'alert',
    tone: 'high',
    fg: 'text-sev-high',
    bg: 'bg-sev-high-fill',
  },
};

// ─── Language dot colour ──────────────────────────────────────────────────────
// ProjectSummary carries `language` as a bare string; the little colour dot is
// pure presentation, so map the common languages here (GitHub-linguist-ish),
// with a neutral fallback for anything unknown.
const LANG_COLORS: Record<string, string> = {
  typescript: '#3178C6',
  javascript: '#F1E05A',
  rust: '#DEA584',
  python: '#3572A5',
  go: '#00ADD8',
  ruby: '#701516',
  java: '#B07219',
  hcl: '#844FBA',
  jupyter: '#DA5B0B',
  'jupyter notebook': '#DA5B0B',
  mdx: '#1B1F24',
  markdown: '#083FA1',
  shell: '#89E051',
  c: '#555555',
  'c++': '#F34B7D',
  'c#': '#178600',
  php: '#4F5D95',
  swift: '#F05138',
  kotlin: '#A97BFF',
};
export function langColor(language: string): string {
  return LANG_COLORS[language.toLowerCase()] ?? 'var(--color-border-strong)';
}

// ─── Flag rollups (used by the by-type group headers) ─────────────────────────
export interface FlagRollup {
  key: Flag;
  count: number;
}
/** Count flags across a set of items, ordered by {@link FLAG_ORDER} severity. */
export function rollup(items: { flags: Flag[] }[]): FlagRollup[] {
  const counts: Partial<Record<Flag, number>> = {};
  items.forEach((it) => {
    it.flags.forEach((fl) => {
      counts[fl] = (counts[fl] ?? 0) + 1;
    });
  });
  return FLAG_ORDER.filter((k) => counts[k]).map((k) => ({ key: k, count: counts[k] ?? 0 }));
}

// ─── UI state ─────────────────────────────────────────────────────────────────
/** What's selected in the left navigator / shown in the right pane. */
export type Selection =
  | { type: 'project'; id: string }
  | { type: 'harness'; id: string }
  | { type: Exclude<AssetType, 'project'>; id: string };

/** The minimal shape resolveInventorySelection needs from each nav dataset. */
export interface InventoryNavData {
  harnesses: { id: string; categories: { assets: { id: string }[] }[] }[];
  projects: { id: string }[];
  assetGroups: { type: AssetType; items: { id: string }[] }[];
}

/**
 * Resolve the active inventory selection: honor a still-present URL selection,
 * else default to the first harness → project → asset that exists. Returns null
 * only when the inventory is empty. Shared by every Inventory
 * page so the "what's valid / default order" semantics can't fork between them.
 */
export function resolveInventorySelection(
  requested: Selection | null,
  data: InventoryNavData,
): Selection | null {
  const assetPresent = (id: string): boolean =>
    data.assetGroups.some((g) => g.items.some((it) => it.id === id)) ||
    data.harnesses.some((h) => h.categories.some((c) => c.assets.some((it) => it.id === id)));
  const selValid =
    requested != null &&
    (requested.type === 'harness'
      ? data.harnesses.some((h) => h.id === requested.id)
      : requested.type === 'project'
        ? data.projects.some((p) => p.id === requested.id)
        : assetPresent(requested.id));
  if (selValid) return requested;

  const h = data.harnesses[0];
  if (h) return { type: 'harness', id: h.id };
  const p = data.projects[0];
  if (p) return { type: 'project', id: p.id };
  for (const g of data.assetGroups) {
    const first = g.items[0];
    if (g.type !== 'project' && first) return { type: g.type, id: first.id };
  }
  return null;
}

/** Human-readable "why this file's default LLM access is what it is" copy. */
export function rationale(
  proj: { visibility: Visibility; policyDefault: AccessLevel },
  origin: Origin,
): string {
  if (proj.visibility === 'public')
    return 'Public repository — every file is allowed to any LLM by default.';
  if (origin === 'public-dep')
    return 'Public, open-source dependency — allowed to any LLM by default, even inside a private repo.';
  const dflt = proj.policyDefault === 'blocked' ? 'No LLM' : 'Approved only';
  return `Private repository. First-party files default to “${dflt}”. Adjust per file as needed.`;
}
