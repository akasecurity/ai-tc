// Activity presentation layer — labels, icons and token-class tones for the
// audit-log views. Keyed off the semantic @akasecurity/schema enums; no styling lives on
// the types themselves. All colors resolve to theme.css tokens (no hardcoded hex).
import type { ActivityLink, AuditEventKind, Harness, SessionStatus } from '@akasecurity/schema';
import type { BadgeProps } from '@akasecurity/ui-kit';

import type { IconComponent } from '../lib/icons.ts';
import {
  AlertIcon,
  BoltIcon,
  BranchIcon,
  EditIcon,
  ExternalShareIcon,
  FileIcon,
  GlobeIcon,
  LockIcon,
  RouteIcon,
  SearchIcon,
  ShieldCheckIcon,
  SparklesIcon,
  TerminalIcon,
  UserIcon,
} from '../shared/icons.tsx';

/** The one bit the shared PROVIDERS lettermark map lacks — how a harness runs. */
export const HARNESS_KIND: Record<Harness, string> = {
  claudecode: 'CLI agent',
  cursor: 'IDE',
  copilot: 'IDE',
  codex: 'CLI agent',
  windsurf: 'IDE',
  claudedesktop: 'Desktop app',
  chatgpt: 'Web app',
  api: 'API',
};

/** The harnesses shown in the filter, in display order. */
export const HARNESS_IDS: Harness[] = [
  'claudecode',
  'cursor',
  'copilot',
  'codex',
  'windsurf',
  'claudedesktop',
  'chatgpt',
  'api',
];

interface EventMeta {
  label: string;
  icon: IconComponent;
  /** foreground token class, e.g. `text-primary`. */
  text: string;
  /** fill/tint token class, e.g. `bg-primary-tint`. */
  fill: string;
}

/** Node glyph + tone for each audit event type on the timeline. */
export const EVENT_META: Record<AuditEventKind, EventMeta> = {
  session: { label: 'Session', icon: TerminalIcon, text: 'text-text-2', fill: 'bg-surface-3' },
  prompt: { label: 'Prompt', icon: UserIcon, text: 'text-primary', fill: 'bg-primary-tint' },
  response: { label: 'Response', icon: SparklesIcon, text: 'text-violet', fill: 'bg-violet-fill' },
  tool: { label: 'Tool', icon: TerminalIcon, text: 'text-text-2', fill: 'bg-surface-3' },
  hook: { label: 'Hook', icon: RouteIcon, text: 'text-sev-low', fill: 'bg-sev-low-fill' },
  detection: {
    label: 'Detection',
    icon: ShieldCheckIcon,
    text: 'text-sev-critical',
    fill: 'bg-sev-critical-fill',
  },
  share: { label: 'Egress', icon: ExternalShareIcon, text: 'text-teal', fill: 'bg-teal-fill' },
  permission: {
    label: 'Permission',
    icon: LockIcon,
    text: 'text-sev-high',
    fill: 'bg-sev-high-fill',
  },
  commit: { label: 'Commit', icon: BranchIcon, text: 'text-text-2', fill: 'bg-surface-3' },
  error: {
    label: 'Error',
    icon: AlertIcon,
    text: 'text-sev-critical',
    fill: 'bg-sev-critical-fill',
  },
  active: { label: 'In progress', icon: BoltIcon, text: 'text-primary', fill: 'bg-primary-tint' },
};

// Per-tool glyphs for `tool` events and the tool-call chips. Index this directly
// with a fallback at the call site (`TOOL_META[name] ?? TOOL_ICON_FALLBACK`) so the
// resolved component keeps a stable identity across renders.
export const TOOL_META: Record<string, IconComponent | undefined> = {
  Bash: TerminalIcon,
  Edit: EditIcon,
  Write: EditIcon,
  Read: FileIcon,
  Grep: SearchIcon,
  WebFetch: GlobeIcon,
  Task: RouteIcon,
};

/** Glyph for an unknown tool. */
export const TOOL_ICON_FALLBACK: IconComponent = TerminalIcon;

type BadgeVariant = NonNullable<BadgeProps['variant']>;

interface StatusMeta {
  label: string;
  badge: BadgeVariant;
  /** dot fill token class. */
  dot: string;
}

/** Status pill styling. `active` renders a pulsing live dot (see StatusDot). */
export const STATUS_META: Record<SessionStatus, StatusMeta> = {
  active: { label: 'Live', badge: 'success', dot: 'bg-ok' },
  completed: { label: 'Completed', badge: 'default', dot: 'bg-text-3' },
  interrupted: { label: 'Interrupted', badge: 'high', dot: 'bg-sev-high' },
  error: { label: 'Error', badge: 'critical', dot: 'bg-sev-critical' },
};

/** Label for the deep-link on cross-referencing events. */
export const LINK_LABEL: Record<ActivityLink, string> = {
  detections: 'Findings',
  shares: 'Data Shares',
  inventory: 'Inventory',
};

/** Tool-call counts as a list, sorted most-used first. */
export function toolEntries(tools: Record<string, number>): { name: string; n: number }[] {
  return Object.entries(tools)
    .map(([name, n]) => ({ name, n }))
    .sort((a, b) => b.n - a.n);
}

/** Total tool calls in a session. */
export function toolTotal(tools: Record<string, number>): number {
  return Object.values(tools).reduce((sum, n) => sum + n, 0);
}
