// Activity presentation layer — labels, icons and token-class tones for the
// audit-log views. Keyed off the semantic @akasecurity/schema enums; no styling lives on
// the types themselves. All colors resolve to theme.css tokens (no hardcoded hex).
import {
  type ActivityLink,
  type AuditEventKind,
  HARNESS,
  type Harness,
  type SessionStatus,
} from '@akasecurity/schema';
import { type BadgeProps, TONE_PARTS } from '@akasecurity/ui-kit';

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
  [HARNESS.ClaudeCode]: 'CLI agent',
  [HARNESS.Cursor]: 'IDE',
  [HARNESS.Copilot]: 'IDE',
  [HARNESS.Codex]: 'CLI agent',
  // Ships as both the `agy` CLI and an IDE; the CLI is the surface this
  // repo's plugin instruments (the IDE fires no plugin hooks).
  [HARNESS.Antigravity]: 'CLI agent',
  [HARNESS.Windsurf]: 'IDE',
  [HARNESS.ClaudeDesktop]: 'Desktop app',
  [HARNESS.ChatGpt]: 'Web app',
  [HARNESS.ClaudeAi]: 'Web app',
  [HARNESS.Api]: 'API',
};

// The harnesses shown in the filter, in display order. Derived from the registry
// rather than listed again, so a harness added there cannot go missing from the
// filter — but the order is then a SCHEMA file's declaration order, where
// reordering members does not read as a UI change to anyone. meta.test.ts pins
// the sequence against an explicit list for exactly that reason: the derivation
// owns membership, the test owns order, and a reorder there has to be made here
// too.
export const HARNESS_IDS: readonly Harness[] = Object.values(HARNESS);

interface EventMeta {
  label: string;
  icon: IconComponent;
  /** foreground token class, e.g. `text-primary`. */
  text: string;
  /** fill/tint token class, e.g. `bg-primary-tint`. */
  fill: string;
}

// The tonal halves are spread from the shared registry rather than spelled here:
// a pair written out at a call site is a pair that can be written out wrong, and
// the two halves belong to each other.

/** Node glyph + tone for each audit event type on the timeline. */
export const EVENT_META: Record<AuditEventKind, EventMeta> = {
  session: { label: 'Session', icon: TerminalIcon, ...TONE_PARTS.neutral },
  prompt: { label: 'Prompt', icon: UserIcon, ...TONE_PARTS.primary },
  response: { label: 'Response', icon: SparklesIcon, ...TONE_PARTS.violet },
  tool: { label: 'Tool', icon: TerminalIcon, ...TONE_PARTS.neutral },
  hook: { label: 'Hook', icon: RouteIcon, ...TONE_PARTS.low },
  detection: { label: 'Detection', icon: ShieldCheckIcon, ...TONE_PARTS.critical },
  share: { label: 'Egress', icon: ExternalShareIcon, ...TONE_PARTS.teal },
  permission: { label: 'Permission', icon: LockIcon, ...TONE_PARTS.high },
  commit: { label: 'Commit', icon: BranchIcon, ...TONE_PARTS.neutral },
  error: { label: 'Error', icon: AlertIcon, ...TONE_PARTS.critical },
  active: { label: 'In progress', icon: BoltIcon, ...TONE_PARTS.primary },
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
