// Presentation metadata for the Detections views. The views consume the
// @akasecurity/schema contract types directly (DetectionDetail, DetectionListItem,
// DetectionRule, …); this module owns only the frontend mapping of those semantic
// enums to labels, icons, and tones — there are no domain types here.
import type {
  DetectionCategory,
  DetectionDetail,
  Matcher,
  MatcherType,
  OriginEnum,
  PublisherKind,
} from '@akasecurity/schema';
import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';

import type { IconComponent } from '../lib/icons.ts';
import {
  AlertIcon,
  BracesIcon,
  BuildingIcon,
  EyeIcon,
  FingerprintIcon,
  GlobeIcon,
  PolicyIcon,
  RedactIcon,
  ShieldCheckIcon,
  SlashCircleIcon,
  SparklesIcon,
  UserIcon,
} from '../shared/icons.tsx';

// The default policy shown when a detection has no policy assigned. Enforcement
// defaults to monitor (log-only) until the user picks another action.
export const PLACEHOLDER_POLICY = 'monitor';

export type Tone = 'gray' | 'orange' | 'primary' | 'red' | 'violet' | 'teal' | 'green' | 'blue';

/** Maps a semantic tone to a [foreground, background] pair of theme-token CSS vars. */
export function toneColors(tone: Tone): [string, string] {
  const map: Record<Tone, [string, string]> = {
    primary: ['var(--color-primary)', 'var(--color-primary-tint)'],
    teal: ['var(--color-teal)', 'var(--color-teal-fill)'],
    green: ['var(--color-ok)', 'var(--color-ok-fill)'],
    red: ['var(--color-sev-critical)', 'var(--color-sev-critical-fill)'],
    orange: ['var(--color-sev-high)', 'var(--color-sev-high-fill)'],
    gray: ['var(--color-text-2)', 'var(--color-surface-3)'],
    blue: ['var(--color-sev-low)', 'var(--color-sev-low-fill)'],
    violet: ['var(--color-violet)', 'var(--color-violet-fill)'],
  };
  return map[tone];
}

/** A one-line code-ish summary of a matcher, shown on rule cards. */
export function matcherSummary(m: Matcher): string {
  if (m.type === 'regex') return '/' + m.pattern + '/' + m.flags;
  if (m.type === 'keyword') return m.keywords.join(' · ');
  return m.name;
}

// ─── Matcher metadata ─────────────────────────────────────────────────────────

export interface MatcherMeta {
  label: string;
  icon: IconComponent;
  color: string;
  fill: string;
  blurb: string;
}

export const MATCHER_META: Record<MatcherType, MatcherMeta> = {
  regex: {
    label: 'Regex',
    icon: BracesIcon,
    color: 'var(--color-violet)',
    fill: 'var(--color-violet-fill)',
    blurb: 'Pattern match',
  },
  keyword: {
    label: 'Keyword',
    icon: FingerprintIcon,
    color: 'var(--color-teal)',
    fill: 'var(--color-teal-fill)',
    blurb: 'Literal lookup',
  },
  validator: {
    label: 'Validator',
    icon: SparklesIcon,
    color: 'var(--color-primary)',
    fill: 'var(--color-primary-tint)',
    blurb: 'Checksum / entropy',
  },
};

// ─── Policy metadata ──────────────────────────────────────────────────────────

export interface PolicyMeta {
  id: string;
  label: string;
  icon: IconComponent;
  tone: Tone;
  desc: string;
}

// The four built-in enforcement actions (KNOWN_BUILTIN_IDS). Order is the picker's
// display order (least → most restrictive).
export const POLICY_META: Record<string, PolicyMeta> = {
  monitor: {
    id: 'monitor',
    label: 'Monitor',
    icon: EyeIcon,
    tone: 'gray',
    desc: 'Log every match for audit. The request is allowed through untouched.',
  },
  warn: {
    id: 'warn',
    label: 'Warn',
    icon: AlertIcon,
    tone: 'orange',
    desc: 'Allow the request, but warn the user inline before it is sent.',
  },
  redact: {
    id: 'redact',
    label: 'Redact',
    icon: RedactIcon,
    tone: 'primary',
    desc: 'Automatically strip the matched value from the request, then continue.',
  },
  block: {
    id: 'block',
    label: 'Block',
    icon: SlashCircleIcon,
    tone: 'red',
    desc: 'Refuse the request entirely whenever any rule in this detection matches.',
  },
};

// The built-in policy ids in display order (least → most restrictive) — the
// picker's segmented control. Sourced from the schema's canonical enum so the
// UI and the persistence write facade share one list.
export const BUILTIN_POLICY_IDS: readonly string[] = KNOWN_BUILTIN_IDS;

// Resolve a policy id to its presentation metadata, falling back to a neutral
// pill for an unknown id (e.g. a custom policy not modelled here). Object.hasOwn
// guards the lookup: a custom id that collides with an Object.prototype member
// ('constructor', 'toString', …) must NOT resolve the inherited function — that
// yields an undefined tone and crashes toneColors on the whole page. The fallback
// uses the distinct neutral PolicyIcon (never Monitor's EyeIcon), so a custom
// policy can't be misread as the log-only Monitor builtin.
export function policyMeta(id: string): PolicyMeta {
  const known = Object.hasOwn(POLICY_META, id) ? POLICY_META[id] : undefined;
  return known ?? { id, label: id, icon: PolicyIcon, tone: 'gray', desc: '' };
}

// ─── Category metadata ────────────────────────────────────────────────────────

export const CATEGORY_LABEL: Record<DetectionCategory, string> = {
  pii: 'PII',
  financial: 'Financial',
  secret: 'Secret',
  phi: 'PHI',
  code_context: 'Code context',
  code_flaw: 'Code flaw',
  custom: 'Custom',
  config: 'Configuration',
};

// ─── Origin metadata ──────────────────────────────────────────────────────────

export interface OriginMeta {
  label: string;
  icon: IconComponent;
  tone: Tone;
  blurb: string;
}

export const ORIGIN_META: Record<OriginEnum, OriginMeta> = {
  library: {
    label: 'Library',
    icon: GlobeIcon,
    tone: 'teal',
    blurb: 'Imported from the public library',
  },
};

// ─── Publisher metadata ───────────────────────────────────────────────────────

export interface PublisherMeta {
  label: string;
  icon: IconComponent;
  tone: Tone;
  verified: boolean;
}

export const PUBLISHER_META: Record<PublisherKind, PublisherMeta> = {
  labs: { label: 'AKA Labs', icon: ShieldCheckIcon, tone: 'teal', verified: true },
  org: { label: 'Your org', icon: BuildingIcon, tone: 'violet', verified: false },
  user: { label: 'Community', icon: UserIcon, tone: 'gray', verified: false },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

// The provenance block's three honest states. The store distinguishes them
// (persistence returns update: null ONLY when no mirror row exists — nothing
// has recorded what the running binaries ship); rendering must never
// conflate `unknown` with `up-to-date`, which would hide the update feature
// from any machine where only the dashboard had run.
export type ProvenanceState = 'update-available' | 'up-to-date' | 'unknown';

export function provenanceState(d: Pick<DetectionDetail, 'update'>): ProvenanceState {
  if (d.update == null) return 'unknown';
  return d.update.available ? 'update-available' : 'up-to-date';
}
