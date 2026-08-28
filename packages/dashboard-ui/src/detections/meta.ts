// Presentation metadata for the Detections views. The views consume the
// @akasecurity/schema contract types directly (DetectionDetail, DetectionListItem,
// DetectionRule, …); this module owns only the frontend mapping of those semantic
// enums to labels, icons, and tones — there are no domain types here.
import type {
  BuiltinPolicyId,
  DetectionCategory,
  DetectionDetail,
  Matcher,
  OriginEnum,
  PublisherKind,
} from '@akasecurity/schema';
import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import type { Tone } from '@akasecurity/ui-kit';

import type { IconComponent } from '../lib/icons.ts';
import {
  AlertIcon,
  BracesIcon,
  BuildingIcon,
  EyeIcon,
  FingerprintIcon,
  GlobeIcon,
  LockIcon,
  PolicyIcon,
  RedactIcon,
  ShieldCheckIcon,
  SlashCircleIcon,
  UserIcon,
} from '../shared/icons.tsx';

// The default policy shown when a detection has no policy assigned. Enforcement
// defaults to monitor (log-only) until the user picks another action.
export const PLACEHOLDER_POLICY = 'monitor';

/** A one-line code-ish summary of a matcher, shown on rule cards. */
export function matcherSummary(m: Matcher): string {
  if (m.type === 'regex') return '/' + m.pattern + '/' + m.flags;
  return m.keywords.join(' · ');
}

// ─── Matcher metadata ─────────────────────────────────────────────────────────

export interface MatcherMeta {
  label: string;
  icon: IconComponent;
  color: string;
  fill: string;
  blurb: string;
}

// Keyed on the union's own discriminants rather than the standalone MatcherType
// enum, so a matcher kind added to the schema arrives here as a compile error
// rather than as a missing tile at render time.
export const MATCHER_META: Record<Matcher['type'], MatcherMeta> = {
  regex: {
    label: 'Regex',
    icon: BracesIcon,
    color: 'var(--color-violet-ink)',
    fill: 'var(--color-violet-fill)',
    blurb: 'Pattern match',
  },
  keyword: {
    label: 'Keyword',
    icon: FingerprintIcon,
    color: 'var(--color-teal-ink)',
    fill: 'var(--color-teal-fill)',
    blurb: 'Literal lookup',
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

// The built-in enforcement archetypes (KNOWN_BUILTIN_IDS). Order is the picker's
// display order (least → most restrictive).
//
// Keyed by BuiltinPolicyId rather than `string`, which is what makes adding an
// archetype a COMPILE error here. It was `Record<string, …>`, so a new id
// compiled clean and rendered through policyMeta's fallback: an unlabelled gray
// pill with an EMPTY description card, on both the picker and the detail view.
// A missing entry has to fail loudly, because the failure it produces otherwise
// looks like a styling bug rather than a missing policy.
export const POLICY_META: Record<BuiltinPolicyId, PolicyMeta> = {
  monitor: {
    id: 'monitor',
    label: 'Monitor',
    icon: EyeIcon,
    tone: 'neutral',
    desc: 'Log every match for audit. The request is allowed through untouched.',
  },
  warn: {
    id: 'warn',
    label: 'Warn',
    icon: AlertIcon,
    tone: 'high',
    desc: 'Allow the request, but warn the user inline before it is sent.',
  },
  redact: {
    id: 'redact',
    label: 'Redact',
    icon: RedactIcon,
    tone: 'primary',
    desc:
      'Strip the matched value from the request and destroy it, then continue. ' +
      'What was removed cannot be recovered.',
  },
  vault: {
    id: 'vault',
    label: 'Redact & Vault',
    icon: LockIcon,
    tone: 'teal',
    desc:
      'Strip the matched value from the request and keep an encrypted, recoverable copy in ' +
      'the local vault, leaving a pointer in its place. Needs the vault consent granted under ' +
      'Settings; without it this behaves as Redact.',
  },
  block: {
    id: 'block',
    label: 'Block',
    icon: SlashCircleIcon,
    tone: 'critical',
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
  // The map is keyed by BuiltinPolicyId so a missing archetype is a compile
  // error, but the ARGUMENT is deliberately a plain string: a custom policy id
  // reaches here too, and narrowing the parameter would just move the cast to
  // every call site. Read through a widened view after the hasOwn guard.
  const table: Partial<Record<string, PolicyMeta>> = POLICY_META;
  const known = Object.hasOwn(POLICY_META, id) ? table[id] : undefined;
  return known ?? { id, label: id, icon: PolicyIcon, tone: 'neutral', desc: '' };
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
  user: { label: 'Community', icon: UserIcon, tone: 'neutral', verified: false },
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
