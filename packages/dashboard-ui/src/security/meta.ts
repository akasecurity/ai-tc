// Presentational lookups for the security widget views. API responses are
// SEMANTIC (enums only — no colors/icons/labels); the view layer owns the mapping.
// Lives in @akasecurity/dashboard-ui so every consuming app renders
// the same severity/enforcement styling. (The display ORDER + zero-fill
// normalization stay in the apps, next to the data fetch.)
import type { EnforcementActionKind, Severity } from '@akasecurity/schema';

import { COLORS } from '../lib/colors.ts';
import type { IconComponent } from '../lib/icons.ts';
import { AlertOctagonIcon, RedactIcon, SlashCircleIcon } from '../shared/icons.tsx';

export const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: COLORS.sevCritical },
  high: { label: 'High', color: COLORS.sevHigh },
  medium: { label: 'Medium', color: COLORS.sevMedium },
  low: { label: 'Low', color: COLORS.sevLow },
};

// A severity-tinted icon tile needs no lookup of its own: every Severity member
// is also a tonal family name, so `TONE_SOFT[severity]` at the call site IS the
// mapping.

// `icon` is a concrete component (resolved here, not a string name), so the view
// renders it directly and a missing mapping is a compile error.
export const ENFORCEMENT_META: Record<
  EnforcementActionKind,
  { label: string; icon: IconComponent; color: string }
> = {
  blocked: { label: 'Blocked', icon: SlashCircleIcon, color: COLORS.sevCritical },
  redacted: { label: 'Redacted', icon: RedactIcon, color: COLORS.primary },
  warned: { label: 'Warned', icon: AlertOctagonIcon, color: COLORS.sevHigh },
};
