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

// Tailwind classes for a severity-tinted icon tile (fill + foreground).
export const SEVERITY_TILE: Record<Severity, string> = {
  critical: 'bg-sev-critical-fill text-sev-critical',
  high: 'bg-sev-high-fill text-sev-high',
  medium: 'bg-sev-medium-fill text-sev-medium',
  low: 'bg-sev-low-fill text-sev-low',
};

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
