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

// The channel that tells two severity series apart WITHOUT colour, as an SVG
// `stroke-dasharray`. The four hues above are mutually indistinguishable by
// luminance — every one of the six pairs measures under the 3:1 that WCAG 2.2
// 1.4.11 asks of non-text contrast (1.03:1 to 2.47:1 in light, 1.10:1 to
// 1.64:1 in dark, worst pair critical/low) — so a line's identity cannot rest
// on its hue. Dash geometry is theme-independent, which is why it is the
// channel here: it does not have to be re-tuned per theme the way a hue does.
//
// `critical` is solid on purpose. One series has to be the unbroken one for
// the other three to read as departures from it, and the most urgent series is
// the one that should not be visually interrupted.
//
// Every cycle also fits inside the 16px the legend and tooltip chips are wide,
// so a chip draws the whole rhythm instead of a clipped prefix of it. A chip is
// only useful if it is recognisably the SAME pattern as the line it stands for,
// and a cycle wider than the chip loses whatever falls past the edge — which is
// the trailing gap, the part that makes a dash-dot read as a dash-dot.
export const SEVERITY_DASH: Record<Severity, string | undefined> = {
  critical: undefined,
  high: '7 3',
  medium: '2 3',
  low: '9 3 2 2',
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
