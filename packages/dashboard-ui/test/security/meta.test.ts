import type { EnforcementActionKind, Severity, SeveritySummaryItem } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { ENFORCEMENT_META, SEVERITY_META } from '../../src/security/meta.ts';
import { hasResolutionData } from '../../src/security/SeverityCardView.tsx';

// Count-only bySeverity fixture (no caught/openAtRest) — the shape a
// not-yet-updated feeder returns today.
function countOnlyItem(severity: Severity, count: number): SeveritySummaryItem {
  return { severity, count };
}

describe('SEVERITY_META', () => {
  it('labels every severity and assigns a non-empty color', () => {
    const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
    for (const s of severities) {
      const m = SEVERITY_META[s];
      expect(m.label).toBe(s.charAt(0).toUpperCase() + s.slice(1));
      expect(m.color).toMatch(/\S/);
    }
  });
});

describe('ENFORCEMENT_META', () => {
  it('maps every enforcement kind to a label, icon component, and non-empty color', () => {
    const kinds: EnforcementActionKind[] = ['blocked', 'redacted', 'warned'];
    for (const k of kinds) {
      const m = ENFORCEMENT_META[k];
      expect(m.label).toBe(k.charAt(0).toUpperCase() + k.slice(1));
      expect(typeof m.icon).toBe('function');
      expect(m.color).toMatch(/\S/);
    }
  });
});

describe('hasResolutionData', () => {
  it('is false for the legacy count-only shape (no per-severity caught/openAtRest)', () => {
    expect(
      hasResolutionData({
        bySeverity: [countOnlyItem('critical', 3), countOnlyItem('high', 1)],
      }),
    ).toBe(false);
  });

  it('is false for a count-only feeder even when the caller coerces needsRemediation to 0', () => {
    // Mimics a count-only feeder's output: bySeverity carries no
    // caught/openAtRest, and a top-level
    // needsRemediation of 0 must NOT count as resolution data — detection keys
    // off the per-severity fields, which the coerced-0 doesn't fabricate. This
    // is the live surface the fallback must protect.
    expect(hasResolutionData({ bySeverity: [countOnlyItem('high', 5)] })).toBe(false);
  });

  it('is true when a bySeverity item carries a defined caught count, even at 0', () => {
    const withCaught: SeveritySummaryItem = { severity: 'critical', count: 5, caught: 0 };
    expect(hasResolutionData({ bySeverity: [withCaught] })).toBe(true);
  });

  it('is true when a bySeverity item carries a defined openAtRest count', () => {
    const withOpenAtRest: SeveritySummaryItem = { severity: 'high', count: 2, openAtRest: 2 };
    expect(hasResolutionData({ bySeverity: [withOpenAtRest] })).toBe(true);
  });

  it('is false for an empty bySeverity list', () => {
    expect(hasResolutionData({ bySeverity: [] })).toBe(false);
  });
});
