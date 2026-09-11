import type { EnforcementActionKind, Severity } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { ENFORCEMENT_META, SEVERITY_META } from '../../src/security/meta.ts';

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
