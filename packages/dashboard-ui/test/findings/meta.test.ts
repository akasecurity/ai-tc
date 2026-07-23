import type { FindingAction, FindingInstance, FindingStatus } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { formatConfidence } from '../../src/findings/FindingDetailView.tsx';
import {
  ACTION_META,
  CATEGORY_LABEL,
  categoryStyle,
  filterInstancesByStatus,
  FINDING_STATUSES,
  SEVERITIES,
} from '../../src/findings/meta.ts';

// Minimal FindingInstance fixture — only `id` and `status` vary per test.
function buildInstance(id: string, status?: FindingStatus): FindingInstance {
  return {
    id,
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/a.ts',
    action: 'allowed',
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 0.9,
    ...(status ? { status } : {}),
  };
}

describe('categoryStyle', () => {
  it('returns the tinted classes for a known category', () => {
    expect(categoryStyle('secret')).toBe('bg-sev-critical-fill text-sev-critical');
    expect(categoryStyle('source_code')).toBe('bg-violet-fill text-violet');
  });

  it('falls back to a neutral surface tone for an off-enum category', () => {
    expect(categoryStyle('not-a-category')).toBe('bg-surface-2 text-text-2');
  });
});

describe('ACTION_META', () => {
  it('maps every finding action to a label, icon component, and tinted className', () => {
    const actions: FindingAction[] = [
      'blocked',
      'redacted',
      'warned',
      'allowed',
      'monitored',
      'quarantined',
    ];
    for (const a of actions) {
      const m = ACTION_META[a];
      expect(m.label).toBe(a.charAt(0).toUpperCase() + a.slice(1));
      expect(typeof m.icon).toBe('function');
      expect(m.className).toMatch(/\S/);
    }
  });
});

describe('CATEGORY_LABEL / SEVERITIES / FINDING_STATUSES', () => {
  it('labels categories and orders severities critical→low', () => {
    expect(CATEGORY_LABEL.secret).toBe('Secret');
    expect(CATEGORY_LABEL.pii).toBe('PII');
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
  });

  it('orders statuses open→dismissed for the Status filter', () => {
    expect(FINDING_STATUSES).toEqual(['open', 'handled', 'resolved', 'dismissed']);
  });
});

describe('formatConfidence', () => {
  it('buckets by threshold and formats the score to two decimals', () => {
    expect(formatConfidence(0.95)).toEqual({ label: 'High · 0.95', tone: 'text-ok' });
    // Threshold boundaries are inclusive at 0.9 (High) and 0.7 (Medium).
    expect(formatConfidence(0.9)).toEqual({ label: 'High · 0.90', tone: 'text-ok' });
    expect(formatConfidence(0.89)).toEqual({ label: 'Medium · 0.89', tone: 'text-sev-high' });
    expect(formatConfidence(0.7)).toEqual({ label: 'Medium · 0.70', tone: 'text-sev-high' });
    expect(formatConfidence(0.69)).toEqual({ label: 'Low · 0.69', tone: 'text-text-2' });
    expect(formatConfidence(0)).toEqual({ label: 'Low · 0.00', tone: 'text-text-2' });
  });
});

describe('filterInstancesByStatus', () => {
  const instances: FindingInstance[] = [
    buildInstance('i-open', 'open'),
    buildInstance('i-handled', 'handled'),
    buildInstance('i-resolved', 'resolved'),
    buildInstance('i-dismissed', 'dismissed'),
    buildInstance('i-legacy'), // no status (predates the resolution feature)
  ];

  it('keeps only instances whose own status is among the selected ones', () => {
    expect(filterInstancesByStatus(instances, ['open'])).toEqual([instances[0]]);
    expect(filterInstancesByStatus(instances, ['handled'])).toEqual([instances[1]]);
  });

  it('keeps the union when several statuses are selected', () => {
    expect(filterInstancesByStatus(instances, ['open', 'resolved'])).toEqual([
      instances[0],
      instances[2],
    ]);
  });

  it('excludes a legacy instance with no status when a status is selected', () => {
    const legacyOnly = instances.filter((i) => i.id === 'i-legacy');
    expect(filterInstancesByStatus(legacyOnly, ['open'])).toEqual([]);
  });

  it('returns every instance unchanged for an empty selection', () => {
    expect(filterInstancesByStatus(instances, [])).toEqual(instances);
  });

  it('returns every instance unchanged when no status filter is given', () => {
    expect(filterInstancesByStatus(instances, undefined)).toEqual(instances);
  });

  it('never empties out a group the store already deemed visible', () => {
    // foldGroupStatus only assigns a candidate status to a group when at
    // least one instance carries it — so filtering that SAME group's
    // instances by the SAME status can never yield an empty expanded list.
    const mixed = [buildInstance('i1', 'handled'), buildInstance('i2', 'dismissed')];
    expect(filterInstancesByStatus(mixed, ['handled'])).toHaveLength(1);
  });
});
