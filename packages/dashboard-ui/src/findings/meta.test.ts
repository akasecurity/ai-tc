import type {
  FindingAction,
  FindingGroup,
  FindingInstance,
  FindingStatus,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { formatConfidence } from './FindingDetailView.tsx';
import {
  ACTION_META,
  CATEGORY_LABEL,
  categoryStyle,
  filterGroupsByStatus,
  filterInstancesByStatus,
  SEVERITIES,
} from './meta.ts';

// Minimal FindingGroup fixture — only `id` and `status` vary per test; the rest
// are placeholder values satisfying the required shape.
function buildGroup(id: string, status?: FindingStatus): FindingGroup {
  return {
    id,
    category: 'secret',
    subtype: 'aws-key',
    severity: 'high',
    match: { maskedValue: '****', contextPrefix: '' },
    detection: { id: 'aws-key', name: null },
    policy: { id: 'category:secret', name: 'secret' },
    instanceCount: 1,
    providers: ['api'],
    aggregateAction: 'allowed',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    instances: [],
    ...(status ? { status } : {}),
  };
}

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

describe('CATEGORY_LABEL / SEVERITIES', () => {
  it('labels categories and orders severities critical→low', () => {
    expect(CATEGORY_LABEL.secret).toBe('Secret');
    expect(CATEGORY_LABEL.pii).toBe('PII');
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
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

describe('filterGroupsByStatus', () => {
  const groups: FindingGroup[] = [
    buildGroup('g-open', 'open'),
    buildGroup('g-handled', 'handled'),
    buildGroup('g-resolved', 'resolved'),
    buildGroup('g-dismissed', 'dismissed'),
    buildGroup('g-legacy'), // no status (predates the resolution feature)
  ];

  it('keeps only groups whose derived status matches the given status', () => {
    expect(filterGroupsByStatus(groups, 'open')).toEqual([groups[0]]);
    expect(filterGroupsByStatus(groups, 'resolved')).toEqual([groups[2]]);
  });

  it('excludes a legacy group with no status when filtering by a specific status', () => {
    const legacyOnly = groups.filter((g) => g.id === 'g-legacy');
    expect(filterGroupsByStatus(legacyOnly, 'open')).toEqual([]);
  });

  it('returns every group unchanged for "all"', () => {
    expect(filterGroupsByStatus(groups, 'all')).toEqual(groups);
  });

  it('returns every group unchanged when no status filter is given', () => {
    expect(filterGroupsByStatus(groups, undefined)).toEqual(groups);
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

  it('keeps only instances whose own status matches the given status', () => {
    expect(filterInstancesByStatus(instances, 'open')).toEqual([instances[0]]);
    expect(filterInstancesByStatus(instances, 'handled')).toEqual([instances[1]]);
  });

  it('excludes a legacy instance with no status when filtering by a specific status', () => {
    const legacyOnly = instances.filter((i) => i.id === 'i-legacy');
    expect(filterInstancesByStatus(legacyOnly, 'open')).toEqual([]);
  });

  it('returns every instance unchanged for "all"', () => {
    expect(filterInstancesByStatus(instances, 'all')).toEqual(instances);
  });

  it('returns every instance unchanged when no status filter is given', () => {
    expect(filterInstancesByStatus(instances, undefined)).toEqual(instances);
  });

  it('never empties out a group that filterGroupsByStatus already deemed visible', () => {
    // deriveGroupStatus only assigns a candidate status to a group when at
    // least one instance carries it — so filtering that SAME group's
    // instances by the SAME status can never yield an empty expanded list.
    const mixed = [buildInstance('i1', 'handled'), buildInstance('i2', 'dismissed')];
    expect(filterInstancesByStatus(mixed, 'handled')).toHaveLength(1);
  });
});
