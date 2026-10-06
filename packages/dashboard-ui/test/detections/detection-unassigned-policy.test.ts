import type { DetectionDetail, DetectionListItem } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';
import { DetectionsListView } from '../../src/detections/DetectionsListView.tsx';
import { policyMeta } from '../../src/detections/meta.ts';
import type { DetectionPolicyFloor } from '../../src/detections/policy-floor.ts';

// A detection with no assigned policy reads as Monitor by default. A host whose
// unassigned detections resolve to something else passes `unassignedPolicy`,
// and only the unassigned, unconstrained case changes.

const UNASSIGNED_POLICY = {
  label: 'Category policy',
  description: 'Follows the policy assigned to its category.',
};

const WARN_FLOOR: DetectionPolicyFloor = { floor: 'warn', locked: false };

const UNASSIGNED_ITEM: DetectionListItem = {
  id: 'aka/secrets',
  name: 'Secrets',
  version: '1.0.0',
  enabled: true,
  origin: 'library',
  ruleCount: 1,
  namespace: 'aka',
  packId: 'secrets',
};

const MONITOR_ITEM: DetectionListItem = { ...UNASSIGNED_ITEM, policyId: 'monitor' };
const WARN_ITEM: DetectionListItem = { ...UNASSIGNED_ITEM, policyId: 'warn' };

const UNASSIGNED_DETAIL: DetectionDetail = {
  ...UNASSIGNED_ITEM,
  editedAt: '2026-01-01T00:00:00.000Z',
  findingsLast30d: 0,
  update: null,
  modified: false,
  rules: [
    {
      id: 'secrets/example',
      name: 'Example',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'keyword', keywords: ['example'], caseSensitive: false },
    },
  ],
};

const MONITOR_DETAIL: DetectionDetail = { ...UNASSIGNED_DETAIL, policyId: 'monitor' };
const WARN_DETAIL: DetectionDetail = { ...UNASSIGNED_DETAIL, policyId: 'warn' };

function list(
  items: DetectionListItem[],
  props: Partial<Parameters<typeof DetectionsListView>[0]> = {},
): string {
  return renderToStaticMarkup(
    createElement(DetectionsListView, {
      items,
      counts: { all: items.length },
      activeId: '',
      query: '',
      filter: 'all',
      onQueryChange: () => undefined,
      onFilterChange: () => undefined,
      onSelect: () => undefined,
      ...props,
    }),
  );
}

function detail(
  d: DetectionDetail,
  props: Partial<Parameters<typeof DetectionDetailView>[0]> = {},
): string {
  return renderToStaticMarkup(
    createElement(DetectionDetailView, {
      d,
      onOpenRule: () => undefined,
      onChangePolicy: () => undefined,
      ...props,
    }),
  );
}

/** The opening tags of the picker's archetype buttons that render as pressed. */
function pressedButtons(html: string): string[] {
  return html
    .split('<button')
    .slice(1)
    .map((chunk) => chunk.slice(0, chunk.indexOf('>')))
    .filter((tag) => tag.includes('aria-pressed="true"'));
}

describe('DetectionsListView with no unassignedPolicy', () => {
  it('renders an unassigned row exactly as an explicit Monitor assignment', () => {
    const html = list([UNASSIGNED_ITEM]);
    expect(html).toBe(list([MONITOR_ITEM]));
    expect(html).toContain('>Monitor<');
  });

  it('renders byte-identically whether the prop is omitted or undefined', () => {
    expect(list([UNASSIGNED_ITEM], { unassignedPolicy: undefined })).toBe(list([UNASSIGNED_ITEM]));
  });
});

describe('DetectionsListView with an unassignedPolicy', () => {
  it('labels an unassigned row with the host label instead of Monitor', () => {
    const html = list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY });
    expect(html).toContain(`>${UNASSIGNED_POLICY.label}<`);
    expect(html).not.toContain('>Monitor<');
    // The description is detail-pane copy, not row copy.
    expect(html).not.toContain(UNASSIGNED_POLICY.description);
  });

  it('leaves an assigned row unchanged', () => {
    for (const item of [MONITOR_ITEM, WARN_ITEM]) {
      expect(list([item], { unassignedPolicy: UNASSIGNED_POLICY })).toBe(list([item]));
    }
  });

  it('lets a floor win over the host label on an unassigned row', () => {
    const floorsById = new Map([[UNASSIGNED_ITEM.id, WARN_FLOOR]]);
    const html = list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY, floorsById });
    expect(html).toBe(list([UNASSIGNED_ITEM], { floorsById }));
    expect(html).toContain(policyMeta('warn').label);
    expect(html).not.toContain(UNASSIGNED_POLICY.label);
  });
});

describe('DetectionDetailView with no unassignedPolicy', () => {
  it('renders an unassigned detection exactly as an explicit Monitor assignment', () => {
    const html = detail(UNASSIGNED_DETAIL);
    expect(html).toBe(detail(MONITOR_DETAIL));
    expect(html).toContain(policyMeta('monitor').desc);
    expect(pressedButtons(html)).toHaveLength(1);
  });

  it('renders byte-identically whether the prop is omitted or undefined', () => {
    expect(detail(UNASSIGNED_DETAIL, { unassignedPolicy: undefined })).toBe(
      detail(UNASSIGNED_DETAIL),
    );
  });
});

describe('DetectionDetailView with an unassignedPolicy', () => {
  it('describes an unassigned detection with the host copy and selects no archetype', () => {
    const html = detail(UNASSIGNED_DETAIL, { unassignedPolicy: UNASSIGNED_POLICY });
    expect(html).toContain(UNASSIGNED_POLICY.label);
    expect(html).toContain(UNASSIGNED_POLICY.description);
    expect(html).not.toContain(policyMeta('monitor').desc);
    // Positive control: the unassigned pane without the prop does press one.
    expect(pressedButtons(detail(UNASSIGNED_DETAIL))).toHaveLength(1);
    expect(pressedButtons(html)).toHaveLength(0);
    // Every archetype is still offered.
    expect(html).toContain('>Monitor<');
  });

  it('leaves an assigned detection unchanged', () => {
    for (const d of [MONITOR_DETAIL, WARN_DETAIL]) {
      expect(detail(d, { unassignedPolicy: UNASSIGNED_POLICY })).toBe(detail(d));
    }
  });

  it('lets a policyFloor win over the host copy', () => {
    const html = detail(UNASSIGNED_DETAIL, {
      unassignedPolicy: UNASSIGNED_POLICY,
      policyFloor: WARN_FLOOR,
    });
    expect(html).toBe(detail(UNASSIGNED_DETAIL, { policyFloor: WARN_FLOOR }));
    expect(html).not.toContain(UNASSIGNED_POLICY.description);
  });
});
