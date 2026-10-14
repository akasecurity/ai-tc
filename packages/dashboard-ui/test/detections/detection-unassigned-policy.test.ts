import type { DetectionDetail, DetectionListItem } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';
import { DetectionsListView } from '../../src/detections/DetectionsListView.tsx';
import { policyMeta } from '../../src/detections/meta.ts';
import { type DetectionPolicyFloor, policyFloorReason } from '../../src/detections/policy-floor.ts';

// A detection with no assigned policy reads as Monitor by default. A host whose
// unassigned detections resolve to something else passes `unassignedPolicy`,
// and only the unassigned, unconstrained case changes.

const UNASSIGNED_POLICY = {
  label: 'Category policy',
  description: 'Follows the policy assigned to its category.',
};

// An unlocked floor is a minimum the host policy is raised to, not a value, so
// it does not say what an unassigned detection runs at. A locked floor does.
const MONITOR_FLOOR: DetectionPolicyFloor = { floor: 'monitor', locked: false };
const WARN_FLOOR: DetectionPolicyFloor = { floor: 'warn', locked: false };
const LOCKED_WARN_FLOOR: DetectionPolicyFloor = { floor: 'warn', locked: true };

const REFUSAL = 'You cannot change detections in this workspace.';

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

// A host mapping an API or database row straight across can hand over `null`
// for unassigned, which the type does not admit but `??` already treats as such.
const NULL_ITEM = { ...UNASSIGNED_ITEM, policyId: null } as unknown as DetectionListItem;
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

const NULL_DETAIL = { ...UNASSIGNED_DETAIL, policyId: null } as unknown as DetectionDetail;
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

/** The opening tag of the picker's unassigned option, if it rendered. */
function unassignedOption(html: string): string | undefined {
  return html
    .split('<button')
    .slice(1)
    .map((chunk) => chunk.slice(0, chunk.indexOf('>')))
    .find((tag) => tag.includes('data-slot="policy-unassigned-option"'));
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

  it('renders a null policyId as Monitor, the same as an absent one', () => {
    expect(list([NULL_ITEM])).toBe(list([MONITOR_ITEM]));
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

  it('labels a row whose policyId is null with the host label', () => {
    const html = list([NULL_ITEM], { unassignedPolicy: UNASSIGNED_POLICY });
    expect(html).toBe(list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY }));
    expect(html).not.toContain('>Monitor<');
  });

  it('keeps the host label under an unlocked floor', () => {
    for (const floor of [MONITOR_FLOOR, WARN_FLOOR]) {
      const floorsById = new Map([[UNASSIGNED_ITEM.id, floor]]);
      const html = list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY, floorsById });
      expect(html, floor.floor).toContain(`>${UNASSIGNED_POLICY.label}<`);
      expect(html, floor.floor).not.toContain(`>${policyMeta(floor.floor).label}<`);
    }
  });

  it('lets a locked floor win over the host label on an unassigned row', () => {
    const floorsById = new Map([[UNASSIGNED_ITEM.id, LOCKED_WARN_FLOOR]]);
    const html = list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY, floorsById });
    expect(html).toBe(list([UNASSIGNED_ITEM], { floorsById }));
    expect(html).toContain(policyMeta('warn').label);
    expect(html).not.toContain(UNASSIGNED_POLICY.label);
  });

  it('tells an unassigned row apart from a custom policy of the same name', () => {
    const custom: DetectionListItem = { ...UNASSIGNED_ITEM, policyId: UNASSIGNED_POLICY.label };
    const unassigned = list([UNASSIGNED_ITEM], { unassignedPolicy: UNASSIGNED_POLICY });
    // Positive control: both rows carry the same text.
    expect(list([custom])).toContain(`>${UNASSIGNED_POLICY.label}<`);
    expect(unassigned).not.toBe(list([custom]));
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

  it('renders a null policyId as Monitor, the same as an absent one', () => {
    expect(detail(NULL_DETAIL)).toBe(detail(MONITOR_DETAIL));
  });

  it('offers no unassigned option, even when the host wires onUnassignPolicy', () => {
    const html = detail(UNASSIGNED_DETAIL, { onUnassignPolicy: () => undefined });
    expect(html).toBe(detail(UNASSIGNED_DETAIL));
    expect(unassignedOption(html)).toBeUndefined();
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

  it('describes a detection whose policyId is null with the host copy', () => {
    const html = detail(NULL_DETAIL, { unassignedPolicy: UNASSIGNED_POLICY });
    expect(html).toBe(detail(UNASSIGNED_DETAIL, { unassignedPolicy: UNASSIGNED_POLICY }));
    expect(pressedButtons(html)).toHaveLength(0);
  });

  it('keeps the host copy under an unlocked Monitor floor, which restricts nothing', () => {
    const html = detail(UNASSIGNED_DETAIL, {
      unassignedPolicy: UNASSIGNED_POLICY,
      policyFloor: MONITOR_FLOOR,
    });
    expect(html).toContain(UNASSIGNED_POLICY.description);
    expect(html).not.toContain(policyMeta('monitor').desc);
    expect(pressedButtons(html)).toHaveLength(0);
  });

  it('keeps the host copy under an unlocked Warn floor, beside the floor reason', () => {
    const html = detail(UNASSIGNED_DETAIL, {
      unassignedPolicy: UNASSIGNED_POLICY,
      policyFloor: WARN_FLOOR,
    });
    expect(html).toContain(UNASSIGNED_POLICY.description);
    expect(html).not.toContain(policyMeta('warn').desc);
    expect(pressedButtons(html)).toHaveLength(0);
    // The picker still says what the floor forbids.
    expect(html).toContain(policyFloorReason(WARN_FLOOR));
  });

  it('lets a locked policyFloor win over the host copy', () => {
    const html = detail(UNASSIGNED_DETAIL, {
      unassignedPolicy: UNASSIGNED_POLICY,
      policyFloor: LOCKED_WARN_FLOOR,
    });
    expect(html).toBe(detail(UNASSIGNED_DETAIL, { policyFloor: LOCKED_WARN_FLOOR }));
    expect(html).toContain(policyMeta('warn').desc);
    expect(html).not.toContain(UNASSIGNED_POLICY.description);
  });
});

describe('DetectionDetailView unassigned option', () => {
  const live = { unassignedPolicy: UNASSIGNED_POLICY, onUnassignPolicy: () => undefined };

  it('is absent when the host wires no onUnassignPolicy', () => {
    const html = detail(UNASSIGNED_DETAIL, { unassignedPolicy: UNASSIGNED_POLICY });
    expect(unassignedOption(html)).toBeUndefined();
  });

  it('is labelled with the host label and pressed for an unassigned detection', () => {
    for (const d of [UNASSIGNED_DETAIL, NULL_DETAIL]) {
      const html = detail(d, live);
      const option = unassignedOption(html);
      expect(option).toBeDefined();
      expect(option).toContain('aria-pressed="true"');
      expect(option).not.toContain('disabled');
      expect(pressedButtons(html)).toEqual([option]);
      expect(html).toContain(`${UNASSIGNED_POLICY.label}</button>`);
    }
  });

  it('is offered but not pressed for an assigned detection', () => {
    for (const d of [MONITOR_DETAIL, WARN_DETAIL]) {
      const html = detail(d, live);
      const option = unassignedOption(html);
      expect(option).toBeDefined();
      expect(option).toContain('aria-pressed="false"');
      expect(pressedButtons(html)).toHaveLength(1);
    }
  });

  it('stays live and pressed under an unlocked floor', () => {
    const option = unassignedOption(
      detail(UNASSIGNED_DETAIL, { ...live, policyFloor: WARN_FLOOR }),
    );
    expect(option).toContain('aria-pressed="true"');
    expect(option).not.toContain('disabled');
  });

  it('is refused, unpressed, under a locked floor', () => {
    const html = detail(UNASSIGNED_DETAIL, { ...live, policyFloor: LOCKED_WARN_FLOOR });
    const option = unassignedOption(html);
    expect(option).toContain('aria-pressed="false"');
    expect(option).toContain('aria-disabled="true"');
    expect(option).toContain(`title="${policyFloorReason(LOCKED_WARN_FLOOR)}"`);
    expect(option).not.toContain('disabled=""');
    // The floor's archetype is the one pressed.
    expect(pressedButtons(html)).toHaveLength(1);
    expect(pressedButtons(html)[0]).not.toBe(option);
  });

  it('is refused with the caller reason under editRefusal', () => {
    const option = unassignedOption(detail(UNASSIGNED_DETAIL, { ...live, editRefusal: REFUSAL }));
    expect(option).toContain('aria-disabled="true"');
    expect(option).toContain(`title="${REFUSAL}"`);
    expect(option).toContain('aria-describedby=');
  });

  it('is natively disabled, like every option, in a read-only pane', () => {
    const option = unassignedOption(
      detail(UNASSIGNED_DETAIL, { ...live, onChangePolicy: undefined }),
    );
    expect(option).toContain('disabled=""');
    expect(option).toContain('aria-pressed="true"');
  });
});
