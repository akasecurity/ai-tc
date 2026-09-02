import type { DetectionDetail, DetectionListItem } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';
import { DetectionsListView } from '../../src/detections/DetectionsListView.tsx';
import { policyMeta } from '../../src/detections/meta.ts';
import type { DetectionPolicyFloor } from '../../src/detections/policy-floor.ts';
import { DETECTION_STAYS_ON_REASON, policyFloorReason } from '../../src/detections/policy-floor.ts';

// The two surfaces that used to disagree with enforcement, driven end to end
// from the serializable floor a host hands them.
//
// The detail pane's picker is the one that took the click; the list is the same
// untruth one level out, and a page whose list says Monitor beside a pane
// saying the organization requires Warn has only moved the confusion.

const DETAIL: DetectionDetail = {
  id: 'aka/secrets',
  name: 'Secrets',
  version: '1.0.0',
  enabled: true,
  origin: 'library',
  ruleCount: 1,
  namespace: 'aka',
  packId: 'secrets',
  editedAt: '2026-01-01T00:00:00.000Z',
  findingsLast30d: 0,
  update: null,
  modified: false,
  policyId: 'monitor',
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

const ITEM: DetectionListItem = {
  id: 'aka/secrets',
  name: 'Secrets',
  version: '1.0.0',
  enabled: true,
  origin: 'library',
  ruleCount: 1,
  namespace: 'aka',
  packId: 'secrets',
  policyId: 'monitor',
};

const WARN_FLOOR: DetectionPolicyFloor = { floor: 'warn', locked: false };
const LOCKED: DetectionPolicyFloor = { floor: 'redact', locked: true };

function detail(props: Partial<Parameters<typeof DetectionDetailView>[0]> = {}): string {
  return renderToStaticMarkup(
    createElement(DetectionDetailView, {
      d: DETAIL,
      onOpenRule: () => undefined,
      onChangePolicy: () => undefined,
      ...props,
    }),
  );
}

/**
 * The opening tags of every <button> in a rendering.
 *
 * The assertions below are about ONE control, and the pane also carries
 * ordinarily-disabled buttons of its own (the "Add rule" placeholder), so
 * searching the whole document for `disabled=""` would answer about the wrong
 * element and pass whatever the picker emitted.
 */
function buttonTags(html: string): string[] {
  return html
    .split('<button')
    .slice(1)
    .map((chunk) => chunk.slice(0, chunk.indexOf('>')));
}

/**
 * The opening tag of the enable/disable Switch, which renders as a <button> of
 * its own. Picked out by slot rather than by position: the pane carries other
 * buttons — the picker's five archetypes, "Add rule" — and an assertion aimed
 * at the wrong one would pass whatever this control emitted.
 */
function switchTag(html: string): string {
  const tag = buttonTags(html).find((t) => t.includes('data-slot="switch"'));
  expect(tag, 'the pane rendered no enable/disable switch at all').toBeDefined();
  return tag ?? '';
}

/** The same pane with a host that can actually write the enabled state. */
function toggleable(props: Partial<Parameters<typeof DetectionDetailView>[0]> = {}): string {
  return detail({ onToggleEnabled: () => undefined, ...props });
}

function list(floorsById?: ReadonlyMap<string, DetectionPolicyFloor>): string {
  return renderToStaticMarkup(
    createElement(DetectionsListView, {
      items: [ITEM],
      counts: { all: 1 },
      activeId: ITEM.id,
      query: '',
      filter: 'all',
      onQueryChange: () => undefined,
      onFilterChange: () => undefined,
      onSelect: () => undefined,
      floorsById,
    }),
  );
}

describe('DetectionDetailView under a control-plane floor', () => {
  it('renders byte-identically when no floor is supplied', () => {
    // The standalone machine, which is every install that has not attached. It
    // must not pick up a disabled option, a reason line, or a raised pill.
    expect(detail({ policyFloor: null })).toBe(detail());
    expect(detail({ policyError: null })).toBe(detail());
  });

  it('offers a below-floor archetype disabled rather than hiding it', () => {
    const html = detail({ policyFloor: WARN_FLOOR });
    // Still present — hiding turns "you cannot pick this, because X" into "this
    // does not exist", and the reader's next move is to go looking for it.
    expect(html).toContain(policyMeta('monitor').label);
    // Exactly one option restricted: the four at or above the floor stay live.
    expect(html.match(/data-unavailable/g)?.length).toBe(1);
    const restricted = buttonTags(html).filter((tag) => tag.includes('data-unavailable'));
    expect(restricted).toHaveLength(1);
    // aria, never the native attribute — a natively disabled button leaves the
    // tab order, so the reason never reaches a keyboard or screen-reader user.
    // Asserted precisely: `toContain('disabled')` matches the aria form too and
    // would pass whichever one the component emitted.
    expect(restricted[0]).toContain('aria-disabled="true"');
    expect(restricted[0]).not.toContain(' disabled=""');
  });

  it('says why, in a line the restricted option points at', () => {
    const html = detail({ policyFloor: WARN_FLOOR });
    expect(html).toContain('data-slot="policy-unavailable-reason"');
    expect(html).toContain(policyFloorReason(WARN_FLOOR));
    const describedBy = /aria-describedby="([^"]+)"/.exec(html);
    expect(describedBy, 'the restricted option describes nothing').not.toBeNull();
    expect(html).toContain(`id="${describedBy?.[1] ?? ''}"`);
  });

  it('shows the ENFORCED archetype as selected, not the weaker stored one', () => {
    // The store can hold a below-floor assignment written before this machine
    // was attached; the write path refuses new ones but cannot rewrite history.
    const html = detail({ policyFloor: WARN_FLOOR });
    expect(html).toContain('aria-pressed="true"');
    // The description card explains the selected archetype, so the two must
    // name the same one — a Warn pill over Monitor's description is the same
    // lie in a different place.
    expect(html).toContain(policyMeta('warn').desc);
    expect(html).not.toContain(policyMeta('monitor').desc);
    // Positive control on the same bytes: Monitor's description IS what renders
    // without a floor, so the absence above cannot pass vacuously.
    expect(detail()).toContain(policyMeta('monitor').desc);
  });

  it('takes every option away for a locked detection', () => {
    const html = detail({ policyFloor: LOCKED });
    expect(html.match(/data-unavailable/g)?.length).toBe(5);
    // One constraint, one line — the reasons dedupe by string.
    expect(html.match(/data-slot="policy-unavailable-reason"/g)?.length).toBe(1);
    expect(html).toContain(policyFloorReason(LOCKED));
  });

  it('renders a refused write at the control that produced it', () => {
    const message = 'That change was not saved.';
    const html = detail({ policyError: message });
    expect(html).toContain('data-slot="policy-write-error"');
    expect(html).toContain(message);
    // And nowhere near it when there is nothing to report.
    expect(detail()).not.toContain('data-slot="policy-write-error"');
  });

  it('keeps a host-supplied restriction alongside the floor', () => {
    // Both are real at once: a host that cannot deliver an archetype AND an
    // organization that requires a minimum. Merging rather than choosing is
    // what stops one of them from silently winning.
    const html = detail({
      policyFloor: WARN_FLOOR,
      unavailablePolicies: { vault: 'Not available on this machine.' },
    });
    expect(html.match(/data-unavailable/g)?.length).toBe(2);
    expect(html).toContain('Not available on this machine.');
    expect(html).toContain(policyFloorReason(WARN_FLOOR));
  });
});

describe('the enable toggle under a control-plane floor', () => {
  it('renders byte-identically when no floor and no refusal are supplied', () => {
    // The standalone machine again, at the other control. It must not pick up an
    // aria-disabled switch, a reason line, or a message.
    expect(toggleable({ policyFloor: null })).toBe(toggleable());
    expect(toggleable({ enabledError: null })).toBe(toggleable());
  });

  it('withholds the switch-off without taking it out of the tab order', () => {
    const html = toggleable({ policyFloor: WARN_FLOOR });
    // aria, never the native attribute — the same contract the picker's
    // unassignable archetypes keep, and for the same reason: a natively
    // disabled control leaves the tab order, so the reason never reaches a
    // keyboard or screen-reader user. Asserted precisely, because
    // `toContain('disabled')` matches the aria form too.
    expect(switchTag(html)).toContain('aria-disabled="true"');
    expect(switchTag(html)).not.toContain(' disabled=""');
    // Positive control on the same control: unconstrained, it carries neither.
    expect(switchTag(toggleable())).not.toContain('aria-disabled');
  });

  it('says why, in a line the switch points at', () => {
    const html = toggleable({ policyFloor: WARN_FLOOR });
    expect(html).toContain(DETECTION_STAYS_ON_REASON);
    expect(html).toContain('data-slot="enabled-locked-reason"');
    // The reason travels on the control as well, for a pointer user.
    expect(switchTag(html)).toContain(`title="${DETECTION_STAYS_ON_REASON}"`);
    const describedBy = /aria-describedby="([^"]+)"/.exec(switchTag(html));
    expect(describedBy, 'the withheld switch describes nothing').not.toBeNull();
    // And it points at an element that is really in the markup — an id
    // referencing nothing announces nothing, and reads identically here.
    expect(html).toMatch(
      new RegExp(`id="${describedBy?.[1] ?? ''}"[^>]*data-slot="enabled-locked-reason"`),
    );
  });

  it('withholds it under a Monitor floor too, where the picker restricts nothing', () => {
    // "Off" is below every archetype, so the weakest floor still forbids it.
    // Both halves asserted on one rendering, so this cannot pass by the pane
    // having rendered neither control.
    const html = toggleable({ policyFloor: { floor: 'monitor', locked: false } });
    expect(switchTag(html)).toContain('aria-disabled="true"');
    expect(html).not.toContain('data-unavailable');
  });

  it('leaves a governed detection that is already off free to be turned back on', () => {
    // Re-enabling moves toward what the organization asked for. A store can hold
    // a detection switched off from before this refusal existed, and withholding
    // the toggle there would leave it stuck off.
    const html = toggleable({ d: { ...DETAIL, enabled: false }, policyFloor: LOCKED });
    expect(switchTag(html)).not.toContain('aria-disabled');
    expect(html).not.toContain('data-slot="enabled-locked-reason"');
  });

  it('does not make a read-only pane look restricted', () => {
    // No onToggleEnabled is a different statement — this host offers no
    // enable/disable at all, not that the organization withheld one. It must not
    // sprout a reason for a control that is not there.
    const html = detail({ policyFloor: LOCKED });
    expect(html).not.toContain('data-slot="switch"');
    expect(html).not.toContain('data-slot="enabled-locked-reason"');
  });

  it('renders a refused toggle at the toggle, not under the picker', () => {
    // The two refusals are about different controls. Reporting this one under
    // the picker would attribute the organization's constraint to a choice it
    // never touched.
    const message = 'That change was not saved.';
    const html = toggleable({ enabledError: message });
    expect(html).toContain('data-slot="enabled-write-error"');
    expect(html).toContain(message);
    expect(html).not.toContain('data-slot="policy-write-error"');
    // And the picker's own refusal still lands at the picker.
    const other = toggleable({ policyError: message });
    expect(other).toContain('data-slot="policy-write-error"');
    expect(other).not.toContain('data-slot="enabled-write-error"');
  });
});

describe('DetectionsListView under a control-plane floor', () => {
  it('renders byte-identically when no floors are supplied', () => {
    expect(list(new Map())).toBe(list());
  });

  it('names what is enforced on the row, not the weaker stored assignment', () => {
    const html = list(new Map([[ITEM.id, WARN_FLOOR]]));
    expect(html).toContain(policyMeta('warn').label);
    // Positive control: Monitor's label IS what the row shows unconstrained, so
    // its absence here is a real change rather than a label that never renders.
    expect(list()).toContain(policyMeta('monitor').label);
    expect(html).not.toContain('>Monitor<');
  });

  it('carries the reason on the row for anyone who cannot see the marker', () => {
    const html = list(new Map([[ITEM.id, WARN_FLOOR]]));
    expect(html).toContain(policyFloorReason(WARN_FLOOR));
    expect(html).toContain('sr-only');
  });

  it('marks a locked row even when the local value already agrees', () => {
    const html = list(new Map([[ITEM.id, { floor: 'monitor', locked: true }]]));
    // The value is right and the decision is still not this machine's.
    expect(html).toContain(policyMeta('monitor').label);
    expect(html).toContain('sr-only');
  });

  it('leaves a row whose choice already satisfies the floor unmarked', () => {
    const html = list(new Map([[ITEM.id, { floor: 'monitor', locked: false }]]));
    expect(html).toBe(list());
  });
});
