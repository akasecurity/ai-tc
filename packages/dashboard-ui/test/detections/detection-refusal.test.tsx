// @vitest-environment jsdom
//
// editRefusal/deleteRefusal are a caller-imposed lock, independent of origin
// and policyFloor (see their JSDoc on DetectionDetailView). This is the live
// proof, for every control they cover, that a refused control (1) is
// aria-disabled and NOT natively disabled, (2) names a visible, linked
// reason, and (3) never reaches its handler on a real click — plus that
// omitting both props changes nothing.
import type { DetectionDetail } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

function detection(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return {
    id: 'aka/secrets',
    name: 'Secrets',
    version: '1.0.0',
    enabled: true,
    origin: 'custom',
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
    ...overrides,
  };
}

const REASON = 'This control is not available here.';

let mounted: MountedRoot;

function mount(ui: React.ReactElement): void {
  renderRoot(mounted.root, ui);
}

beforeEach(() => {
  mounted = mountRoot();
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

function describedReason(el: HTMLElement): string | null {
  const id = el.getAttribute('aria-describedby');
  if (id === null) return null;
  return document.getElementById(id)?.textContent ?? null;
}

function describedSlot(el: HTMLElement): string | null {
  const id = el.getAttribute('aria-describedby');
  if (id === null) return null;
  return document.getElementById(id)?.getAttribute('data-slot') ?? null;
}

function switchEl(): HTMLButtonElement {
  const el = mounted.host.querySelector('[data-slot="switch"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no switch rendered');
  return el;
}

function policyButtons(): HTMLButtonElement[] {
  return [...mounted.host.querySelectorAll('[aria-pressed]')] as HTMLButtonElement[];
}

function addRuleButton(): HTMLButtonElement {
  const el = mounted.host.querySelector('button[data-slot="add-rule"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no "Add rule" button rendered');
  return el;
}

function trigger(): HTMLButtonElement {
  const el = mounted.host.querySelector('button[aria-label="More"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no "More" button rendered');
  return el;
}

function menuItem(name: string): HTMLElement | null {
  const items = [...document.querySelectorAll('[role="menuitem"]')];
  return (items.find((el) => el.textContent === name) as HTMLElement | undefined) ?? null;
}

function open(): void {
  act(() => {
    trigger().dispatchEvent(
      new PointerEvent('pointerdown', { bubbles: true, button: 0, pointerId: 1 }),
    );
  });
}

function updateButton(): HTMLButtonElement {
  const el = mounted.host.querySelector('button[data-slot="open-update"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no "Update" button rendered');
  return el;
}

function updateAvailable(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return detection({ update: { available: true, latestVersion: '2.0.0' }, ...overrides });
}

describe('the enable/disable switch under editRefusal', () => {
  it('refuses a live toggle: aria-disabled, reason visible and linked, handler not called', () => {
    const onToggleEnabled = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ enabled: true })}
        onOpenRule={() => undefined}
        onToggleEnabled={onToggleEnabled}
        editRefusal={REASON}
      />,
    );

    const el = switchEl();
    expect(el.disabled).toBe(false);
    expect(el.getAttribute('aria-disabled')).toBe('true');
    expect(describedReason(el)).toBe(REASON);
    expect(describedSlot(el)).toBe('enabled-locked-reason');

    act(() => {
      el.click();
    });
    expect(onToggleEnabled).not.toHaveBeenCalled();
  });

  it('renders unchanged when editRefusal is absent', () => {
    const onToggleEnabled = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ enabled: true })}
        onOpenRule={() => undefined}
        onToggleEnabled={onToggleEnabled}
      />,
    );

    const el = switchEl();
    expect(el.getAttribute('aria-disabled')).toBeNull();

    act(() => {
      el.click();
    });
    expect(onToggleEnabled).toHaveBeenCalledTimes(1);
  });
});

describe('the policy picker under editRefusal', () => {
  it('refuses every archetype: aria-disabled, reason visible and linked, handler not called', () => {
    const onChangePolicy = vi.fn();
    mount(
      <DetectionDetailView
        d={detection()}
        onOpenRule={() => undefined}
        onChangePolicy={onChangePolicy}
        editRefusal={REASON}
      />,
    );

    const buttons = policyButtons();
    expect(buttons).toHaveLength(5);
    for (const btn of buttons) {
      expect(btn.getAttribute('aria-disabled')).toBe('true');
      expect(describedReason(btn)).toBe(REASON);
      expect(describedSlot(btn)).toBe('policy-unavailable-reason');
    }

    act(() => {
      buttons[0]?.click();
    });
    expect(onChangePolicy).not.toHaveBeenCalled();
  });

  it('renders unchanged when editRefusal is absent', () => {
    const onChangePolicy = vi.fn();
    mount(
      <DetectionDetailView
        d={detection()}
        onOpenRule={() => undefined}
        onChangePolicy={onChangePolicy}
      />,
    );

    for (const btn of policyButtons()) {
      expect(btn.getAttribute('aria-disabled')).toBeNull();
    }
  });
});

describe('the Add rule button under editRefusal', () => {
  it('refuses a live click, with editRefusal as the reason (custom origin)', () => {
    const onAddRule = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onAddRule={onAddRule}
        editRefusal={REASON}
      />,
    );

    const button = addRuleButton();
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(describedReason(button)).toBe(REASON);
    expect(describedSlot(button)).toBe('add-rule-reason');
    // Cancels the live outline/neutral button's hover:bg-surface-2.
    // Whole-token matches throughout: hover:bg-surface is a prefix of the hover:bg-surface-2 it cancels.
    expect(button.className.split(' ')).toEqual(expect.arrayContaining(['hover:bg-surface']));

    act(() => {
      button.click();
    });
    expect(onAddRule).not.toHaveBeenCalled();
  });

  it('keeps the library-origin reason when editRefusal is also set', () => {
    const onAddRule = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'library' })}
        onOpenRule={() => undefined}
        onAddRule={onAddRule}
        editRefusal={REASON}
      />,
    );

    expect(describedReason(addRuleButton())).toBe('Library rules are not edited in place');
  });
});

describe('the "More" menu under editRefusal and deleteRefusal', () => {
  it('omits "Edit rules" alone when only editRefusal is set, leaving Delete live', () => {
    const onEditRules = vi.fn();
    const onDelete = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
        onDelete={onDelete}
        editRefusal={REASON}
      />,
    );

    expect(trigger().getAttribute('aria-haspopup')).toBe('menu');
    open();
    expect(menuItem('Edit rules')).toBeNull();
    const deleteItem = menuItem('Delete detection');
    expect(deleteItem).not.toBeNull();
    act(() => {
      deleteItem?.click();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
    expect(onEditRules).not.toHaveBeenCalled();
  });

  it('omits "Delete detection" alone when only deleteRefusal is set, leaving Edit rules live', () => {
    const onEditRules = vi.fn();
    const onDelete = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
        onDelete={onDelete}
        deleteRefusal={REASON}
      />,
    );

    open();
    expect(menuItem('Delete detection')).toBeNull();
    const editItem = menuItem('Edit rules');
    expect(editItem).not.toBeNull();
    act(() => {
      editItem?.click();
    });
    expect(onEditRules).toHaveBeenCalledTimes(1);
    expect(onDelete).not.toHaveBeenCalled();
  });

  it('refuses the trigger itself when both are set, with a linked, visible reason', () => {
    const onEditRules = vi.fn();
    const onDelete = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
        onDelete={onDelete}
        editRefusal={REASON}
        deleteRefusal={REASON}
      />,
    );

    expect(trigger().getAttribute('aria-haspopup')).toBeNull();
    expect(trigger().disabled).toBe(false);
    expect(trigger().getAttribute('aria-disabled')).toBe('true');
    expect(describedReason(trigger())).toBe(REASON);
    expect(describedSlot(trigger())).toBe('more-actions-reason');
    // Cancels the live ghost/neutral icon button's hover:bg-surface-2 and hover:text-text.
    expect(trigger().className.split(' ')).toEqual(
      expect.arrayContaining(['hover:bg-transparent', 'hover:text-text-3']),
    );

    act(() => {
      trigger().click();
    });
    expect(onEditRules).not.toHaveBeenCalled();
    expect(onDelete).not.toHaveBeenCalled();
  });

  it('renders unchanged when neither refusal is set', () => {
    const onEditRules = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
      />,
    );

    expect(trigger().getAttribute('aria-haspopup')).toBe('menu');
    open();
    expect(menuItem('Edit rules')).not.toBeNull();
  });
});

describe('the Update button under editRefusal', () => {
  it('refuses a live click in place: inside the banner, amber, reason visible and linked', () => {
    const onOpenUpdate = vi.fn();
    mount(
      <DetectionDetailView
        d={updateAvailable()}
        onOpenRule={() => undefined}
        onOpenUpdate={onOpenUpdate}
        editRefusal={REASON}
      />,
    );

    const updateButtons = [...mounted.host.querySelectorAll('button')].filter(
      (b) => b.textContent === 'Update',
    );
    expect(updateButtons).toHaveLength(1);

    const button = updateButton();
    // In the banner that names the update, not a second control below the block.
    const banner = button.closest('.bg-sev-high-fill');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain('Update available');
    // The live button's own amber look, kept while refused.
    expect(button.className.split(' ')).toEqual(
      expect.arrayContaining(['bg-sev-high-ink', 'text-on-accent']),
    );
    // Cancels the live button's hover:bg-sev-high-ink override of the default
    // solid/primary hover (hover:bg-primary-hover).
    expect(button.className.split(' ')).toEqual(expect.arrayContaining(['hover:bg-sev-high-ink']));
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);
    expect(describedSlot(button)).toBe('open-update-reason');
    expect(
      banner?.contains(document.getElementById(button.getAttribute('aria-describedby') ?? '')),
    ).toBe(true);

    act(() => {
      button.click();
    });
    expect(onOpenUpdate).not.toHaveBeenCalled();
  });

  it("renders ProvenanceBlock's own live button when editRefusal is absent, under the same data-slot", () => {
    const onOpenUpdate = vi.fn();
    mount(
      <DetectionDetailView
        d={updateAvailable()}
        onOpenRule={() => undefined}
        onOpenUpdate={onOpenUpdate}
      />,
    );

    const updateButtons = [...mounted.host.querySelectorAll('button')].filter(
      (b) => b.textContent === 'Update',
    );
    expect(updateButtons).toHaveLength(1);
    const button = updateButton();
    expect(button).toBe(updateButtons[0]);
    expect(button.getAttribute('aria-disabled')).toBeNull();
    expect(mounted.host.querySelector('[data-slot="open-update-reason"]')).toBeNull();
    act(() => {
      button.click();
    });
    expect(onOpenUpdate).toHaveBeenCalledTimes(1);
  });

  it('renders no Update control when the host wired no update path, even with editRefusal set', () => {
    mount(
      <DetectionDetailView
        d={updateAvailable()}
        onOpenRule={() => undefined}
        editRefusal={REASON}
      />,
    );

    expect(mounted.host.querySelector('[data-slot="open-update"]')).toBeNull();
    expect(mounted.host.querySelector('[data-slot="open-update-reason"]')).toBeNull();
  });

  it('adds nothing when the detection is not update-available, even with editRefusal set', () => {
    const onOpenUpdate = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ update: { available: false, latestVersion: '1.0.0' } })}
        onOpenRule={() => undefined}
        onOpenUpdate={onOpenUpdate}
        editRefusal={REASON}
      />,
    );

    expect(mounted.host.querySelector('[data-slot="open-update"]')).toBeNull();
  });
});
