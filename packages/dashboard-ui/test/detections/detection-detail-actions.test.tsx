// @vitest-environment jsdom
//
// The "More" menu renders through a Radix Portal, which produces NO markup
// under `renderToStaticMarkup` — verified in rule-inspector.test.tsx for the
// same reason — so a static-markup suite could assert this menu into
// existence and pass against an empty string. This is the one place its real
// open/select/close behavior is proven.
//
// The Add rule button needs no portal and its title/disabled states are
// already covered by static markup in detection-floor-views.test.ts — but a
// title and a `disabled` attribute both hold even for a button whose click
// handler was silently dropped, so THIS file is what proves a live click
// actually reaches onAddRule, and that a disabled rendering really refuses
// one.
import type { DetectionDetail } from '@akasecurity/schema';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DetectionDetailView } from '../../src/detections/DetectionDetailView.tsx';

function detection(overrides: Partial<DetectionDetail> = {}): DetectionDetail {
  return {
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
    ...overrides,
  };
}

let host: HTMLDivElement;
let root: Root;

function mount(ui: React.ReactElement): void {
  act(() => {
    root.render(ui);
  });
}

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement('div');
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  // Unmounted here rather than at the end of a body, same as SearchField.test.tsx:
  // a failing assertion would otherwise skip an in-body teardown and leave a
  // live root — and a portalled, still-open menu — in the document.
  act(() => {
    root.unmount();
  });
  host.remove();
});

function trigger(): HTMLButtonElement {
  const el = host.querySelector('button[aria-label="More"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no "More" button rendered');
  return el;
}

function addRuleButton(): HTMLButtonElement {
  const el = host.querySelector('button[data-slot="add-rule"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no "Add rule" button rendered');
  return el;
}

/**
 * Radix's DropdownMenuTrigger opens on `pointerdown` (so the menu is ready by
 * the time a mouse button is released), not on `click` — see
 * @radix-ui/react-dropdown-menu's DropdownMenuTrigger.
 */
function open(): void {
  act(() => {
    trigger().dispatchEvent(
      new PointerEvent('pointerdown', { bubbles: true, button: 0, pointerId: 1 }),
    );
  });
}

/** The menu item with this exact accessible text, portalled onto `document.body`. */
function menuItem(name: string): HTMLElement | null {
  const items = [...document.querySelectorAll('[role="menuitem"]')];
  return (items.find((el) => el.textContent === name) as HTMLElement | undefined) ?? null;
}

describe('DetectionDetailView "More" menu', () => {
  it('offers Edit rules and Delete detection for a custom detection wired for both', () => {
    const onEditRules = vi.fn();
    const onDelete = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
        onDelete={onDelete}
      />,
    );

    open();
    expect(menuItem('Edit rules')).not.toBeNull();
    expect(menuItem('Delete detection')).not.toBeNull();

    act(() => {
      menuItem('Edit rules')?.click();
    });
    expect(onEditRules).toHaveBeenCalledTimes(1);
    expect(onDelete).not.toHaveBeenCalled();

    // Re-open: selecting an item closes the menu, so the second action needs
    // its own open() the same way a real second click would.
    open();
    act(() => {
      menuItem('Delete detection')?.click();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it('offers only the action the host actually wired', () => {
    const onEditRules = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onEditRules={onEditRules}
      />,
    );

    open();
    expect(menuItem('Edit rules')).not.toBeNull();
    // Not merely inactive — absent, because there is nothing this control
    // could do for a callback the host never supplied.
    expect(menuItem('Delete detection')).toBeNull();
  });

  it('leaves the trigger inert for a library detection, even with both callbacks supplied', () => {
    // A library pack is edited by publishing a new version, never in place —
    // origin gates the menu ahead of whichever callbacks the host wired.
    mount(
      <DetectionDetailView
        d={detection({ origin: 'library' })}
        onOpenRule={() => undefined}
        onEditRules={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    // A real Radix trigger always carries aria-haspopup; its absence is the
    // proof this rendered the plain fallback button, not a disabled menu.
    expect(trigger().getAttribute('aria-haspopup')).toBeNull();

    open();
    expect(document.querySelector('[role="menu"]')).toBeNull();
  });

  it('renders no menu at all when a custom detection has neither callback', () => {
    mount(<DetectionDetailView d={detection({ origin: 'custom' })} onOpenRule={() => undefined} />);

    expect(trigger().getAttribute('aria-haspopup')).toBeNull();

    open();
    expect(document.querySelector('[role="menu"]')).toBeNull();
  });

  it('offers Delete detection alone, with no Edit rules item and no separator', () => {
    // The mirror of "offers only the action the host actually wired" above:
    // proves the single-item case works with the OTHER item present too, and
    // that a menu with one item carries no leftover separator between it and
    // nothing.
    const onDelete = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onDelete={onDelete}
      />,
    );

    open();
    expect(menuItem('Edit rules')).toBeNull();
    const deleteItem = menuItem('Delete detection');
    expect(deleteItem).not.toBeNull();
    // dropdown-menu.tsx's DropdownMenuSeparator renders Radix's Separator,
    // which carries role="separator" — the one marker a lone item would still
    // pass without if this only checked for two menuitems.
    expect(document.querySelector('[role="separator"]')).toBeNull();

    act(() => {
      deleteItem?.click();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it('disables the fallback trigger for a library detection, with its own reason', () => {
    mount(
      <DetectionDetailView
        d={detection({ origin: 'library' })}
        onOpenRule={() => undefined}
        onEditRules={vi.fn()}
        onDelete={vi.fn()}
      />,
    );

    expect(trigger().disabled).toBe(true);
    expect(trigger().getAttribute('title')).toBe('Library detections are managed from the library');
  });

  it('disables the fallback trigger for a custom detection with no callback wired, with its own reason', () => {
    mount(<DetectionDetailView d={detection({ origin: 'custom' })} onOpenRule={() => undefined} />);

    expect(trigger().disabled).toBe(true);
    expect(trigger().getAttribute('title')).toBe('Detection actions are not available here');
  });
});

describe('DetectionDetailView "Add rule" button, live', () => {
  it('reaches onAddRule on a real click for a custom detection wired for it', () => {
    const onAddRule = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'custom' })}
        onOpenRule={() => undefined}
        onAddRule={onAddRule}
      />,
    );

    act(() => {
      addRuleButton().click();
    });
    expect(onAddRule).toHaveBeenCalledTimes(1);
  });

  it('refuses the click for a custom detection with no write path wired', () => {
    mount(<DetectionDetailView d={detection({ origin: 'custom' })} onOpenRule={() => undefined} />);

    expect(addRuleButton().disabled).toBe(true);
  });

  it('refuses the click for a library detection even when onAddRule is supplied', () => {
    // A library pack is edited by publishing a new version, never in place —
    // so the callback being wired changes nothing for it.
    const onAddRule = vi.fn();
    mount(
      <DetectionDetailView
        d={detection({ origin: 'library' })}
        onOpenRule={() => undefined}
        onAddRule={onAddRule}
      />,
    );

    expect(addRuleButton().disabled).toBe(true);
    act(() => {
      addRuleButton().click();
    });
    expect(onAddRule).not.toHaveBeenCalled();
  });
});
