// @vitest-environment jsdom
//
// actionRefusal covers exactly two controls on a row: Apply (only its
// mode==='apply' branch — the mode==='navigate' link and the no-href
// dead-end never call applyAction, so neither is in scope) and Dismiss
// (only when the row has a rule subject to dismiss — a row without one
// renders no Dismiss control today, refused or not). This proves, for
// both: (1) aria-disabled without native disabled, (2) a visible reason
// linked via aria-describedby, (3) the handler never reached on a real
// click, and that omitting the prop changes nothing.
import type { RecommendedAction } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { RecommendedActionsCardView } from '../../src/security/RecommendedActionsCardView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

function action(overrides: Partial<RecommendedAction> = {}): RecommendedAction {
  return {
    id: 'ra_1',
    category: 'block_credentials',
    severity: 'critical',
    title: 'Block credential exposure',
    description: 'AWS keys were found unblocked in 3 repositories.',
    subjects: [{ type: 'rule', id: 'aws-key', label: 'aws-key' }],
    action: { mode: 'apply', type: 'promote_policy_to_block', label: 'Block now' },
    ...overrides,
  };
}

const REASON = 'This control is not available here.';
const noop = (): void => undefined;

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

function applyButton(): HTMLButtonElement {
  const el = mounted.host.querySelector('button[data-slot="recommended-action-apply"]');
  if (!(el instanceof HTMLButtonElement)) throw new Error('no Apply button rendered');
  return el;
}

function dismissButton(): HTMLButtonElement | null {
  return mounted.host.querySelector('button[data-slot="recommended-action-dismiss"]');
}

function describedReason(el: HTMLElement): string | null {
  const id = el.getAttribute('aria-describedby');
  if (id === null) return null;
  return document.getElementById(id)?.textContent ?? null;
}

describe('Apply, live', () => {
  it('reaches applyAction on a real click', () => {
    const applyAction = vi.fn();
    mount(
      <RecommendedActionsCardView
        items={[action()]}
        isLoading={false}
        error={null}
        applyAction={applyAction}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
      />,
    );

    act(() => {
      applyButton().click();
    });

    expect(applyAction).toHaveBeenCalledTimes(1);
    expect(applyAction).toHaveBeenCalledWith('ra_1');
  });
});

describe('Dismiss, live', () => {
  it('opens the dismiss dialog on a real click', () => {
    mount(
      <RecommendedActionsCardView
        items={[action()]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
      />,
    );

    act(() => {
      dismissButton()?.click();
    });

    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
  });

  it('renders no Dismiss control for a row with no rule subject', () => {
    mount(
      <RecommendedActionsCardView
        items={[action({ subjects: [{ type: 'repo', id: 'r1', label: 'acme/api' }] })]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
      />,
    );

    expect(dismissButton()).toBeNull();
  });
});

describe('Apply and Dismiss, refused', () => {
  it('refuses Apply: aria-disabled, reason visible and linked, applyAction never called', () => {
    const applyAction = vi.fn();
    mount(
      <RecommendedActionsCardView
        items={[action()]}
        isLoading={false}
        error={null}
        applyAction={applyAction}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
        actionRefusal={REASON}
      />,
    );

    const button = applyButton();
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);

    act(() => {
      button.click();
    });
    expect(applyAction).not.toHaveBeenCalled();
  });

  it('refuses Dismiss: aria-disabled, reason visible and linked, dialog never opens', () => {
    mount(
      <RecommendedActionsCardView
        items={[action()]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
        actionRefusal={REASON}
      />,
    );

    const button = dismissButton();
    if (button === null) throw new Error('no Dismiss button rendered');
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);

    act(() => {
      button.click();
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it('renders no Dismiss control for a row with no rule subject, even when refused', () => {
    mount(
      <RecommendedActionsCardView
        items={[action({ subjects: [{ type: 'repo', id: 'r1', label: 'acme/api' }] })]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
        actionRefusal={REASON}
      />,
    );

    expect(dismissButton()).toBeNull();
  });

  it('leaves the navigate-mode Apply link unaffected (no applyAction to refuse)', () => {
    mount(
      <RecommendedActionsCardView
        items={[
          action({
            action: { mode: 'navigate', type: 'open_policy', label: 'Review policy', href: '/x' },
          }),
        ]}
        isLoading={false}
        error={null}
        applyAction={noop}
        dismissAction={() => Promise.resolve(true)}
        isMutating={false}
        mutationError={null}
        actionRefusal={REASON}
      />,
    );

    expect(mounted.host.querySelector('a[href="/x"]')).not.toBeNull();
    expect(mounted.host.querySelector('button[data-slot="recommended-action-apply"]')).toBeNull();
  });
});
