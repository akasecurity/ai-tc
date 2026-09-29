// @vitest-environment jsdom
//
// trustRefusal covers AssetDetail's one live control: the MCP trust
// RadioCardList. Every action button actionsFor(...) renders is documented
// in this file's own top comment as a visual affordance with no operation
// behind it, so trustRefusal must not touch any of them. Proves: (1)
// aria-disabled without native disabled on every trust option, (2) a
// visible reason linked via aria-describedby, (3) onTrust never reached on
// a real click, (4) no stray refusal markup for a non-MCP asset (no trust
// picker exists there to refuse), and that omitting the prop changes
// nothing.
import type { AssetDetail as AssetDetailShape } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AssetDetail } from '../../src/inventory/AssetDetail.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

function mcpAsset(overrides: Partial<AssetDetailShape> = {}): AssetDetailShape {
  return {
    id: 'asset_1',
    type: 'mcp',
    name: 'stripe-mcp',
    sub: 'stripe',
    flags: [],
    trust: 'risky',
    description: null,
    meta: {},
    finding: null,
    tools: [],
    ...overrides,
  };
}

function optionButton(host: HTMLElement, label: string): HTMLButtonElement {
  const buttons = [...host.querySelectorAll('button')];
  const el = buttons.find((b) => b.textContent.includes(label));
  if (!(el instanceof HTMLButtonElement)) throw new Error(`no "${label}" option rendered`);
  return el;
}

function describedReason(el: HTMLElement): string | null {
  const id = el.getAttribute('aria-describedby');
  if (id === null) return null;
  return document.getElementById(id)?.textContent ?? null;
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

describe('AssetDetail MCP trust picker, live', () => {
  it('reaches onTrust on a real click', () => {
    const onTrust = vi.fn();
    mount(<AssetDetail asset={mcpAsset()} onTrust={onTrust} />);

    act(() => {
      optionButton(mounted.host, 'Known good').click();
    });

    expect(onTrust).toHaveBeenCalledTimes(1);
    expect(onTrust).toHaveBeenCalledWith('known-good');
  });
});

describe('AssetDetail MCP trust picker, refused', () => {
  it('refuses every option: aria-disabled, reason visible and linked, onTrust never called', () => {
    const onTrust = vi.fn();
    mount(<AssetDetail asset={mcpAsset()} onTrust={onTrust} trustRefusal={REASON} />);

    const button = optionButton(mounted.host, 'Known good');
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);
    // This control has no hover state of its own to cancel, so the call site
    // passes no neutralizer; pin that it stays that way (and stays inert).
    expect(button.className).toContain('cursor-not-allowed opacity-50');
    expect(button.className).not.toContain('hover:');

    act(() => {
      button.click();
    });
    expect(onTrust).not.toHaveBeenCalled();

    const unapprovedButton = optionButton(mounted.host, 'Unapproved');
    expect(unapprovedButton.getAttribute('aria-disabled')).toBe('true');
    act(() => {
      unapprovedButton.click();
    });
    expect(onTrust).not.toHaveBeenCalled();
  });

  it('renders no refusal markup for a non-MCP asset (no trust picker to refuse)', () => {
    const onTrust = vi.fn();
    mount(
      <AssetDetail
        asset={mcpAsset({ type: 'skill', trust: null, tools: undefined })}
        onTrust={onTrust}
        trustRefusal={REASON}
      />,
    );

    expect(mounted.host.querySelector('[data-slot="radio-card-list-refusal-reason"]')).toBeNull();
  });
});
