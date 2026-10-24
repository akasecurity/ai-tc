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
import { TrustChoice } from '../../src/inventory/chips.tsx';
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

const PAGE = { onBack: () => undefined, backLabel: 'Claude Code', locale: 'en-US' };

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
    mount(<AssetDetail {...PAGE} asset={mcpAsset()} onTrust={onTrust} />);

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
    mount(<AssetDetail {...PAGE} asset={mcpAsset()} onTrust={onTrust} trustRefusal={REASON} />);

    const button = optionButton(mounted.host, 'Known good');
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);
    // This control has no hover state of its own to cancel, so the call site
    // passes no neutralizer; pin that it stays that way (and stays inert).
    expect(button.className.split(' ')).toEqual(
      expect.arrayContaining(['cursor-not-allowed', 'opacity-50']),
    );
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
        {...PAGE}
        asset={mcpAsset({ type: 'skill', trust: null, tools: undefined })}
        onTrust={onTrust}
        trustRefusal={REASON}
      />,
    );

    expect(mounted.host.querySelector('[data-slot="radio-card-list-refusal-reason"]')).toBeNull();
  });
});

describe('AssetDetail per-type details', () => {
  const fieldText = (host: HTMLElement): string[] =>
    [...host.querySelectorAll('dl > div')].map(
      (row) =>
        `${row.querySelector('dt')?.textContent ?? ''}=${row.querySelector('dd')?.textContent ?? ''}`,
    );

  it("labels a hook's fields and shows its command in a code block, not the grid", () => {
    mount(
      <AssetDetail
        {...PAGE}
        asset={mcpAsset({
          type: 'hook',
          name: 'guard.sh',
          trust: null,
          tools: undefined,
          meta: {
            event: 'PreToolUse',
            matcher: 'Bash',
            scope: 'user',
            status: 'active',
            command: './guard.sh --strict',
          },
        })}
        onTrust={vi.fn()}
      />,
    );

    expect(mounted.host.querySelector('pre')?.textContent).toBe('./guard.sh --strict');
    expect(fieldText(mounted.host)).toEqual([
      'Event=PreToolUse',
      'Matcher=Bash',
      'Scope=user',
      'State=active',
    ]);
  });

  it("labels a skill's versions and keeps unrecognised keys under a readable label", () => {
    mount(
      <AssetDetail
        {...PAGE}
        asset={mcpAsset({
          type: 'skill',
          trust: null,
          tools: undefined,
          meta: {
            source: 'acme/skills',
            installedVersion: '1.2.0',
            latestVersion: '1.3.0',
            reviewedBy: 'sec',
          },
        })}
        onTrust={vi.fn()}
      />,
    );

    expect(fieldText(mounted.host)).toEqual([
      'Source=acme/skills',
      'Installed=1.2.0',
      'Latest=1.3.0',
      'Reviewed by=sec',
    ]);
  });

  it('leads with an icon-only back button named for where it returns', () => {
    const onBack = vi.fn();
    mount(<AssetDetail {...PAGE} onBack={onBack} asset={mcpAsset()} onTrust={vi.fn()} />);

    const back = mounted.host.querySelector('button[aria-label="Back to Claude Code"]');
    expect(back).not.toBeNull();
    expect(back?.textContent).toBe('');
    act(() => {
      (back as HTMLButtonElement).click();
    });
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});

describe('AssetDetail endpoints', () => {
  const variant = (over: Partial<NonNullable<AssetDetailShape['seenOn']>[number]> = {}) => ({
    machines: 3,
    sub: 'stripe',
    description: null,
    flags: [],
    meta: { transport: 'http', url: 'https://a.example/mcp', updatedAt: '2026-10-01T00:00:00Z' },
    ...over,
  });

  it('says how many endpoints report the asset when the store records it', () => {
    mount(<AssetDetail {...PAGE} asset={mcpAsset({ machines: 12 })} onTrust={vi.fn()} />);
    expect(mounted.host.textContent).toContain('Seen on 12 endpoints');

    mount(<AssetDetail {...PAGE} asset={mcpAsset({ machines: 1 })} onTrust={vi.fn()} />);
    expect(mounted.host.textContent).toContain('Seen on 1 endpoint');
  });

  it('says nothing about endpoints when the store does not record them', () => {
    mount(<AssetDetail {...PAGE} asset={mcpAsset()} onTrust={vi.fn()} />);
    expect(mounted.host.textContent).not.toContain('Seen on');
    expect(mounted.host.textContent).not.toContain('Versions reported');
  });

  it('lists each version with the fields that differ, its endpoints and up to five hosts', () => {
    const seenOn = [
      variant({
        machines: 8,
        hosts: ['h1', 'h2', 'h3', 'h4', 'h5'],
        meta: {
          transport: 'http',
          url: 'https://a.example/mcp',
          updatedAt: '2026-10-01T00:00:00Z',
        },
      }),
      variant({
        machines: 2,
        hosts: ['h9', 'h10'],
        meta: {
          transport: 'http',
          url: 'https://b.example/mcp',
          updatedAt: '2026-10-02T00:00:00Z',
        },
      }),
    ];
    mount(<AssetDetail {...PAGE} asset={mcpAsset({ machines: 10, seenOn })} onTrust={vi.fn()} />);
    const section = [...mounted.host.querySelectorAll('li')].map((li) => li.textContent);

    expect(mounted.host.textContent).toContain('Versions reported');
    expect(section).toHaveLength(2);
    expect(section[0]).toContain('8 endpoints');
    expect(section[0]).toContain('h1, h2, h3, h4, h5 and 3 more');
    expect(section[0]).toContain('https://a.example/mcp');
    expect(section[1]).toContain('2 endpoints');
    expect(section[1]).toContain('h9, h10');
    expect(section[1]).not.toContain('more');
    expect(section[1]).toContain('https://b.example/mcp');
    // The transport is the same in both, and the date is when one endpoint last
    // changed its copy: neither tells the versions apart.
    for (const text of section) {
      expect(text).not.toContain('Transport');
      expect(text).not.toContain('2026');
    }
  });

  it('shows no breakdown for an asset every endpoint reports the same way', () => {
    mount(
      <AssetDetail
        {...PAGE}
        asset={mcpAsset({ machines: 4, seenOn: [variant({ machines: 4 })] })}
        onTrust={vi.fn()}
      />,
    );
    expect(mounted.host.textContent).toContain('Seen on 4 endpoints');
    expect(mounted.host.textContent).not.toContain('Versions reported');
  });
});

describe('AssetDetail host actions', () => {
  it('draws no trust picker without onTrust', () => {
    mount(<AssetDetail {...PAGE} asset={mcpAsset()} />);
    expect(mounted.host.textContent).not.toContain('Trust classification');
    expect([...mounted.host.querySelectorAll('button')].map((b) => b.textContent)).not.toContain(
      'Known good',
    );
  });

  it("draws the host's actions in place of the per-type buttons", () => {
    mount(
      <AssetDetail
        {...PAGE}
        asset={mcpAsset()}
        actions={<div data-testid="host-actions">Host actions</div>}
      />,
    );
    expect(mounted.host.querySelector('[data-testid="host-actions"]')).not.toBeNull();
    expect(mounted.host.textContent).not.toContain('Re-verify');
  });

  it('keeps the per-type buttons when the host passes no actions', () => {
    mount(<AssetDetail {...PAGE} asset={mcpAsset()} onTrust={vi.fn()} />);
    expect(mounted.host.textContent).toContain('Re-verify');
  });
});

describe('TrustChoice', () => {
  it('reaches onChange with the level clicked', () => {
    const onChange = vi.fn();
    mount(<TrustChoice value="risky" onChange={onChange} />);
    act(() => {
      optionButton(mounted.host, 'Known good').click();
    });
    expect(onChange).toHaveBeenCalledWith('known-good');
  });

  it('marks every option aria-disabled and never calls onChange while locked', () => {
    const onChange = vi.fn();
    mount(<TrustChoice value="risky" onChange={onChange} locked />);
    const option = optionButton(mounted.host, 'Known good');
    expect(option.getAttribute('aria-disabled')).toBe('true');
    expect(option.disabled).toBe(false);
    act(() => {
      option.click();
    });
    expect(onChange).not.toHaveBeenCalled();
    expect(describedReason(option)).toBeNull();
  });

  it('shows one linked reason when refused', () => {
    const onChange = vi.fn();
    mount(<TrustChoice value="risky" onChange={onChange} refusal={{ id: 'r', reason: REASON }} />);
    const option = optionButton(mounted.host, 'Known good');
    expect(describedReason(option)).toBe(REASON);
    act(() => {
      option.click();
    });
    expect(onChange).not.toHaveBeenCalled();
  });
});
