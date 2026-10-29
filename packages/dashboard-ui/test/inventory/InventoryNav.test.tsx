// @vitest-environment jsdom
import type { AssetGroup, HarnessSummary, ProjectSummary } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InventoryNav, type InventoryNavUnavailable } from '../../src/inventory/InventoryNav.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const PROJECT: ProjectSummary = {
  id: 'proj-1',
  name: 'web-app',
  repo: 'acme/web-app',
  visibility: 'private',
  language: 'TypeScript',
  policyDefault: 'approved',
  updatedAt: '2026-09-01T00:00:00.000Z',
  accessCounts: { open: 1, approved: 0, blocked: 0, total: 1 },
  findingsCount: 1,
};

const HARNESSES: HarnessSummary[] = [
  {
    id: 'claudecode',
    label: 'Claude Code',
    kind: 'claude_code',
    version: '2.1.4',
    sessions: 3,
    assetCount: 1,
    flagCount: 0,
    projects: [PROJECT],
    categories: [
      {
        type: 'skill',
        assets: [{ id: 's1', type: 'skill', name: 'review', sub: 'Skill', flags: [], meta: {} }],
      },
    ],
  },
  {
    id: 'cursor',
    label: 'Cursor',
    kind: 'cursor',
    version: '1.0',
    sessions: 0,
    assetCount: 0,
    flagCount: 0,
    projects: [],
    categories: [],
  },
];

const GROUPS: AssetGroup[] = [
  {
    type: 'mcp',
    total: 1,
    flagRollup: {},
    items: [
      {
        id: 'm1',
        type: 'mcp',
        name: 'github',
        sub: 'MCP',
        flags: [],
        trust: 'unapproved',
        meta: {},
      },
    ],
  },
];

let mounted: MountedRoot;
beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

const entries = (): string[] =>
  [...mounted.host.querySelectorAll('nav li button')].map((b) => b.textContent);

/** The attention summary beside the header label, whichever branch it took. */
const headerTotal = (): string | null => {
  const label = [...mounted.host.querySelectorAll('span')].find(
    (s) => s.textContent === 'All assets',
  );
  return label?.nextElementSibling?.textContent ?? null;
};

/** A refusal reaches both of the lists one `endpoints: view` gate covers. */
const refused = (reason?: string) =>
  reason === undefined ? undefined : { harnesses: reason, assets: reason };

function mount(
  view: 'harness' | 'type',
  handlers: { onSelectHarness?: () => void } = {},
  assetsRefusal?: string,
): void {
  renderRoot(
    mounted.root,
    <InventoryNav
      harnesses={HARNESSES}
      projects={[PROJECT]}
      assetGroups={GROUPS}
      view={view}
      onView={vi.fn()}
      harness="claudecode"
      type="project"
      onSelectHarness={handlers.onSelectHarness ?? vi.fn()}
      onSelectType={vi.fn()}
      unavailable={refused(assetsRefusal)}
    />,
  );
}

describe('InventoryNav', () => {
  it('lists only harnesses, each with its row count, and nothing nested under them', () => {
    mount('harness');
    expect(entries()).toEqual(['CCClaude Code2', 'CuCursor0']);
    expect(mounted.host.querySelectorAll('nav li')).toHaveLength(2);
  });

  it('marks a harness with something to review with an attention dot', () => {
    mount('harness');
    const [claude, cursor] = [...mounted.host.querySelectorAll('nav li')];
    expect(claude?.querySelector('[aria-label="1 need attention"]')).not.toBeNull();
    expect(cursor?.querySelector('[role="img"]')).toBeNull();
  });

  it('counts every project and asset needing review once in the header', () => {
    mount('type');
    expect(mounted.host.textContent).toContain('2 to review');
  });

  it('lists every type with its count under By type', () => {
    mount('type');
    expect(entries()).toEqual(['Projects1', 'Skills0', 'MCP servers1', 'Hooks0', 'Configuration0']);
  });

  function withLink(
    view: 'harness' | 'type',
    link: { selected?: boolean; onSelect?: () => void } = {},
    assetsRefusal?: string,
    loading = false,
  ) {
    renderRoot(
      mounted.root,
      <InventoryNav
        harnesses={loading ? [] : HARNESSES}
        projects={loading ? [] : [PROJECT]}
        assetGroups={loading ? [] : GROUPS}
        isLoading={loading}
        view={view}
        onView={vi.fn()}
        harness="claudecode"
        type="project"
        onSelectHarness={vi.fn()}
        onSelectType={vi.fn()}
        unavailable={refused(assetsRefusal)}
        links={[
          {
            key: 'credentials',
            label: 'Credentials',
            icon: 'key',
            fg: 'text-sev-high-ink',
            bg: 'bg-sev-high-fill',
            count: 7,
            attention: 3,
            selected: link.selected,
            onSelect: link.onSelect ?? vi.fn(),
          },
        ]}
      />,
    );
    return [...mounted.host.querySelectorAll('nav li button')].at(-1) as HTMLButtonElement;
  }

  it('lists a host link after the types, counts its attention, and opens it on click', () => {
    const onSelect = vi.fn();
    const last = withLink('type', { onSelect });
    expect(entries().at(-1)).toBe('Credentials7');
    expect(mounted.host.textContent).toContain('5 to review');
    expect(last.getAttribute('aria-current')).toBeNull();
    act(() => {
      last.click();
    });
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('leaves a host link out of the harness list, while still counting its attention', () => {
    withLink('harness');
    expect(entries()).toEqual(['CCClaude Code2', 'CuCursor0']);
    expect(mounted.host.querySelector('nav ul[aria-label="Pages"]')).toBeNull();
    expect(mounted.host.textContent).toContain('5 to review');
  });

  it('reads the same attention total in either view for the same props', () => {
    const cases = [
      [undefined, '5 to review'],
      ['You need permission to view assets.', 'At least 4 to review'],
    ] as const;
    for (const [assetsRefusal, expected] of cases) {
      withLink('harness', {}, assetsRefusal);
      const underHarness = headerTotal();
      withLink('type', {}, assetsRefusal);
      expect(headerTotal()).toBe(underHarness);
      expect(underHarness).toBe(expected);
    }
  });

  it('marks a host link as the current entry while its page is shown', () => {
    expect(withLink('type', { selected: true }).getAttribute('aria-current')).toBe('true');
  });

  it('still counts the projects and host links it shows while the asset lists are refused', () => {
    withLink('type', {}, 'You need permission to view assets.');
    // The project row still needs attention, and so do the link's three.
    expect(mounted.host.textContent).toContain('At least 4 to review');
    expect(mounted.host.textContent).not.toContain('All clear');
  });

  it('shows a host link while the inventory is still loading', () => {
    withLink('type', {}, undefined, true);
    expect(mounted.host.textContent).toContain('Loading inventory');
    expect(entries()).toEqual(['Credentials7']);
  });

  it('puts host links in a list of their own under By type', () => {
    withLink('type');
    const pages = mounted.host.querySelector('nav ul[aria-label="Pages"]');
    expect(pages?.querySelectorAll('li')).toHaveLength(1);
    expect(pages?.textContent).toBe('Credentials7');
  });

  it('selects a harness on click and marks the current one', () => {
    const onSelectHarness = vi.fn();
    mount('harness', { onSelectHarness });
    const buttons = [...mounted.host.querySelectorAll('nav li button')];
    expect(buttons[0]?.getAttribute('aria-current')).toBe('true');
    act(() => {
      (buttons[1] as HTMLButtonElement).click();
    });
    expect(onSelectHarness).toHaveBeenCalledWith('cursor');
  });

  describe('while one list has landed and another has not', () => {
    function mountPartial(
      view: 'harness' | 'type',
      landed: {
        harnesses?: HarnessSummary[];
        projects?: ProjectSummary[];
        assetGroups?: AssetGroup[];
        unavailable?: InventoryNavUnavailable;
      },
      isLoading = true,
    ): void {
      renderRoot(
        mounted.root,
        <InventoryNav
          harnesses={landed.harnesses ?? []}
          projects={landed.projects ?? []}
          assetGroups={landed.assetGroups ?? []}
          unavailable={landed.unavailable}
          isLoading={isLoading}
          view={view}
          onView={vi.fn()}
          harness="claudecode"
          type="project"
          onSelectHarness={vi.fn()}
          onSelectType={vi.fn()}
        />,
      );
    }

    it('says it is loading, not that no harness was detected, while the harness read is still out', () => {
      mountPartial('harness', { projects: [PROJECT], assetGroups: GROUPS });
      expect(mounted.host.textContent).toContain('Loading inventory');
      expect(mounted.host.textContent).not.toContain('No harnesses detected');
    });

    it('claims no attention total, since the lists it would add up are incomplete', () => {
      mountPartial('harness', { projects: [PROJECT], assetGroups: GROUPS });
      expect(mounted.host.textContent).not.toContain('to review');
      expect(mounted.host.textContent).not.toContain('All clear');
    });

    it('leaves a type count unknown rather than zero until that type\u2019s list lands', () => {
      mountPartial('type', { harnesses: HARNESSES, projects: [PROJECT] });
      expect(entries()).toEqual([
        'Projects1',
        'Skills\u2014',
        'MCP servers\u2014',
        'Hooks\u2014',
        'Configuration\u2014',
      ]);
    });

    it('lists the harnesses as soon as they land, with the other reads still out', () => {
      mountPartial('harness', { harnesses: HARNESSES });
      expect(entries()).toEqual(['CCClaude Code2', 'CuCursor0']);
      expect(mounted.host.textContent).not.toContain('Loading inventory');
    });

    it('says no harness was detected once the read is in and found none', () => {
      mountPartial('harness', { projects: [PROJECT], assetGroups: GROUPS }, false);
      expect(mounted.host.textContent).toContain('No harnesses detected');
      expect(mounted.host.textContent).not.toContain('Loading inventory');
    });
  });

  describe('when a read fails', () => {
    const FAILED = "Couldn't load the harnesses. Please try again.";

    function mountFailed(
      view: 'harness' | 'type',
      unavailable: InventoryNavUnavailable,
      isLoading = false,
    ): void {
      renderRoot(
        mounted.root,
        <InventoryNav
          harnesses={[]}
          projects={[PROJECT]}
          assetGroups={[]}
          unavailable={unavailable}
          isLoading={isLoading}
          view={view}
          onView={vi.fn()}
          harness="claudecode"
          type="project"
          onSelectHarness={vi.fn()}
          onSelectType={vi.fn()}
        />,
      );
    }

    it('shows why the harness list is missing instead of saying none was detected', () => {
      mountFailed('harness', { harnesses: FAILED });
      expect(mounted.host.textContent).toContain(FAILED);
      expect(mounted.host.textContent).not.toContain('No harnesses detected');
    });

    it('keeps saying why while a sibling read is still out', () => {
      mountFailed('harness', { harnesses: FAILED }, true);
      expect(mounted.host.textContent).toContain(FAILED);
      expect(mounted.host.textContent).not.toContain('No harnesses detected');
      expect(mounted.host.textContent).not.toContain('Loading inventory');
    });

    it('leaves the asset counts unknown and the total a lower bound', () => {
      mountFailed('type', { assets: FAILED });
      expect(entries()).toEqual([
        'Projects1',
        'Skills\u2014',
        'MCP servers\u2014',
        'Hooks\u2014',
        'Configuration\u2014',
      ]);
      expect(mounted.host.textContent).toContain('At least 1 to review');
      expect(mounted.host.textContent).not.toContain('All clear');
    });

    it('counts the lists that are in, so one failed read does not hide the others', () => {
      renderRoot(
        mounted.root,
        <InventoryNav
          harnesses={HARNESSES}
          projects={[]}
          assetGroups={GROUPS}
          unavailable={{ projects: FAILED }}
          view="type"
          onView={vi.fn()}
          harness="claudecode"
          type="project"
          onSelectHarness={vi.fn()}
          onSelectType={vi.fn()}
        />,
      );
      expect(entries()).toEqual([
        'Projects\u2014',
        'Skills0',
        'MCP servers1',
        'Hooks0',
        'Configuration0',
      ]);
      expect(mounted.host.textContent).toContain('At least 1 to review');
    });
  });

  describe('when the host cannot read the asset lists', () => {
    const REASON = 'You do not have enough permissions.';

    it('claims no total, only a lower bound from the projects it can read', () => {
      mount('type', {}, REASON);
      expect(mounted.host.textContent).toContain('At least 1 to review');
      expect(mounted.host.textContent).not.toContain('All clear');
      expect(mounted.host.textContent).not.toMatch(/(?<!At least )\b\d+ to review/);
    });

    it('says Not available when nothing it can read needs review', () => {
      renderRoot(
        mounted.root,
        <InventoryNav
          harnesses={HARNESSES}
          projects={[]}
          assetGroups={GROUPS}
          view="type"
          onView={vi.fn()}
          harness="claudecode"
          type="project"
          onSelectHarness={vi.fn()}
          onSelectType={vi.fn()}
          unavailable={refused(REASON)}
        />,
      );
      expect(mounted.host.textContent).toContain('Not available');
      expect(mounted.host.textContent).not.toContain('to review');
      expect(mounted.host.textContent).not.toContain('All clear');
    });

    it('shows the reason instead of a harness list', () => {
      mount('harness', {}, REASON);
      expect(mounted.host.textContent).toContain(REASON);
      expect(mounted.host.textContent).not.toContain('No harnesses detected');
      expect(mounted.host.querySelectorAll('nav li')).toHaveLength(0);
    });

    it('counts projects but no asset type it could not read', () => {
      mount('type', {}, REASON);
      expect(entries()).toEqual([
        'Projects1',
        'Skills—',
        'MCP servers—',
        'Hooks—',
        'Configuration—',
      ]);
    });
  });
});
