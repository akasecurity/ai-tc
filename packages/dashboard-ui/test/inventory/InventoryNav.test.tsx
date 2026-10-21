// @vitest-environment jsdom
import type { AssetGroup, HarnessSummary, ProjectSummary } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InventoryNav } from '../../src/inventory/InventoryNav.tsx';
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
      assetsRefusal={assetsRefusal}
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

  it('lists a host link after the types, counts its attention, and opens it on click', () => {
    const onSelect = vi.fn();
    renderRoot(
      mounted.root,
      <InventoryNav
        harnesses={HARNESSES}
        projects={[PROJECT]}
        assetGroups={GROUPS}
        view="type"
        onView={vi.fn()}
        harness="claudecode"
        type="project"
        onSelectHarness={vi.fn()}
        onSelectType={vi.fn()}
        links={[
          {
            key: 'credentials',
            label: 'Credentials',
            icon: 'key',
            fg: 'text-sev-high-ink',
            bg: 'bg-sev-high-fill',
            count: 7,
            attention: 3,
            onSelect,
          },
        ]}
      />,
    );
    expect(entries().at(-1)).toBe('Credentials7');
    expect(mounted.host.textContent).toContain('5 to review');
    const last = [...mounted.host.querySelectorAll('nav li button')].at(-1) as HTMLButtonElement;
    expect(last.getAttribute('aria-current')).toBeNull();
    act(() => {
      last.click();
    });
    expect(onSelect).toHaveBeenCalledTimes(1);
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

  describe('when the host cannot read the asset lists', () => {
    const REASON = 'You do not have enough permissions.';

    it('claims no review count, clean or otherwise', () => {
      mount('type', {}, REASON);
      expect(mounted.host.textContent).toContain('Not available');
      expect(mounted.host.textContent).not.toContain('All clear');
      expect(mounted.host.textContent).not.toContain('to review');
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
