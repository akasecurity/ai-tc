// @vitest-environment jsdom
//
// accessRefusal covers every per-file access control this pane renders: the
// browse/search table's AccessControl AND the "Recently blocked" strip's —
// a blocked file inside the browsed directory renders in BOTH at once. This
// proves, for both call sites: (1) aria-disabled without native disabled,
// (2) a visible reason linked via aria-describedby, (3) onSetAccess never
// reached on a real click, and that omitting the prop changes nothing.
import type { FileSummary, ProjectSummary, ProjectTreeResponse } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ProjectPane, type ProjectPaneProps } from '../../src/inventory/ProjectPane.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

function proj(overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return {
    id: 'proj_1',
    name: 'api',
    repo: 'acme/api',
    visibility: 'private',
    language: 'TypeScript',
    policyDefault: 'approved',
    updatedAt: '2026-01-01T00:00:00.000Z',
    accessCounts: { open: 0, approved: 1, blocked: 0, total: 1 },
    findingsCount: 0,
    ...overrides,
  };
}

function file(overrides: Partial<FileSummary> = {}): FileSummary {
  return {
    path: 'src/index.ts',
    name: 'index.ts',
    origin: 'source',
    access: 'approved',
    isCustom: false,
    findings: 0,
    ...overrides,
  };
}

function baseProps(overrides: Partial<ProjectPaneProps> = {}): ProjectPaneProps {
  const p = proj();
  const tree: ProjectTreeResponse = {
    project: { id: p.id, repo: p.repo, visibility: p.visibility },
    path: '',
    folders: [],
    files: [file()],
  };
  return {
    proj: p,
    path: [],
    onPathChange: vi.fn(),
    query: '',
    onQueryChange: vi.fn(),
    tree,
    isLoading: false,
    error: null,
    onSetAccess: vi.fn(),
    onOpenFile: vi.fn(),
    drawerPath: null,
    blocked: [],
    showBlocked: false,
    onToggleBlocked: vi.fn(),
    ...overrides,
  };
}

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

function toggleOption(title: string): HTMLButtonElement {
  const el = mounted.host.querySelector(`button[title="${title}"]`);
  if (!(el instanceof HTMLButtonElement)) throw new Error(`no "${title}" toggle option rendered`);
  return el;
}

function refusedControls(): HTMLButtonElement[] {
  return [
    ...mounted.host.querySelectorAll<HTMLButtonElement>('button[data-slot="access-control"]'),
  ];
}

function describedReason(el: HTMLElement): string | null {
  const id = el.getAttribute('aria-describedby');
  if (id === null) return null;
  return document.getElementById(id)?.textContent ?? null;
}

const REASON = 'You do not have enough permissions.';

describe('ProjectPane per-file access control, live', () => {
  it('reaches onSetAccess on a real click', () => {
    const onSetAccess = vi.fn();
    mount(<ProjectPane {...baseProps({ onSetAccess })} />);

    act(() => {
      toggleOption('No LLM').click();
    });

    expect(onSetAccess).toHaveBeenCalledTimes(1);
    expect(onSetAccess).toHaveBeenCalledWith('src/index.ts', 'blocked');
    expect(refusedControls()).toHaveLength(0);
  });
});

describe('ProjectPane per-file access control, refused', () => {
  it('refuses the table control: aria-disabled, reason visible and linked, onSetAccess never called', () => {
    const onSetAccess = vi.fn();
    mount(<ProjectPane {...baseProps({ onSetAccess, accessRefusal: REASON })} />);

    const buttons = refusedControls();
    expect(buttons).toHaveLength(1);
    const button = buttons[0];
    if (button === undefined) throw new Error('no refused access control rendered');
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);
    expect(button.getAttribute('aria-label')).toBe('LLM access: Approved only');

    act(() => {
      button.click();
    });
    expect(onSetAccess).not.toHaveBeenCalled();
  });

  it('refuses the blocked-strip control too, independently of the same file in the table', () => {
    const onSetAccess = vi.fn();
    const blockedFile = file({
      path: 'src/secret.env',
      name: 'secret.env',
      access: 'blocked',
      blockedAt: '2026-01-01T00:00:00.000Z',
      note: 'Detected secret',
    });
    mount(
      <ProjectPane
        {...baseProps({
          onSetAccess,
          blocked: [blockedFile],
          showBlocked: true,
          accessRefusal: REASON,
        })}
      />,
    );

    // One in the browse table (src/index.ts) and one in the blocked strip
    // (src/secret.env) — two distinct controls, not one shared by both.
    const buttons = refusedControls();
    expect(buttons).toHaveLength(2);
    for (const button of buttons) {
      expect(button.getAttribute('aria-disabled')).toBe('true');
      act(() => {
        button.click();
      });
    }
    expect(onSetAccess).not.toHaveBeenCalled();
  });
});
