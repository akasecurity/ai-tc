// @vitest-environment jsdom
//
// accessRefusal covers the drawer's one RadioCardList (the "LLM access"
// section). Proves: (1) aria-disabled without native disabled on every
// option, (2) a visible reason linked via aria-describedby, (3) onChange
// never reached on a real click, and that omitting the prop changes
// nothing.
//
// `FileDetailDrawer` renders `SheetHeader`/`SheetTitle`, and `SheetTitle` is
// Radix `Dialog.Title` — it throws outside a `Dialog`/`Sheet` context, which
// is why every real caller (see `web-ui`'s InventoryClient) renders this
// component inside `<Sheet><SheetContent>`. Mounting it bare here would
// throw before any assertion ran, so this suite wraps it the same way and
// queries through `document`, since `SheetContent` portals its children out
// of the host div (FindingDetailView.test.tsx is the existing pattern this
// follows).
import type { FileDetail } from '@akasecurity/schema';
import { Sheet, SheetContent } from '@akasecurity/ui-kit';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { FileDetailDrawer } from '../../src/inventory/FileDetailDrawer.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

function fileDetail(overrides: Partial<FileDetail> = {}): FileDetail {
  return {
    path: 'src/index.ts',
    name: 'index.ts',
    origin: 'source',
    access: 'approved',
    isCustom: false,
    findings: 0,
    project: {
      repo: 'acme/api',
      visibility: 'private',
      language: 'TypeScript',
      policyDefault: 'approved',
      updatedAt: '2026-01-01T00:00:00.000Z',
    },
    findingsRefs: [],
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

function mountDrawer(ui: React.ReactElement): void {
  renderRoot(
    mounted.root,
    <Sheet open>
      <SheetContent>{ui}</SheetContent>
    </Sheet>,
  );
}

beforeEach(() => {
  mounted = mountRoot();
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

describe('FileDetailDrawer LLM-access picker, live', () => {
  it('reaches onChange on a real click', () => {
    const onChange = vi.fn();
    mountDrawer(<FileDetailDrawer file={fileDetail()} onChange={onChange} />);

    act(() => {
      optionButton(document.body, 'No LLM').click();
    });

    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith('blocked');
  });
});

describe('FileDetailDrawer LLM-access picker, refused', () => {
  it('refuses every option: aria-disabled, reason visible and linked, onChange never called', () => {
    const onChange = vi.fn();
    mountDrawer(
      <FileDetailDrawer file={fileDetail()} onChange={onChange} accessRefusal={REASON} />,
    );

    const button = optionButton(document.body, 'No LLM');
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-disabled')).toBe('true');
    expect(button.getAttribute('title')).toBe(REASON);
    expect(describedReason(button)).toBe(REASON);

    act(() => {
      button.click();
    });
    expect(onChange).not.toHaveBeenCalled();

    // Every option is refused, not only the one clicked.
    const approvedButton = optionButton(document.body, 'Approved only');
    expect(approvedButton.getAttribute('aria-disabled')).toBe('true');
    act(() => {
      approvedButton.click();
    });
    expect(onChange).not.toHaveBeenCalled();

    expect(
      document.querySelector('[data-slot="radio-card-list-refusal-reason"]')?.textContent,
    ).toBe(REASON);
  });
});
