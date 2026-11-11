// @vitest-environment jsdom
import type { AssetSummary, FindingFacets } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CredentialsListView } from '../../src/credentials/CredentialsListView.tsx';
import { DetectionsListView } from '../../src/detections/DetectionsListView.tsx';
import { FindingsToolbarView } from '../../src/findings/FindingsToolbarView.tsx';
import { FindingTypesListView } from '../../src/findings/FindingTypesListView.tsx';
import { EMPTY_FILTERS } from '../../src/findings/meta.ts';
import { InventoryNav } from '../../src/inventory/InventoryNav.tsx';
import { InventoryTable } from '../../src/inventory/InventoryTable.tsx';
import { ChipCount } from '../../src/shared/ChipCount.tsx';
import { accessibleName } from '../helpers/accessible-name.ts';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

// Every control that pairs a label with a count must read as separate words to
// a screen reader. The control's flex gap is layout, not text, so it adds
// nothing to the accessible name; the separator has to be real text, and it has
// to be `sr-only` so a sighted reader still sees only the gap. Each control is
// therefore held to two strings: the name a screen reader announces, and the
// text left once `sr-only` content is removed. The first fails when the
// separator is missing, the second when it is visible.

const RENDERED_AT = Date.parse('2026-10-21T12:00:00.000Z');

let mounted: MountedRoot;
beforeEach(() => {
  mounted = mountRoot();
});
afterEach(() => {
  unmountMountedRoot(mounted);
});

/** The text a sighted reader sees: everything except `sr-only` content. */
function visibleText(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? '';
  if (node instanceof Element && node.classList.contains('sr-only')) return '';
  return [...node.childNodes].map(visibleText).join('');
}

/**
 * The one button whose name starts with `prefix`. Searched in the whole
 * document, because a popover's content is portalled out of the mounted host.
 */
function control(prefix: string): HTMLButtonElement {
  const matches = [...document.querySelectorAll('button')].filter((b) =>
    accessibleName(b).startsWith(prefix),
  );
  expect(matches).toHaveLength(1);
  const [el] = matches;
  if (!(el instanceof HTMLButtonElement)) throw new Error(`no "${prefix}" control`);
  return el;
}

/** The control is announced as `name` and shows `visible`. */
function expectControl(prefix: string, name: string, visible: string): void {
  const el = control(prefix);
  // The helper reads names from content; a control named another way would
  // make the assertion below say nothing about what is announced.
  expect(el.hasAttribute('aria-label')).toBe(false);
  expect(el.hasAttribute('aria-labelledby')).toBe(false);
  expect(accessibleName(el)).toBe(name);
  expect(visibleText(el)).toBe(visible);
}

describe('ChipCount', () => {
  it("formats the count in the host's locale", () => {
    renderRoot(
      mounted.root,
      <>
        <ChipCount value={1234} locale="en-US" />
        <ChipCount value={1234} locale="de-DE" />
      </>,
    );
    expect([...mounted.host.children].map((el) => el.textContent)).toEqual([', 1,234', ', 1.234']);
  });

  it('takes its styling from the control it sits in', () => {
    renderRoot(
      mounted.root,
      <ChipCount value={3} locale="en-US" className="tabular-nums opacity-70" />,
    );
    expect(mounted.host.firstElementChild?.getAttribute('class')).toBe('tabular-nums opacity-70');
  });
});

describe('chip accessible names', () => {
  it('credentials: status chips and the dismissed toggle', () => {
    renderRoot(
      mounted.root,
      <CredentialsListView
        locale="de-DE"
        items={[]}
        total={0}
        search=""
        onSearch={vi.fn()}
        onSelect={vi.fn()}
        onExport={vi.fn()}
        onNextPage={vi.fn()}
        onPreviousPage={vi.fn()}
        hasNextPage={false}
        hasPreviousPage={false}
        pageStart={1}
        renderedAt={RENDERED_AT}
        onStatus={vi.fn()}
        status={null}
        statusCounts={{
          all: 1234,
          byStatus: { exposed: 4, rotation_overdue: 0 },
        }}
        onDismissedChange={vi.fn()}
        dismissedCount={2}
      />,
    );
    expectControl('All', 'All, 1.234', 'All1.234');
    expectControl('Dismissed', 'Dismissed, 2', 'Dismissed2');
  });

  function skill(id: string, flags: AssetSummary['flags'] = []): AssetSummary {
    return {
      id,
      type: 'skill',
      name: id,
      sub: 'Skill',
      flags,
      meta: { source: 'acme/skills', scope: 'user', installedVersion: '1.0.0' },
    };
  }

  function inventory(type: 'skill' | null): void {
    renderRoot(
      mounted.root,
      <InventoryTable
        title="Claude Code"
        subtitle="sub"
        avatar={null}
        rows={[skill('a', ['update']), skill('b')]}
        type={type}
        searchNoun="inventory"
        onOpen={vi.fn()}
        renderedAt={RENDERED_AT}
        locale="en-US"
      />,
    );
  }

  it('inventory: the All, reason and OK pills of one type', () => {
    inventory('skill');
    expectControl('All', 'All, 2', 'All2');
    expectControl('Update,', 'Update, 1', 'Update1');
    expectControl('OK', 'OK, 1', 'OK1');
  });

  it("inventory: a harness's type pills", () => {
    inventory(null);
    expectControl('Skills', 'Skills, 2', 'Skills2');
  });

  it('inventory nav: a row with attention, and a row whose count is unknown', () => {
    renderRoot(
      mounted.root,
      <InventoryNav
        locale="de-DE"
        harnesses={[]}
        projects={[]}
        assetGroups={[]}
        view="type"
        onView={vi.fn()}
        harness={null}
        type="project"
        onSelectHarness={vi.fn()}
        onSelectType={vi.fn()}
        unavailable={{ assets: 'Not permitted', projects: 'Not permitted' }}
        links={[
          {
            key: 'credentials',
            label: 'Credentials',
            icon: 'key',
            fg: 'text-sev-high-ink',
            bg: 'bg-sev-high-fill',
            count: 1234,
            attention: 3,
            onSelect: vi.fn(),
          },
        ]}
      />,
    );
    // The attention dot is named by its label, so it needs a separator of its own.
    expectControl('Credentials', 'Credentials, 3 need attention, 1.234', 'Credentials1.234');
    // An unknown count is a visible dash with nothing to announce.
    expectControl('Skills', 'Skills', 'Skills\u2014');
  });

  it('findings toolbar: the filter trigger and its options', () => {
    const facets: FindingFacets = {
      severity: [{ value: 'critical', count: 1234 }],
      subtype: [],
      provider: [],
      action: [],
      status: [],
    };
    renderRoot(
      mounted.root,
      <FindingsToolbarView
        facets={facets}
        filters={{ ...EMPTY_FILTERS, severity: ['critical'] }}
        onFiltersChange={vi.fn()}
        query=""
        onQueryChange={vi.fn()}
        locale="de-DE"
      />,
    );
    expectControl('Severity', 'Severity, 1 selected', 'Severity1');
    act(() => {
      control('Severity').click();
    });
    expectControl('Critical', 'Critical, 1.234', 'Critical1.234');
  });

  it('detections: the status filter chips', () => {
    renderRoot(
      mounted.root,
      <DetectionsListView
        items={[]}
        counts={{ all: 1234, updates: 3 }}
        activeId=""
        query=""
        filter="all"
        onQueryChange={vi.fn()}
        onFilterChange={vi.fn()}
        onSelect={vi.fn()}
        filterTabs={[
          ['all', 'All'],
          ['updates', 'Updates'],
        ]}
        locale="de-DE"
      />,
    );
    expectControl('All', 'All, 1.234', 'All1.234');
    // The update arrow is aria-hidden and has no text, so it adds to neither.
    expectControl('Updates', 'Updates, 3', 'Updates3');
  });

  it('finding types: the severity filters', () => {
    renderRoot(
      mounted.root,
      <FindingTypesListView
        locale="de-DE"
        types={[]}
        activeId=""
        onSelect={vi.fn()}
        query=""
        onQueryChange={vi.fn()}
        severityCounts={new Map([['critical', 1234]])}
        selectedSeverities={[]}
        onSeverityChange={vi.fn()}
      />,
    );
    expectControl('critical', 'critical, 1.234', 'critical1.234');
    expectControl('low', 'low, 0', 'low0');
  });
});
