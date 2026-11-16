// @vitest-environment jsdom
import type {
  AssetSummary,
  DetectionListItem,
  FindingFacets,
  FindingTypeSummary,
} from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ToolChip } from '../../src/activity/atoms.tsx';
import { CredentialsListView } from '../../src/credentials/CredentialsListView.tsx';
import { DetectionsListView } from '../../src/detections/DetectionsListView.tsx';
import { FindingsToolbarView } from '../../src/findings/FindingsToolbarView.tsx';
import { FindingTypesListView } from '../../src/findings/FindingTypesListView.tsx';
import { EMPTY_FILTERS } from '../../src/findings/meta.ts';
import { InventoryNav } from '../../src/inventory/InventoryNav.tsx';
import { InventoryTable } from '../../src/inventory/InventoryTable.tsx';
import { ChipCount } from '../../src/shared/ChipCount.tsx';
import { accessibleName, visibleText } from '../helpers/accessible-name.ts';
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

/**
 * The one button whose name starts with `prefix`. Searched in the whole
 * document, because a popover's content is portalled out of the mounted host.
 */
function control(prefix: string): HTMLElement {
  const matches = [...document.querySelectorAll('button, a')].filter((b) =>
    accessibleName(b).startsWith(prefix),
  );
  expect(matches).toHaveLength(1);
  const [el] = matches;
  if (!(el instanceof HTMLElement)) throw new Error(`no "${prefix}" control`);
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

const DETECTION: DetectionListItem = {
  id: 'aka/secrets',
  name: 'Secrets',
  version: '1.0.0',
  enabled: true,
  origin: 'library',
  ruleCount: 1234,
  namespace: 'aka',
  packId: 'secrets',
  policyId: 'monitor',
};

const FINDING_TYPE: FindingTypeSummary = {
  id: 'aws-key',
  category: 'secret',
  subtype: 'aws-key',
  severity: 'critical',
  detection: { id: 'aws-key', name: null },
  policy: { id: 'category:secret', name: 'secret' },
  instanceCount: 1234,
  providers: ['claudecode'],
  aggregateAction: 'blocked',
  latestDetectedAt: '2026-01-01T00:00:00.000Z',
  status: 'open',
};

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
            attention: 1234,
            onSelect: vi.fn(),
          },
          {
            key: 'pending',
            label: 'Pending',
            icon: 'key',
            fg: 'text-text-3',
            bg: 'bg-surface-2',
            // Outside the prop type, as a host built without it could pass.
            count: undefined as unknown as null,
            attention: 0,
            onSelect: vi.fn(),
          },
        ]}
      />,
    );
    // The attention dot is named by its label, so it needs a separator of its own;
    // its number is formatted like the count beside it.
    expectControl('Credentials', 'Credentials, 1.234 need attention, 1.234', 'Credentials1.234');
    // The dot is named only because it is an image: a bare span's label is ignored.
    const dot = control('Credentials').querySelector('[aria-label$="need attention"]');
    expect(dot?.getAttribute('role')).toBe('img');
    expect(dot?.getAttribute('title')).toBe('1.234 need attention');
    expectControl('Pending', 'Pending', 'Pending\u2014');
    // An unknown count is a visible dash with nothing to announce.
    expectControl('Skills', 'Skills', 'Skills\u2014');
  });

  it('inventory nav: the attention total, partial and whole, in the same convention', () => {
    const nav = (unavailable?: { assets: string; projects: string }) => (
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
        unavailable={unavailable}
        links={[
          {
            key: 'credentials',
            label: 'Credentials',
            icon: 'key',
            fg: 'text-sev-high-ink',
            bg: 'bg-sev-high-fill',
            count: 1,
            attention: 1234,
            onSelect: vi.fn(),
          },
        ]}
      />
    );
    renderRoot(mounted.root, nav({ assets: 'Not permitted', projects: 'Not permitted' }));
    expect(mounted.host.textContent).toContain('At least 1.234 to review');
    renderRoot(mounted.root, nav());
    expect(mounted.host.textContent).toContain('1.234 to review');
    expect(mounted.host.textContent).not.toContain('At least');
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
        items={[DETECTION]}
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
    // The row's rule count is formatted like the chips above it.
    expect(control('Secrets').textContent).toContain('1.234 rules');
  });

  it('finding types: the severity filters', () => {
    renderRoot(
      mounted.root,
      <FindingTypesListView
        locale="de-DE"
        types={[FINDING_TYPE]}
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
    // A type row joins three fields, each kept apart in the name.
    expectControl('aws-key', 'aws-key, Secret, 1.234', 'aws-keySecret1.234');
  });

  it('session detail: a tool chip that links to its findings', () => {
    renderRoot(
      mounted.root,
      <ToolChip name="Bash" n={1234} href="/findings?tool=Bash" locale="de-DE" />,
    );
    // `title` is not consulted: content names a link before its title does.
    expectControl('Bash', 'Bash, 1.234', 'Bash1.234');
  });
});
