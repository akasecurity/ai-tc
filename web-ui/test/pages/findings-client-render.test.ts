// The findings route's own wiring, which lives in a client component and so is
// invisible to both neighbouring suites: the page suite reads the props the
// server hands down, and dashboard-ui pins each view in isolation. Neither can
// see how this route composes them.
//
// Three joins live here and each fails quietly:
//   - which filters reach which panel (severity narrows types, provider/action/
//     status narrow the findings of one type),
//   - what the detail side renders when there is no type to show, which differs
//     between an empty STORE and an empty RESULT,
//   - and whether the panel draws ONE card, since a caller that wraps the table
//     to add a title strip draws a second border around the first.
//
// Renders are static: renderToStaticMarkup runs no effects and fires no
// handlers, so this covers what the route puts on the page, not what clicking
// it does. That is the half the other two suites cannot reach — and it is also
// the limit. Anything inside a Radix popover (every filter's own options and
// their counts) never reaches the markup, because a static render never opens
// one.
//
// The tally's locale behaviour is out of reach for a different reason: the
// separator in `6,456` is the RUNNER's, so the assertion below goes through
// toLocaleString rather than a literal. That the mismatch is ACKNOWLEDGED — a
// doc line on `Tally`, the form HarnessOverview's formatEvent uses — is a
// property of the source, and this suite reads markup. Nothing here pins it.
import type {
  FindingFacets,
  FindingInstanceDetail,
  FindingLocationSummary,
  FindingTypeSummary,
  ListFindingInstancesResponse,
  ListFindingLocationsResponse,
  ListFindingTypesResponse,
} from '@akasecurity/schema';
import type React from 'react';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

// FindingsClient reaches the router through the shared navigation hook, which
// throws outside a real Next app. Nothing calls it under a static render.
vi.mock('next/navigation', () => ({
  usePathname: () => '/findings',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { FindingsClient } = await import('../../app/(app)/findings/FindingsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const AWS = 'secrets/aws-access-key';
const TODO = 'code/todo-note';

const EMPTY_FILTERS = { severity: [], type: [], provider: [], action: [], status: [] };

function facets(over: Partial<FindingFacets> = {}): FindingFacets {
  return {
    severity: [{ value: 'critical', count: 1 }],
    subtype: [{ value: AWS, count: 1 }],
    provider: [{ value: 'claudecode', count: 4 }],
    action: [{ value: 'blocked', count: 3 }],
    status: [{ value: 'open', count: 2 }],
    ...over,
  };
}

function type(id: string, over: Partial<FindingTypeSummary> = {}): FindingTypeSummary {
  return {
    id,
    category: 'secret',
    subtype: id,
    severity: 'critical',
    detection: { id, name: null },
    policy: { id: 'category:secret', name: 'secret' },
    instanceCount: 42,
    providers: ['claudecode'],
    aggregateAction: 'blocked',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    status: 'open',
    ...over,
  };
}

function instance(id: string, groupId = AWS): FindingInstanceDetail {
  return {
    id,
    groupId,
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/config.ts',
    toolName: 'Bash',
    action: 'blocked',
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 1,
    status: 'open',
    category: 'secret',
    subtype: groupId,
    severity: 'critical',
    match: { maskedValue: `MASK-${id}`, contextPrefix: '' },
    detection: { id: groupId, name: null },
    policy: { id: 'category:secret', name: 'secret' },
  };
}

function types(items: FindingTypeSummary[]): ListFindingTypesResponse {
  return {
    totals: { findings: 6456, types: items.length },
    facets: facets(),
    items,
    nextCursor: null,
  };
}

function instances(items: FindingInstanceDetail[]): ListFindingInstancesResponse {
  return {
    totals: { findings: items.length },
    // Deliberately different from the type list's counts above. Not assertable
    // through the markup (see the header), but it keeps the fixture honest: the
    // panel's controls are fed from THIS read, not the list's.
    facets: facets({ provider: [{ value: 'claudecode', count: 41 }] }),
    items,
    nextCursor: null,
  };
}

function location(over: Partial<FindingLocationSummary> = {}): FindingLocationSummary {
  return {
    id: 'acme%2Fapi/cfg%2F.env',
    repo: 'acme/api',
    file: 'cfg/.env',
    instanceCount: 12,
    maxSeverity: 'critical',
    latestDetectedAt: '2026-01-01T22:00:00.000Z',
    status: 'open',
    ruleIds: [AWS],
    ...over,
  };
}

function locations(items: FindingLocationSummary[]): ListFindingLocationsResponse {
  return {
    totals: { findings: 6456, locations: items.length },
    facets: facets(),
    items,
    nextCursor: null,
  };
}

const COMMON = {
  filters: EMPTY_FILTERS,
  query: '',
  session: '',
  range: null,
  from: null,
  tools: [],
  repo: '',
  file: '',
  renderedAt: Date.parse('2026-01-02T00:00:00.000Z'),
};

function render(props: Record<string, unknown>): string {
  return renderToStaticMarkup(
    createElement(
      NavigationTransitionProvider,
      null,
      // Each case supplies one whole arm of the view union; the spread cannot
      // prove that to the compiler, so it is cast at the seam.
      createElement(FindingsClient as unknown as React.FC<Record<string, unknown>>, {
        ...COMMON,
        ...props,
      }),
    ),
  );
}

function grouped(over: Record<string, unknown> = {}): string {
  return render({
    view: 'grouped',
    types: types([type(AWS), type(TODO, { severity: 'low', instanceCount: 7 })]),
    instances: instances([instance('f1'), instance('f2')]),
    selectedRule: AWS,
    deepLinkedInstance: null,
    ...over,
  });
}

function files(over: Record<string, unknown> = {}): string {
  const items = [location(), location({ id: 'other', file: 'src/db.ts', maxSeverity: 'high' })];
  return render({
    view: 'files',
    locations: locations(items),
    instances: instances([instance('f1'), instance('f2')]),
    selectedLocation: items[0],
    deepLinkedInstance: null,
    ...over,
  });
}

describe('findings client — the By-type view', () => {
  it('puts the type-narrowing controls with the types and the rest with the findings', () => {
    const html = grouped();

    // Types panel: its own search, and severity — a property of the rule.
    expect(html).toContain('Search types…');
    expect(html).toContain('>critical<');
    // Findings panel: the three that vary between one type's findings.
    for (const label of ['Provider', 'Action', 'Status']) {
      expect(html).toContain(`>${label}<`);
    }
    // No page-wide toolbar: the flat view's search would be a second control
    // writing the same `?q=`, and Type would let the filter and the selection
    // disagree about which type is showing.
    expect(html).not.toContain('Search findings…');
    expect(html).not.toContain('>Type<');
  });

  // NOTE: which facets those three are counted against is NOT assertable here.
  // The per-option counts live inside a Radix popover, and a static render never
  // opens one — only the triggers reach the markup. That join is covered by the
  // panel receiving `instances.facets` at its one call site.
  it('states the selected type’s own finding count in the panel paginator', () => {
    // The panel pages the type's findings; the list beside it pages types. Two
    // different units, so the two paginators must not read alike.
    const html = grouped();
    expect(html).toContain('1–2 of 2 findings');
    expect(html).toContain('1–2 of 2 types');
  });

  it('names the selected type once, and draws ONE card around the findings', () => {
    const html = grouped();
    expect(html).toContain(AWS);
    // Two cards here means two borders and two radii where the header meets the
    // table — the panel wraps nothing, the table carries the header itself.
    const cards = html.match(/data-slot="card"/g) ?? [];
    expect(cards).toHaveLength(2); // the types list, and the findings panel
  });

  it('says why the detail side is empty rather than showing a blank card', () => {
    // The filter is what makes this case: `emptyState` is supplied only for an
    // EMPTY STORE, so with one active it is undefined, and rendering it alone
    // left a bordered box with no text in it at all.
    const html = grouped({
      filters: { ...EMPTY_FILTERS, severity: ['critical'] },
      types: types([]),
      instances: null,
      selectedRule: '',
    });
    expect(html).toContain('No types match these filters.');
    expect(html).not.toContain('No findings yet');
  });

  it('shows the onboarding hint instead when nothing is filtered', () => {
    // The control for the case above: an empty STORE is a different answer from
    // an empty RESULT, and the page must not tell a first-run user their filters
    // matched nothing.
    const html = grouped({ types: types([]), instances: null, selectedRule: '' });
    expect(html).toContain('No findings yet');
    expect(html).not.toContain('No types match these filters.');
  });

  it('carries the page tally under the title, away from the filters', () => {
    const html = grouped();
    expect(html).toContain('Every sensitive-data finding across providers');
    // The findings total spans every listed type; the type count is the list's
    // own length. Both describe the whole scope, which is why they sit here and
    // not beside a filter that cannot move them.
    //
    // Asserted THROUGH toLocaleString rather than against a literal `6,456`:
    // the thousands separator is the RUNNER's, so a hardcoded one fails
    // wherever LANG is not en-*.
    expect(html).toContain((6456).toLocaleString());
    expect(html).toContain('types');
  });
});

// P1: the flat tally's two halves must answer the same question. `facets.subtype`
// is computed with its OWN dimension excluded, so read as a scope count it
// reports every rule in the store while the findings half is filtered. An empty
// `type` filter makes that self-exclusion a no-op, which is why this case sets
// a non-empty one — the only shape that binds the expression.
describe('findings client — the flat tally under a type filter', () => {
  const threeRules = [
    { value: AWS, count: 3 },
    { value: TODO, count: 9 },
    { value: 'pii/email', count: 5 },
  ];

  it('counts only the types the filter selected', () => {
    const html = render({
      view: 'flat',
      filters: { ...EMPTY_FILTERS, type: [AWS] },
      flat: {
        ...instances([instance('f1')]),
        totals: { findings: 3 },
        facets: facets({ subtype: threeRules }),
      },
    });
    expect(html).toContain('1</span> type');
    // The unfiltered rule count must not reach the page.
    expect(html).not.toContain('3</span> types');
  });

  it('falls back to every rule in scope when no type is filtered', () => {
    const html = render({
      view: 'flat',
      filters: EMPTY_FILTERS,
      flat: {
        ...instances([instance('f1')]),
        totals: { findings: 17 },
        facets: facets({ subtype: threeRules }),
      },
    });
    expect(html).toContain('3</span> types');
  });
});

describe('findings client — the other views', () => {
  it('gives the flat view the full toolbar it can honour', () => {
    const html = render({ view: 'flat', flat: instances([instance('f1')]) });
    // Every dimension narrows the one list here, so all of them belong.
    expect(html).toContain('Search findings…');
    for (const label of ['Severity', 'Type', 'Provider', 'Action', 'Status']) {
      expect(html).toContain(`>${label}<`);
    }
  });

  // The inverse of the By-type case above, and the inverse of what this view
  // used to do. Every dimension narrows BOTH of its reads, because a location
  // owns none of the fields on its row, so all of them belong in one toolbar
  // over the pair rather than split between the panels.
  it('gives the locations view the whole toolbar, and puts none of it in the panel', () => {
    const html = files();

    expect(html).toContain('Search findings…');
    for (const label of ['Severity', 'Type', 'Provider', 'Action', 'Status']) {
      expect(html).toContain(`>${label}<`);
    }
    // FIVE filter popovers and no more. Counting the label text would count the
    // findings table's own column headers too — `>Provider<` appears twice for
    // that reason alone — so this counts the popover triggers, which only a
    // filter renders. A sixth would be the panel growing its own copy of a
    // control that writes the same param as the one above it.
    expect((html.match(/aria-haspopup="dialog"/g) ?? []).length).toBe(5);
    // And no second search box: the list has no search of its own here, unlike
    // the type list, because the toolbar's already writes the same `?q=`.
    expect(html).not.toContain('Search types…');
  });

  it("pairs the location list with the selected location's findings", () => {
    const html = files();

    // Left: the location rows, repo as context and file as the subject.
    expect(html).toContain('acme/api');
    expect(html).toContain('cfg/.env');
    expect(html).toContain('src/db.ts');
    // Right: the panel names what it is showing, and lists that location's
    // findings.
    expect(html).toContain('MASK-f1');
    // Two cards, not a border inside a border: the panel's header is a slot in
    // the table's own card rather than a wrapper around it.
    expect((html.match(/data-slot="card"/g) ?? []).length).toBe(2);
  });

  // Two different empties, and the panel has to tell them apart the way the list
  // does. With filters active the store may be full and the query simply
  // fruitless; with none active the store itself is empty and the reader needs
  // the onboarding hint instead.
  it('mirrors the list rather than leaving a blank card beside it', () => {
    const filtered = files({
      locations: locations([]),
      instances: null,
      selectedLocation: null,
      filters: { ...EMPTY_FILTERS, severity: ['critical'] },
    });
    expect(filtered).toContain('No locations match these filters');

    const emptyStore = files({
      locations: locations([]),
      instances: null,
      selectedLocation: null,
    });
    expect(emptyStore).toContain('No findings yet');
  });

  it('counts LOCATIONS in the tally, and does not call them types', () => {
    const html = files();
    // Scoped to the subtitle rather than the whole document: an absence
    // assertion over the page would redden for any unrelated label that happened
    // to contain the word, pointing a reader at the tally when nothing about it
    // had changed.
    const sub = /<p[^>]*>((?:(?!<\/p>).)*findings(?:(?!<\/p>).)*)<\/p>/.exec(html)?.[1] ?? '';
    expect(sub, 'no subtitle found to read the tally from').not.toBe('');
    expect(sub).toContain((6456).toLocaleString());
    expect(sub).toContain('locations');
    expect(sub).not.toContain('types');
  });

  it('shows the session scope chip and keeps a way back to Activity', () => {
    const html = grouped({ session: 'sess-1' });
    expect(html).toContain('Showing findings enforced live in session');
    expect(html).toContain('sess-1');
    expect(html).toContain('/activity?id=sess-1');
  });
});
