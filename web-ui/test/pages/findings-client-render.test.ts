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
// the limit: anything inside a Radix popover (every filter's own options and
// their counts) never reaches the markup, because a static render never opens
// one.
import type {
  FindingFacets,
  FindingInstanceDetail,
  FindingTypeSummary,
  ListFindingInstancesResponse,
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
    expect(html).toContain('6,456');
    expect(html).toContain('2</span> types');
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

  it('renders the locations view without a toolbar, which has no facets of its own', () => {
    const html = render({
      view: 'files',
      locations: { totals: { repos: 0, files: 0, findings: 0 }, items: [], nextCursor: null },
    });
    expect(html).not.toContain('Search findings…');
    expect(html).not.toContain('Search types…');
  });

  it('shows the session scope chip and keeps a way back to Activity', () => {
    const html = grouped({ session: 'sess-1' });
    expect(html).toContain('Showing findings enforced live in session');
    expect(html).toContain('sess-1');
    expect(html).toContain('/activity?id=sess-1');
  });
});
