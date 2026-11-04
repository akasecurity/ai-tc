// @vitest-environment jsdom
//
// What the By-type view DOES, which its sibling static-render suite cannot see:
// renderToStaticMarkup fires no handlers, so every click path below is
// invisible there. The environment is opted into per file, as this repo's other
// DOM suite does — the rest of web-ui covers pure helpers, server components and
// static markup, and gains nothing from jsdom but time.
//
// Three things are worth driving rather than reasoning about:
//
//   - Selection and the type-level filters go through the URL, not local state,
//     because the server owns which type is selected. If a handler stopped
//     pushing, the panel would simply never change and nothing would throw.
//   - The findings panel keeps its own page cache. Stepping forward past the
//     frontier fetches; stepping back does not. A cache that re-fetched on every
//     Previous is invisible except as latency.
//   - Paging closes the drawer. Left open, it points at a row the new page no
//     longer contains.
import type {
  FindingContext,
  FindingFacets,
  FindingInstanceDetail,
  FindingLocationSummary,
  FindingTypeSummary,
  ListFindingInstancesResponse,
  ListFindingLocationsResponse,
  ListFindingTypesResponse,
} from '@akasecurity/schema';
import type React from 'react';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  usePathname: () => '/findings',
  useRouter: () => ({ push, replace: vi.fn(), prefetch: vi.fn() }),
}));

// The panel's "Load more" is a Server Action, which cannot run here. Stubbing it
// is what lets the page cache be driven: the assertions below are about how many
// times it is called, and with which cursor.
const loadMoreFindingInstances = vi.fn<(q: unknown) => Promise<ListFindingInstancesResponse>>();
const loadMoreFindingTypes = vi.fn<(q: unknown) => Promise<ListFindingTypesResponse>>();
const loadMoreFindingLocations = vi.fn<(q: unknown) => Promise<ListFindingLocationsResponse>>();
// The drawer's excerpt read. No excerpt unless a case says otherwise.
const loadFindingContextAction = vi.fn<(q: unknown) => Promise<FindingContext | null>>(() =>
  Promise.resolve(null),
);
vi.mock('../../app/(app)/findings/actions', () => ({
  loadFindingContextAction: (q: unknown) => loadFindingContextAction(q),
  loadMoreFindingInstances: (q: unknown) => loadMoreFindingInstances(q),
  loadMoreFindingTypes: (q: unknown) => loadMoreFindingTypes(q),
  loadMoreFindingLocations: (q: unknown) => loadMoreFindingLocations(q),
}));

const { FindingsClient } = await import('../../app/(app)/findings/FindingsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const AWS = 'secrets/aws-access-key';
const TODO = 'code/todo-note';
const EMPTY_FILTERS = {
  severity: [],
  type: [],
  provider: [],
  action: [],
  status: [],
  deployment: [],
};

const FACETS: FindingFacets = {
  severity: [{ value: 'critical', count: 1 }],
  subtype: [{ value: AWS, count: 1 }],
  provider: [{ value: 'claudecode', count: 4 }],
  action: [{ value: 'blocked', count: 3 }],
  status: [{ value: 'open', count: 2 }],
};

function type(id: string): FindingTypeSummary {
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
  };
}

function instance(id: string): FindingInstanceDetail {
  return {
    id,
    groupId: AWS,
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/config.ts',
    action: 'blocked',
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 1,
    status: 'open',
    category: 'secret',
    subtype: AWS,
    severity: 'critical',
    match: { maskedValue: `MASK-${id}`, contextPrefix: '' },
    detection: { id: AWS, name: null },
    policy: { id: 'category:secret', name: 'secret' },
  };
}

const TYPES: ListFindingTypesResponse = {
  totals: { findings: 84, types: 2 },
  facets: FACETS,
  items: [type(AWS), type(TODO)],
  nextCursor: null,
};

function pageOf(ids: string[], nextCursor: string | null): ListFindingInstancesResponse {
  return {
    totals: { findings: 4 },
    facets: FACETS,
    items: ids.map(instance),
    nextCursor,
  };
}

function location(over: Partial<FindingLocationSummary> = {}): FindingLocationSummary {
  return {
    id: 'acme%2Fapi/src%2Fconfig.ts',
    repo: 'acme/api',
    file: 'src/config.ts',
    instanceCount: 12,
    maxSeverity: 'critical',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    status: 'open',
    ruleIds: [AWS],
    ...over,
  };
}

const LOCATIONS: FindingLocationSummary[] = [
  location(),
  location({ id: 'acme%2Fapi/src%2Fdb.ts', file: 'src/db.ts' }),
];

// Facet counts DELIBERATELY different from FACETS above. The toolbar sits over
// both panels here, so which read feeds it is a real question and one that no
// static render can answer — a facet's options live inside a Radix popover,
// which never reaches renderToStaticMarkup.
const LOCATION_FACETS: FindingFacets = {
  severity: [{ value: 'critical', count: 97 }],
  subtype: [{ value: AWS, count: 97 }],
  provider: [{ value: 'claudecode', count: 97 }],
  action: [{ value: 'blocked', count: 97 }],
  status: [{ value: 'open', count: 97 }],
};

function locationsPage(
  items: FindingLocationSummary[],
  nextCursor: string | null,
): ListFindingLocationsResponse {
  return {
    totals: { findings: 24, locations: items.length },
    facets: LOCATION_FACETS,
    items,
    nextCursor,
  };
}

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  push.mockReset();
  loadMoreFindingInstances.mockReset();
  loadMoreFindingTypes.mockReset();
  loadMoreFindingLocations.mockReset();
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

function mount(over: Record<string, unknown> = {}): void {
  act(() => {
    root.render(
      createElement(
        NavigationTransitionProvider,
        null,
        // Each call site supplies one whole arm of the view union; the spread
        // below cannot prove that to the compiler, so it is cast at the seam.
        createElement(FindingsClient as unknown as React.FC<Record<string, unknown>>, {
          filters: EMPTY_FILTERS,
          query: '',
          session: '',
          range: null,
          from: null,
          tools: [],
          repo: '',
          file: '',
          renderedAt: Date.parse('2026-01-02T00:00:00.000Z'),
          locale: 'en-US',
          deployment: null,
          overview: { findings: 0, open: 0, handled: 0, resolved: 0, dismissed: 0 },
          view: 'grouped',
          types: TYPES,
          instances: pageOf(['f1', 'f2'], 'cursor-1'),
          selectedRule: AWS,
          deepLinkedInstance: null,
          ...over,
        }),
      ),
    );
  });
}

/** Click a real node, inside act, the way the browser would. */
function click(el: Element | null | undefined): void {
  expect(el, 'element to click was not found').toBeTruthy();
  act(() => {
    el?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
}

const byText = (
  selector: string,
  text: string,
  within: ParentNode = container,
): Element | undefined =>
  [...within.querySelectorAll(selector)].find((e) => e.textContent.includes(text));

// The page's Cards other than the summary strip, which heads every view as a
// Card of its own and holds no panel.
const panelCards = (): Element[] =>
  [...container.querySelectorAll('[data-slot="card"]')].filter(
    (card) => card.querySelector('[data-slot="summary-stat"]') === null,
  );

// The two panels each have a paginator, and the type list's comes first in the
// markup — an unscoped lookup finds THAT one, which here is disabled and
// swallows the click. Scope every panel query to the second card.
const panel = (): ParentNode => {
  const cards = panelCards();
  expect(cards, 'expected a type list and a findings panel').toHaveLength(2);
  return cards[1] as ParentNode;
};
const typeList = (): ParentNode => panelCards()[0] as ParentNode;
const panelNext = () => byText('button[data-slot="pagination-next"]', 'Next', panel());
const panelPrev = () => byText('button[data-slot="pagination-previous"]', 'Previous', panel());
const fieldIn = (parent: ParentNode): HTMLInputElement => {
  const el = parent.querySelector('input[aria-label="Go to page"]');
  if (!(el instanceof HTMLInputElement)) throw new Error('no page field');
  return el;
};
const jumpIn = async (parent: ParentNode, page: number) => {
  const input = fieldIn(parent);
  await act(async () => {
    // A property descriptor's `set`, applied with an explicit receiver below.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter === undefined) throw new Error('no value setter');
    Reflect.apply(setter, input, [String(page)]);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await Promise.resolve();
  });
  await act(async () => {
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await Promise.resolve();
  });
};
const clickPanelNext = async () => {
  const button = panelNext();
  await act(async () => {
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    // Settle the stubbed action's promise INSIDE act, so the state its
    // continuation sets is flushed before control comes back — otherwise the
    // assertions below read the page as it was before the fetch resolved.
    await Promise.resolve();
  });
};

describe('By-type view — selection and filters ride the URL', () => {
  it('pushes ?rule= when a type is chosen, so the server decides what the panel reads', () => {
    mount();
    click(byText('button[type="button"]', TODO));

    expect(push).toHaveBeenCalledTimes(1);
    const url = String(push.mock.calls[0]?.[0]);
    expect(url).toContain(`rule=${encodeURIComponent(TODO)}`);
  });

  it('pushes the severity it toggled, and keeps the selected type with it', () => {
    mount();
    click(byText('button[aria-pressed]', 'critical'));

    const url = String(push.mock.calls[0]?.[0]);
    expect(url).toContain('severity=critical');
    // The selection rides every push; losing it would drop the reader back to
    // the first type every time they touched a filter.
    expect(url).toContain(`rule=${encodeURIComponent(AWS)}`);
  });
});

// P2: the cursor was minted under the SERVER's term, so the load-more must pair
// the two. Passing the live debounced value instead pages a differently filtered
// list from a cursor that never described it — silently, since a filtered list
// is a subsequence and the slice simply starts past the rows that should have
// been on page 1.
//
// The shape that binds it is a server term DIFFERENT from the live one, which is
// what a click inside the 300 ms debounce window produces.
// N1: the page cache is reset during RENDER against the response's identity, so
// a server re-render can land while a fetch is outstanding — a debounced search
// push is the ordinary way, and clicking Next does not cancel that debounce.
// Without an epoch check the continuation appends the previous query's rows onto
// the new page 0 and moves to them: page 2 of the old filter, labelled as page 2
// of the new one.
//
// Deterministic because the fetch is a promise this test resolves by hand, so
// the re-render is guaranteed to land between the click and the continuation.
describe('By-type view — a server re-render mid-fetch', () => {
  it('drops the in-flight page rather than appending it to the new list', async () => {
    let release: ((r: ListFindingInstancesResponse) => void) | undefined;
    loadMoreFindingInstances.mockReturnValue(
      new Promise<ListFindingInstancesResponse>((resolve) => {
        release = resolve;
      }),
    );
    mount();

    // Start the fetch; it is now parked.
    act(() => {
      panelNext()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);

    // The server answers a filter change with a NEW response object, which is
    // what the cache keys its reset on.
    mount({ instances: pageOf(['g1'], null) });
    expect(container.textContent).toContain('MASK-g1');

    // The old fetch now lands.
    await act(async () => {
      release?.(pageOf(['stale-1'], null));
      await Promise.resolve();
    });

    // It belongs to a list that is no longer on screen.
    expect(container.textContent).not.toContain('MASK-stale-1');
    expect(container.textContent).toContain('MASK-g1');
  });

  it('drops an in-flight jump the same way', async () => {
    let release: ((r: ListFindingInstancesResponse) => void) | undefined;
    loadMoreFindingInstances.mockReturnValue(
      new Promise<ListFindingInstancesResponse>((resolve) => {
        release = resolve;
      }),
    );
    mount({ instances: { ...pageOf(['f1'], 'cursor-1'), totals: { findings: 500 } } });
    await jumpIn(panel(), 7);
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);

    mount({ instances: pageOf(['g1'], null) });

    await act(async () => {
      release?.(pageOf(['stale-1'], null));
      await Promise.resolve();
    });

    expect(container.textContent).not.toContain('MASK-stale-1');
    expect(container.textContent).toContain('MASK-g1');
  });
});

describe('By-type view — load-more pairs the cursor with the term it was minted under', () => {
  it('sends the server-rendered query, not the live debounced one', async () => {
    loadMoreFindingTypes.mockResolvedValue({
      totals: { findings: 84, types: 2 },
      facets: FACETS,
      items: [type(TODO)],
      nextCursor: null,
    });
    // The server rendered against '' and the reader has since typed 'aws'.
    // The type list needs a cursor of its own, or its Next is disabled.
    mount({ query: '', types: { ...TYPES, nextCursor: 'types-cursor-1' } });
    const box = container.querySelector('input[aria-label="Search finding types"]');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(box, 'aws');
      box?.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const next = byText('button[data-slot="pagination-next"]', 'Next', typeList());
    await act(async () => {
      next?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    expect(loadMoreFindingTypes).toHaveBeenCalledTimes(1);
    const query = loadMoreFindingTypes.mock.calls[0]?.[0] as Record<string, unknown>;
    // 'aws' is the live term; pairing it with this cursor is the defect.
    expect(query.q).toBeUndefined();
  });
});

describe('By-type view — the type list pages on its own', () => {
  it('leaves the appended selected type out of the range', () => {
    const items = Array.from({ length: 51 }, (_, i) => type(`rule/${String(i)}`));
    mount({ types: { ...TYPES, items, totals: { findings: 84, types: 214 } } });

    expect(typeList().textContent).toContain('1–50 of 214 types');
  });

  it('reads a jumped-to page of types from its row position', async () => {
    loadMoreFindingTypes.mockResolvedValue({
      ...TYPES,
      totals: { findings: 84, types: 120 },
      items: [type('rule/far')],
    });
    mount({ types: { ...TYPES, totals: { findings: 84, types: 120 } } });

    await jumpIn(typeList(), 3);

    const query = loadMoreFindingTypes.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.offset).toBe(100);
    expect(fieldIn(typeList()).value).toBe('3');
    expect(typeList().textContent).toContain('of 120 types');
  });
});

describe('By-type view — the findings panel pages on its own', () => {
  it('fetches the next page once, then serves the way back from cache', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3', 'f4'], null));
    mount();

    await clickPanelNext();
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain('MASK-f3');

    // Back, then forward again: both pages are already held, so neither step
    // may reach the action a second time.
    click(panelPrev());
    expect(container.textContent).toContain('MASK-f1');
    click(panelNext());
    expect(container.textContent).toContain('MASK-f3');
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);

    // Paging is not navigation — it must not touch the URL, or every step would
    // become a history entry and re-run the whole route.
    expect(push).not.toHaveBeenCalled();
  });

  // 500 findings at 50 a page: ten pages, of which the mount holds only the first.
  const LONG = { ...pageOf(['f1', 'f2'], 'cursor-1'), totals: { findings: 500 } };

  const panelField = () => fieldIn(panel());
  const jumpTo = (page: number) => jumpIn(panel(), page);

  it('reads a jumped-to page from its row position, keeping the scope', async () => {
    loadMoreFindingInstances.mockResolvedValue({
      ...pageOf(['f9'], 'cursor-9'),
      totals: { findings: 500 },
    });
    mount({ instances: LONG });

    await jumpTo(7);

    const query = loadMoreFindingInstances.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.offset).toBe(300);
    expect(query.cursor).toBeUndefined();
    expect(query.subtype).toEqual([AWS]);
    expect(container.textContent).toContain('MASK-f9');
    expect(panelField().value).toBe('7');
    expect(panel().textContent).toContain('301–301 of 500 findings');
  });

  it('carries on by cursor after a jump, and reads the page before it by position', async () => {
    loadMoreFindingInstances.mockResolvedValueOnce(pageOf(['f9'], 'cursor-9'));
    mount({ instances: LONG });
    await jumpTo(7);

    loadMoreFindingInstances.mockResolvedValueOnce(pageOf(['f10'], 'cursor-10'));
    await clickPanelNext();
    const forward = loadMoreFindingInstances.mock.calls[1]?.[0] as Record<string, unknown>;
    expect(forward.cursor).toBe('cursor-9');
    expect(forward.offset).toBeUndefined();
    expect(panelField().value).toBe('8');

    // Page 7 is held, so that step back reads nothing.
    click(panelPrev());
    expect(panelField().value).toBe('7');
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(2);

    // Page 6 is not, and there is no cursor that reaches it.
    loadMoreFindingInstances.mockResolvedValueOnce(pageOf(['f8'], 'cursor-8'));
    const previous = panelPrev();
    await act(async () => {
      previous?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    const back = loadMoreFindingInstances.mock.calls[2]?.[0] as Record<string, unknown>;
    expect(back.offset).toBe(250);
    expect(panelField().value).toBe('6');
  });

  it('stays put when the list has shrunk past the page', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf([], null));
    mount({ instances: LONG });

    await jumpTo(7);

    expect(container.textContent).toContain('MASK-f1');
    expect(panelField().value).toBe('1');
  });

  it('keeps the server’s first page on the way back to it', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f9'], 'cursor-9'));
    mount({ instances: LONG });
    await jumpTo(7);
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);

    await jumpTo(1);

    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain('MASK-f1');
    expect(panelField().value).toBe('1');
    // Next from there carries on from the first page's own cursor.
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3'], null));
    await clickPanelNext();
    const query = loadMoreFindingInstances.mock.calls[1]?.[0] as Record<string, unknown>;
    expect(query.cursor).toBe('cursor-1');
  });

  it('says so when a read fails, and stays put', async () => {
    loadMoreFindingInstances.mockRejectedValue(new Error('locked'));
    mount({ instances: LONG });

    await jumpTo(7);

    expect(panelField().value).toBe('1');
    expect(panel().querySelector('[role="alert"]')?.textContent).toBe(
      'That page of findings could not be read.',
    );
    expect(container.textContent).toContain('MASK-f1');
  });

  it('says so when Next fails, and clears it on the next move', async () => {
    loadMoreFindingInstances.mockRejectedValueOnce(new Error('locked'));
    mount({ instances: LONG });
    await clickPanelNext();
    expect(panel().querySelector('[role="alert"]')?.textContent).toBe(
      'The next page of findings could not be read.',
    );

    loadMoreFindingInstances.mockResolvedValueOnce(pageOf(['f3'], null));
    await clickPanelNext();
    expect(panel().querySelector('[role="alert"]')).toBeNull();
  });

  it('says so when the list has shrunk past the page', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf([], null));
    mount({ instances: LONG });

    await jumpTo(7);

    expect(panel().querySelector('[role="alert"]')?.textContent).toBe(
      'That page of findings is no longer there.',
    );
  });

  it('follows the total of the latest read', async () => {
    loadMoreFindingInstances.mockResolvedValue({
      ...pageOf(['f3'], 'cursor-2'),
      totals: { findings: 900 },
    });
    mount({ instances: LONG });

    await clickPanelNext();

    expect(panel().textContent).toContain('51–51 of 900 findings');
    expect(panel().textContent).toContain('of 18');
  });

  it('numbers a page the same whichever way the reader reached it', async () => {
    const read = (ids: string[], cursor: string) => ({
      ...pageOf(ids, cursor),
      totals: { findings: 500 },
    });
    const long = Array.from({ length: 50 }, (_, i) => `r${String(i)}`);
    mount({ instances: read(long, 'cursor-1') });
    expect(panel().textContent).toContain('1–50 of 500 findings');

    loadMoreFindingInstances.mockResolvedValueOnce(read(['s1'], 'cursor-2'));
    await clickPanelNext();
    expect(panel().textContent).toContain('51–51 of 500 findings');

    loadMoreFindingInstances.mockResolvedValueOnce(read(['t1'], 'cursor-7'));
    await jumpTo(7);
    loadMoreFindingInstances.mockResolvedValueOnce(read(['s1'], 'cursor-2'));
    await jumpTo(2);
    expect(panel().textContent).toContain('51–51 of 500 findings');
  });

  it('closes an open drawer when stepping to a held page', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3'], null));
    mount({ instances: LONG });
    await clickPanelNext();
    const open = () =>
      [...document.querySelectorAll('[role="dialog"]')].some((el) => !container.contains(el));
    click(
      byText('tbody tr', 'MASK-f3', panel())?.querySelector('button, [role="button"]') ??
        byText('tbody tr', 'MASK-f3', panel()),
    );
    expect(open(), 'the row did not open a drawer').toBe(true);

    // Back and forward over held pages: the selection must not survive the trip
    // and reopen the drawer on the row it came from.
    await act(async () => {
      panelPrev()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    await clickPanelNext();

    expect(container.textContent).toContain('MASK-f3');
    expect(open()).toBe(false);
  });

  it('closes an open drawer once a jump lands', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f9'], 'cursor-9'));
    mount({ instances: LONG, deepLinkedInstance: instance('f1') });
    const open = () =>
      [...document.querySelectorAll('[role="dialog"]')].some((el) => !container.contains(el));
    expect(open()).toBe(true);

    await jumpTo(7);

    expect(open()).toBe(false);
  });

  it('keeps the forward pages when stepping back from a jump', async () => {
    const read = (ids: string[], cursor: string) => ({
      ...pageOf(ids, cursor),
      totals: { findings: 500 },
    });
    loadMoreFindingInstances.mockResolvedValueOnce(read(['f9'], 'cursor-9'));
    mount({ instances: LONG });
    await jumpTo(7);
    loadMoreFindingInstances.mockResolvedValueOnce(read(['f8'], 'cursor-8'));
    const previous = panelPrev();
    await act(async () => {
      previous?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    expect(panelField().value).toBe('6');
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(2);

    // Page 7 was kept, so this step reads nothing.
    await clickPanelNext();
    expect(panelField().value).toBe('7');
    expect(container.textContent).toContain('MASK-f9');
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(2);
  });

  it('drops a row already shown when a later page repeats it', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f2', 'f3'], null));
    mount();
    await clickPanelNext();

    const rows = [...container.querySelectorAll('tbody tr')].map((row) => row.textContent);
    expect(rows.some((text) => text.includes('MASK-f3'))).toBe(true);
    expect(rows.some((text) => text.includes('MASK-f2'))).toBe(false);
  });

  it('stays put when a later page repeats everything, and takes its cursor', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f1', 'f2'], null));
    mount({ instances: LONG });
    await clickPanelNext();

    expect(panelField().value).toBe('1');
    expect(panel().querySelector('[role="alert"]')?.textContent).toBe(
      'The rest of findings moved while you were reading it.',
    );
    expect(panelNext()?.hasAttribute('disabled')).toBe(true);
  });

  it('keeps an open drawer when the move does not happen', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf([], null));
    mount({ instances: LONG, deepLinkedInstance: instance('f1') });
    const open = () =>
      [...document.querySelectorAll('[role="dialog"]')].some((el) => !container.contains(el));
    expect(open()).toBe(true);

    await act(async () => {
      fieldIn(panel()).focus();
      await Promise.resolve();
    });
    await jumpTo(7);

    expect(open()).toBe(true);
  });

  it('replays a held page without reading', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3', 'f4'], 'cursor-2'));
    mount({ instances: LONG });
    await clickPanelNext();
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);

    await jumpTo(1);

    expect(container.textContent).toContain('MASK-f1');
    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);
  });

  it('carries the pinned type into the page it fetches', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3'], null));
    mount();

    await clickPanelNext();

    const query = loadMoreFindingInstances.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.subtype).toEqual([AWS]);
    expect(query.cursor).toBe('cursor-1');
  });

  // The DEEP-LINKED drawer is the discriminating case, and the only one.
  //
  // A drawer opened by clicking a row closes on paging whether or not anything
  // clears it, because the selection is resolved against the current page and
  // that row is no longer on it — an assertion there passes on an implementation
  // that never closes anything. A deep-linked finding is shown even when the
  // page does not contain it, precisely so a link to an old finding resolves. So
  // it is the one selection that survives a page step unless the step clears it.
  it('closes a deep-linked drawer when the page moves out from under it', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3'], null));
    const linked = instance('deep-1');
    mount({ deepLinkedInstance: linked });

    const openDrawers = () => document.querySelectorAll('[role="dialog"]').length;
    // It opens on mount, without the row being on the page at all.
    expect(openDrawers()).toBe(1);
    expect(document.body.textContent).toContain('MASK-deep-1');

    await clickPanelNext();

    expect(openDrawers()).toBe(0);
  });
});

describe('findings drawer — the excerpt', () => {
  it("fetches the open finding's excerpt by its id and shows it", async () => {
    const excerpt: FindingContext = {
      basis: 'file',
      firstLine: 7,
      lines: ['element.innerHTML = userInput;'],
      match: { line: 7, start: 8, end: 19 },
    };
    loadFindingContextAction.mockResolvedValueOnce(excerpt);
    mount({ deepLinkedInstance: instance('deep-ctx') });
    // Control: before the read settles the drawer says it is loading.
    expect(document.body.textContent).toContain('Loading the code around this match');

    await act(async () => {
      await Promise.resolve();
    });

    expect(loadFindingContextAction).toHaveBeenCalledWith({ id: 'deep-ctx' });
    expect([...document.querySelectorAll('mark')].map((m) => m.textContent)).toEqual([
      'innerHTML =',
    ]);
    expect(document.body.textContent).toContain('src/config.ts:7');
  });
});

// The By-location view's own wiring. Two of these have no counterpart in the
// By-type suite because the shapes differ: selection is a token rather than an
// id the reader could type, and the panel's query has to carry the whole filter
// set rather than the complement of it.
describe('findings client — the By-location view', () => {
  function mountFiles(over: Record<string, unknown> = {}): void {
    mount({
      view: 'files',
      types: undefined,
      selectedRule: undefined,
      locations: locationsPage(LOCATIONS, 'loc-cursor-1'),
      instances: pageOf(['f1', 'f2'], 'cursor-1'),
      selectedLocation: LOCATIONS[0],
      deepLinkedInstance: null,
      ...over,
    });
  }

  it('pushes the location token as ?loc= rather than setting local state', () => {
    mountFiles();
    click(byText('button', 'src/db.ts', typeList()));

    expect(push).toHaveBeenCalledTimes(1);
    const url = new URL(String(push.mock.calls[0]?.[0]), 'https://x');
    expect(url.searchParams.get('loc')).toBe('acme%2Fapi/src%2Fdb.ts');
    expect(url.searchParams.get('view')).toBe('files');
  });

  // The selection has to survive a filter click, or changing a filter would
  // silently drop the reader back to the first row.
  it('carries the selected location through a filter change', () => {
    mountFiles();
    // The toolbar is above the pair here, so its controls sit outside both cards.
    click(byText('button', 'Severity'));
    // Scoped to the portalled popover, NOT to document.body: a location row is
    // itself a <button> carrying a severity badge, so an unscoped lookup for
    // 'critical' finds a ROW and clicking it pushes a selection — which passes
    // `expect(push).toHaveBeenCalled()` while testing nothing about filters.
    const popover = [...document.querySelectorAll('[role="dialog"]')].find(
      (el) => !container.contains(el),
    );
    expect(popover, 'the severity popover did not open').toBeTruthy();
    // 'Critical', capitalized: the toolbar labels a closed enum through
    // capitalize(), where a location row prints the raw badge value.
    click(byText('button', 'Critical', popover));

    expect(push).toHaveBeenCalled();
    const url = new URL(String(push.mock.calls.at(-1)?.[0]), 'https://x');
    expect(url.searchParams.get('loc')).toBe('acme%2Fapi/src%2Fconfig.ts');
    expect(url.searchParams.getAll('severity')).toEqual(['critical']);
  });

  // The panel's query is the list's plus the pair, so the two reads cannot
  // disagree about what they are counting.
  // Which read feeds the toolbar. Reading a count is the only way to tell: the
  // controls render identically whichever facets they are handed, so a toolbar
  // wired to the panel's read looks correct and answers "how many if I also pick
  // this?" about the wrong rows.
  it('counts the toolbar facets from the LOCATIONS read, not the panel one', () => {
    mountFiles();
    click(byText('button', 'Provider'));
    const popover = [...document.querySelectorAll('[role="dialog"]')].find(
      (el) => !container.contains(el),
    );
    expect(popover, 'the provider popover did not open').toBeTruthy();
    // 97 is the locations read's count; the panel's own facets say 4.
    expect(popover?.textContent).toContain('97');
    expect(popover?.textContent).not.toContain('4');
  });

  it('leaves the appended selected location out of the range', () => {
    const items = Array.from({ length: 51 }, (_, i) =>
      location({ id: `acme%2Fapi/${String(i)}`, file: `f${String(i)}.ts` }),
    );
    mountFiles({
      locations: {
        ...locationsPage(items, 'loc-cursor-1'),
        totals: { findings: 24, locations: 214 },
      },
      selectedLocation: items[0],
    });

    expect(typeList().textContent).toContain('1–50 of 214 locations');
  });

  it('reads a jumped-to page of locations from its row position', async () => {
    loadMoreFindingLocations.mockResolvedValue(locationsPage([LOCATIONS[1] as never], null));
    mountFiles({
      locations: {
        ...locationsPage(LOCATIONS, 'loc-cursor-1'),
        totals: { findings: 24, locations: 120 },
      },
    });

    await jumpIn(typeList(), 3);

    const query = loadMoreFindingLocations.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.offset).toBe(100);
    expect(fieldIn(typeList()).value).toBe('3');
  });

  it('pages the panel with the pinned pair and the whole filter set', async () => {
    loadMoreFindingInstances.mockResolvedValue(pageOf(['f3'], null));
    mountFiles({ filters: { ...EMPTY_FILTERS, provider: ['claudecode'] } });
    await clickPanelNext();

    expect(loadMoreFindingInstances).toHaveBeenCalledTimes(1);
    const query = loadMoreFindingInstances.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.repo).toBe('acme/api');
    expect(query.file).toBe('src/config.ts');
    expect(query.provider).toEqual(['claudecode']);
    expect(query.cursor).toBe('cursor-1');
  });

  // A location has no per-location transcript tally the way a type has a
  // per-rule one, so the drawer's footer passes null and must render the link
  // ALONE. Passing 0 instead would print "Caught by live enforcement only",
  // which is a claim about the transcript that nothing here measured.
  it('offers the session link in the drawer without inventing a firing tally', () => {
    mountFiles({ session: 'sess-1', deepLinkedInstance: instance('f1') });
    const drawer = [...document.querySelectorAll('[role="dialog"]')].find(
      (el) => !container.contains(el),
    );
    expect(drawer, 'the deep-linked drawer did not open').toBeTruthy();
    expect(drawer?.textContent).toContain('View session in Activity');
    expect(drawer?.textContent).not.toContain('this session');
  });

  it('pages the location list from its own cursor', async () => {
    loadMoreFindingLocations.mockResolvedValue(
      locationsPage([location({ id: 'other', file: 'src/x.ts' })], null),
    );
    const listNext = () => byText('button[data-slot="pagination-next"]', 'Next', typeList());
    mountFiles();
    await act(async () => {
      listNext()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    expect(loadMoreFindingLocations).toHaveBeenCalledTimes(1);
    const query = loadMoreFindingLocations.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.cursor).toBe('loc-cursor-1');
    // Paging the list is not a navigation — it must not create a history entry.
    expect(push).not.toHaveBeenCalled();
  });

  // The cursor was minted under the SERVER's term. Pairing it with a newer one
  // pages a differently filtered list, and because a filtered list is a
  // subsequence the slice starts past rows that should have been on page 1.
  // Both re-fetches, in one case, under a NON-EMPTY tool scope.
  //
  // The scope is the whole point: every other case here renders with `tools: []`,
  // and with an empty scope a call site that forwards the scope and one that
  // drops it produce byte-identical payloads. That is exactly how both sites
  // shipped without it — the server render was correctly scoped, the cursor was
  // minted against the scoped list, and page 2 came back from the unscoped one.
  //
  // Driving both panels together rather than one each is deliberate: a third
  // re-fetch added later is caught wherever it is added, not only if someone
  // remembers to write it a case.
  it('carries the tool scope into BOTH re-fetches, not just the server render', async () => {
    loadMoreFindingLocations.mockResolvedValue(locationsPage([], null));
    loadMoreFindingInstances.mockResolvedValue(pageOf([], null));
    mountFiles({ tools: ['Bash'] });

    const listNext = () => byText('button[data-slot="pagination-next"]', 'Next', typeList());
    await act(async () => {
      listNext()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    await clickPanelNext();

    const listQuery = loadMoreFindingLocations.mock.calls[0]?.[0] as Record<string, unknown>;
    const panelQuery = loadMoreFindingInstances.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(listQuery.tool).toEqual(['Bash']);
    expect(panelQuery.tool).toEqual(['Bash']);
    // The controls: each re-fetch still carries what it is FOR, so a payload
    // that gained `tool` by losing its cursor or its pin would not pass.
    expect(listQuery.cursor).toBe('loc-cursor-1');
    expect(panelQuery.cursor).toBe('cursor-1');
    expect(panelQuery.repo).toBe('acme/api');
    expect(panelQuery.file).toBe('src/config.ts');
  });

  it('pages the list under the server term, not the live one', async () => {
    loadMoreFindingLocations.mockResolvedValue(locationsPage([], null));
    mountFiles();

    const box = container.querySelector('input[aria-label="Search findings"]');
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(
        box,
        'typed-since-render',
      );
      box?.dispatchEvent(new Event('input', { bubbles: true }));
    });

    const listNext = () => byText('button[data-slot="pagination-next"]', 'Next', typeList());
    await act(async () => {
      listNext()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    const query = loadMoreFindingLocations.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(query.q).toBeUndefined();
  });
});

describe('findings drawer — the Deployment row', () => {
  const queued = (id: string): FindingInstanceDetail => ({
    ...instance(id),
    delivery: { state: 'queued' },
  });
  const onePage = (): ListFindingInstancesResponse => ({
    ...pageOf(['f1'], null),
    items: [queued('f1')],
  });

  it('explains the state on an attached machine', () => {
    mount({ instances: onePage(), deployment: { canRetry: false } });
    click(byText('tr', 'MASK-f1', panel()));
    expect(document.body.textContent).toContain('Based on its latest detection.');
    expect(document.body.textContent).toContain('Settings → Sync');
  });

  it('shows no Deployment row on a machine that is not attached', () => {
    mount({ instances: onePage() });
    click(byText('tr', 'MASK-f1', panel()));
    // The drawer did open, so the absence below is not the absence of a drawer.
    // Anchored on a label only the drawer renders — the row behind it carries a
    // "Source" column but never these two words together.
    expect(document.body.textContent).toContain('Matched content');
    expect(document.body.textContent).not.toContain('Based on its latest detection.');
  });
});
