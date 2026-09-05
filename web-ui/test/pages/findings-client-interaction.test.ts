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
  FindingFacets,
  FindingInstanceDetail,
  FindingTypeSummary,
  ListFindingInstancesResponse,
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
vi.mock('../../app/(app)/findings/actions', () => ({
  loadMoreFindingInstances: (q: unknown) => loadMoreFindingInstances(q),
  loadMoreFindingTypes: (q: unknown) => loadMoreFindingTypes(q),
}));

const { FindingsClient } = await import('../../app/(app)/findings/FindingsClient.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const AWS = 'secrets/aws-access-key';
const TODO = 'code/todo-note';
const EMPTY_FILTERS = { severity: [], type: [], provider: [], action: [], status: [] };

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

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  push.mockReset();
  loadMoreFindingInstances.mockReset();
  loadMoreFindingTypes.mockReset();
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

// The two panels each have a paginator, and the type list's comes first in the
// markup — an unscoped lookup finds THAT one, which here is disabled and
// swallows the click. Scope every panel query to the second card.
const panel = (): ParentNode => {
  const cards = container.querySelectorAll('[data-slot="card"]');
  expect(cards, 'expected a type list and a findings panel').toHaveLength(2);
  return cards[1] as ParentNode;
};
const typeList = (): ParentNode =>
  container.querySelectorAll('[data-slot="card"]')[0] as ParentNode;
const panelNext = () => byText('button[data-slot="pagination-next"]', 'Next', panel());
const panelPrev = () => byText('button[data-slot="pagination-previous"]', 'Previous', panel());
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
