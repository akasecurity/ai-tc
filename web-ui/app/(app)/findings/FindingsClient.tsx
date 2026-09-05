'use client';

import {
  FindingDetailView,
  FindingLevelFilters,
  FINDINGS_VIEW_LABEL,
  FINDINGS_VIEWS,
  type FindingsFilters,
  FindingsFlatTableView,
  FindingsLocationsView,
  FindingsToolbarView,
  type FindingsView,
  FindingTypesListView,
  PageHead,
  rangeLabel,
  TIME_RANGE_OPTIONS,
  type TimeRange,
} from '@akasecurity/dashboard-ui';
import type {
  FindingGroup,
  FindingInstanceDetail,
  ListFindingInstancesResponse,
  ListFindingLocationsResponse,
  ListFindingTypesResponse,
} from '@akasecurity/schema';
import {
  Badge,
  Button,
  Card,
  cn,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
  Sheet,
  SheetContent,
} from '@akasecurity/ui-kit';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useCallback, useState, useTransition } from 'react';

import { TerminalIcon, XIcon } from '../../components/icons';
import { useNavigationTransition } from '../../components/NavigationTransition';
import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { loadMoreFindingInstances, loadMoreFindingTypes } from './actions';
import {
  buildFindingsParams,
  toFindingTypesQuery,
  toInstancesQuery,
  toTypeInstancesQuery,
} from './filters';

interface CommonProps {
  filters: FindingsFilters;
  query: string;
  /** Session id the list is scoped to ('' when unscoped). */
  session: string;
  /** The resolved time window, or null for all time. */
  range: TimeRange | null;
  /**
   * The window's start as the SERVER resolved it. Passed down rather than
   * recomputed per page: `rangeToFromIso` reads the clock, so a client-side
   * recompute would give a later page a slightly different window than the
   * first — findings silently dropping out between pages.
   */
  from: string | null;
  tools: string[];
  repo: string;
  file: string;
  /**
   * The instant the SERVER rendered against, passed down for the same reason
   * `from` is: every relative label has to read one instant, and a client that
   * read its own would render different text than the HTML it is hydrating.
   */
  renderedAt: number;
}

type ViewProps =
  | {
      view: 'grouped';
      /** The left panel: one page of finding types. */
      types: ListFindingTypesResponse;
      /**
       * The right panel: one page of the selected type's findings. Null only
       * when no type is selected, which means the type list itself is empty.
       */
      instances: ListFindingInstancesResponse | null;
      /** The selected type's rule id ('' when the list is empty). */
      selectedRule: string;
      /**
       * The finding a `?finding=` deep link named, resolved server-side by a
       * primary-key seek — so it opens the drawer whatever page of the right
       * panel it would naturally sort to, and however old it is.
       */
      deepLinkedInstance: FindingInstanceDetail | null;
    }
  | { view: 'flat'; flat: ListFindingInstancesResponse }
  | { view: 'files'; locations: ListFindingLocationsResponse };

/**
 * Client shell for the OSS findings page. The data + facets + current filters
 * come from the Server Component (which reads the local store per URL);
 * filter/search/view changes push a new URL so the server re-queries — the OSS
 * store is server-only, so filtering can't happen in the browser.
 *
 * Pagination is the exception: stepping through pages calls a data-returning
 * Server Action rather than a URL push, so no history entry is created per
 * page. Each view keeps a client-side cache of the pages it has already
 * fetched (keyed by index) plus the cursor to fetch the next one — the lists
 * are keyset-paged server-side, so "Previous" replays a cached page rather
 * than re-fetching, and there is no way to jump to an arbitrary page.
 */
export function FindingsClient(props: CommonProps & ViewProps) {
  const {
    filters,
    query: initialQuery,
    session,
    range,
    from,
    tools,
    repo,
    file,
    renderedAt,
  } = props;
  const pathname = usePathname();
  const { isPending, push } = useNavigationTransition();
  const view = props.view;

  // The selected type rides every push, so changing a filter keeps the type the
  // reader was looking at. It is view-scoped: buildFindingsParams writes it only
  // under `grouped`.
  const rule = props.view === 'grouped' ? props.selectedRule : '';

  const buildUrl = useCallback(
    (
      nextFilters: FindingsFilters,
      nextQuery: string,
      nextSession: string,
      overrides: {
        view?: FindingsView;
        range?: TimeRange | null;
        tools?: string[];
        repo?: string;
        file?: string;
        rule?: string;
      } = {},
    ) => {
      const qs = buildFindingsParams(nextFilters, nextQuery, nextSession, {
        view: overrides.view ?? view,
        range: overrides.range === undefined ? range : overrides.range,
        tools: overrides.tools ?? tools,
        repo: overrides.repo ?? repo,
        file: overrides.file ?? file,
        rule: overrides.rule ?? rule,
      }).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname, view, range, tools, repo, file, rule],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook; a
  // debounced search keeps the current filters, view and session scope.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl(filters, term, session),
  );

  const pushState = useCallback(
    (
      nextFilters: FindingsFilters,
      nextQuery: string,
      nextSession: string,
      overrides?: {
        view?: FindingsView;
        range?: TimeRange | null;
        tools?: string[];
        repo?: string;
        file?: string;
        rule?: string;
      },
    ) => {
      onNavigate(nextQuery);
      push(buildUrl(nextFilters, nextQuery, nextSession, overrides));
    },
    [onNavigate, push, buildUrl],
  );

  // Distinguish an empty local store (first run — nothing captured yet) from a
  // filter/search that simply matched nothing, so a fresh self-hosted install
  // gets an onboarding hint instead of a filter-implying "no matches" message.
  const noActiveFilters =
    query.trim() === '' &&
    session === '' &&
    tools.length === 0 &&
    repo === '' &&
    file === '' &&
    filters.severity.length === 0 &&
    filters.type.length === 0 &&
    filters.provider.length === 0 &&
    filters.action.length === 0 &&
    filters.status.length === 0;

  const emptyState = noActiveFilters ? (
    <p className="py-8 text-center text-sm text-text-3">
      No findings yet — run the plugin or <code>aka scan</code> to populate the local store.
    </p>
  ) : undefined;

  const sessionHref = session ? `/activity?id=${encodeURIComponent(session)}` : null;

  // The page tally. Both views count the same two things — findings in scope and
  // the types they fall under — from whichever read owns that scope. The
  // locations view counts repos and files instead, so it shows none.
  const tally =
    props.view === 'grouped'
      ? { findings: props.types.totals.findings, types: props.types.totals.types }
      : props.view === 'flat'
        ? { findings: props.flat.totals.findings, types: props.flat.facets.subtype.length }
        : null;

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-10 pt-7">
      <PageHead
        title="Findings"
        // Page-level, and deliberately not beside a filter. In the By-type view
        // these describe the TYPE list, which the detail panel's own filters do
        // not narrow — sat next to them, a number that never moved read as a
        // filter that had stopped working.
        sub={tally ? <Tally findings={tally.findings} types={tally.types} /> : PAGE_SUB}
        actions={
          <div className="flex items-center gap-2">
            <RangeFilter
              range={range}
              onChange={(next) => {
                pushState(filters, query, session, { range: next });
              }}
            />
            <ViewToggle
              view={view}
              onChange={(next) => {
                // Switching view is deliberately lossy in one direction: the
                // grouped view cannot honor tool/repo/file, and the locations
                // view is itself the repo/file breakdown, so those params are
                // dropped rather than left as ones the page would ignore.
                pushState(filters, query, session, {
                  view: next,
                  ...(next === 'grouped' ? { tools: [], repo: '', file: '' } : { rule: '' }),
                  ...(next === 'files' ? { repo: '', file: '' } : {}),
                });
              }}
            />
          </div>
        }
      />

      {/* Only the flat view has a toolbar. The locations view has no facets of
          its own (it counts repos and files), and the By-type view splits its
          filters between the two panels — each beside the rows it narrows. */}
      {props.view === 'flat' && (
        // The gap below sits HERE rather than on the panels container, because
        // the By-type view renders neither this nor, usually, the scope chips —
        // and a top margin on the container would then push its panels down
        // from nothing at all. Spacing belongs to whatever creates the need.
        <div className="mb-4">
          <FindingsToolbarView
            facets={props.flat.facets}
            filters={filters}
            onFiltersChange={(next) => {
              pushState(next, query, session);
            }}
            query={query}
            onQueryChange={setQuery}
          />
        </div>
      )}

      <ScopeChips
        session={session}
        sessionHref={sessionHref}
        tools={tools}
        repo={repo}
        file={file}
        onClearSession={() => {
          pushState(filters, query, '');
        }}
        onClearTools={() => {
          pushState(filters, query, session, { tools: [] });
        }}
        onClearLocation={() => {
          pushState(filters, query, session, { repo: '', file: '' });
        }}
        transcriptOnly={
          props.view === 'grouped' && props.types.sessionFirings
            ? Object.entries(props.types.sessionFirings).filter(
                ([ruleId]) => !props.types.items.some((t) => t.id === ruleId),
              )
            : []
        }
      />

      <div
        aria-busy={isPending}
        className={cn(
          'min-h-0 flex-1 transition-shadow duration-150',
          isPending && 'rounded-lg ring-2 ring-primary/70 ring-inset',
        )}
      >
        {props.view === 'grouped' && (
          <TypesMasterDetail
            types={props.types}
            instances={props.instances}
            selectedRule={props.selectedRule}
            deepLinkedInstance={props.deepLinkedInstance}
            filters={filters}
            query={query}
            onQueryChange={setQuery}
            session={session}
            from={from}
            sessionHref={sessionHref}
            emptyState={emptyState}
            renderedAt={renderedAt}
            onSelectRule={(nextRule) => {
              pushState(filters, query, session, { rule: nextRule });
            }}
            onSeverityChange={(next) => {
              pushState({ ...filters, severity: next }, query, session);
            }}
            onFiltersChange={(next) => {
              pushState(next, query, session);
            }}
          />
        )}
        {props.view === 'flat' && (
          <FlatView
            data={props.flat}
            filters={filters}
            query={query}
            session={session}
            from={from}
            tools={tools}
            repo={repo}
            file={file}
            emptyState={emptyState}
            renderedAt={renderedAt}
          />
        )}
        {props.view === 'files' && (
          <LocationsView
            data={props.locations}
            emptyState={emptyState}
            renderedAt={renderedAt}
            onSelectFile={(nextRepo, nextFile) => {
              // Drill into one file's findings: the flat view is the one that
              // can filter down to a single location.
              pushState(filters, query, session, {
                view: 'flat',
                repo: nextRepo,
                file: nextFile,
              });
            }}
          />
        )}
      </div>
    </div>
  );
}

const PAGE_SUB = 'Every sensitive-data finding across providers';

/**
 * The page subtitle: what the page is, then what is currently in scope.
 *
 * One middot separates the two, and the tally's own units are comma-separated
 * rather than middot-separated — nesting the same separator would read as three
 * peers instead of a description followed by its numbers.
 */
function Tally({ findings, types }: { findings: number; types: number }) {
  return (
    <>
      {PAGE_SUB} · <span className="font-semibold text-text">{findings.toLocaleString()}</span>
      {findings === 1 ? ' finding' : ' findings'},{' '}
      <span className="font-semibold text-text">{types.toLocaleString()}</span>
      {types === 1 ? ' type' : ' types'}
    </>
  );
}

// ─── Views ───────────────────────────────────────────────────────────────────

/**
 * The By-type view: a paginated list of finding TYPES on the left, and the
 * selected type's findings — themselves paginated — on the right.
 *
 * The two sides are independent reads, so neither caps the other. Selecting a
 * type pushes the URL (the server owns which type is selected, so the panels
 * cannot disagree); paging either side calls a Server Action and keeps a local
 * page cache, so neither creates a history entry nor disturbs the other.
 */
function TypesMasterDetail({
  types,
  instances,
  selectedRule,
  deepLinkedInstance,
  filters,
  query,
  onQueryChange,
  session,
  from,
  sessionHref,
  emptyState,
  renderedAt,
  onSelectRule,
  onSeverityChange,
  onFiltersChange,
}: {
  types: ListFindingTypesResponse;
  instances: ListFindingInstancesResponse | null;
  selectedRule: string;
  deepLinkedInstance: FindingInstanceDetail | null;
  filters: FindingsFilters;
  query: string;
  onQueryChange: (next: string) => void;
  session: string;
  from: string | null;
  sessionHref: string | null;
  emptyState: React.ReactNode;
  renderedAt: number;
  onSelectRule: (rule: string) => void;
  onSeverityChange: (next: string[]) => void;
  onFiltersChange: (next: FindingsFilters) => void;
}) {
  const typePages = usePagedList(types, types.items, types.nextCursor, (cursor, pages) =>
    loadMoreFindingTypes({
      // Built from the SERVER-RENDERED filters, never the live debounced query:
      // a click during the debounce window would otherwise page a differently
      // filtered set into this one.
      ...toFindingTypesQuery(filters, query, session, { ...(from ? { from } : {}) }),
      cursor,
    }).then((next) => ({
      // The selected type is appended to page 0 out of sort order (see
      // ListFindingTypesQuery.includeId) and resurfaces here at its natural
      // cursor position once paging reaches it — drop the repeat so a page never
      // shows the same type twice.
      items: dedupeAgainstPages(pages, next.items),
      next,
    })),
  );

  const selectedType = types.items.find((t) => t.id === selectedRule) ?? null;

  // The per-rule transcript-firing tally (session-scoped lists only) — surfaces
  // in the drawer footer so the "45 triggered vs 6 listed" gap is explained
  // where the reader is looking.
  const selectedFirings = types.sessionFirings ? (types.sessionFirings[selectedRule] ?? 0) : null;

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-4 lg:grid-cols-[352px_1fr]">
      <FindingTypesListView
        types={typePages.items}
        activeId={selectedRule}
        onSelect={(t) => {
          onSelectRule(t.id);
        }}
        query={query}
        onQueryChange={onQueryChange}
        severityCounts={new Map(types.facets.severity.map((f) => [f.value, f.count]))}
        selectedSeverities={filters.severity}
        onSeverityChange={onSeverityChange}
        onNextPage={typePages.onNextPage}
        onPreviousPage={typePages.onPreviousPage}
        hasNextPage={typePages.hasNextPage}
        hasPreviousPage={typePages.hasPreviousPage}
        loadingNextPage={typePages.loading}
        pageStart={typePages.pageStart}
        total={types.totals.types}
        {...(emptyState === undefined ? {} : { emptyState })}
      />

      {instances && selectedType ? (
        <InstancesPanel
          key={selectedRule}
          data={instances}
          pinnedType
          // The type name only. How many findings it has is already on its row
          // in the list and in this panel's own paginator — a third copy would
          // just be a number to keep in step with two others.
          header={
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
              <h2 className="truncate text-sm font-semibold text-text">{selectedType.subtype}</h2>
              {/* Inside the panel they act on, which says what no caption
                  could: these narrow THESE findings. Their counts come from
                  this panel's own read, so each answers "what happens if I
                  pick this?" about the rows below it. */}
              <div className="flex flex-wrap items-center gap-2">
                <FindingLevelFilters
                  facets={instances.facets}
                  filters={filters}
                  onFiltersChange={onFiltersChange}
                />
              </div>
            </div>
          }
          loadMore={(cursor) =>
            loadMoreFindingInstances({
              ...toTypeInstancesQuery(filters, selectedRule, session, {
                ...(from ? { from } : {}),
              }),
              cursor,
            })
          }
          initialSelected={deepLinkedInstance}
          emptyState={
            <p className="py-8 text-center text-sm text-text-3">
              No findings of this type match these filters.
            </p>
          }
          renderDrawerFooter={() =>
            sessionHref ? (
              <SessionFooter firings={selectedFirings} sessionHref={sessionHref} />
            ) : undefined
          }
          renderedAt={renderedAt}
        />
      ) : (
        <Card className="grid h-full min-h-0 place-items-center p-8 text-center text-sm text-text-3">
          {types.items.length === 0
            ? // `emptyState` is set only for an EMPTY STORE; with filters active
              // it is undefined, and rendering it alone left a blank card beside
              // a list that was explaining itself. Mirror the list's fallback.
              (emptyState ?? 'No types match these filters.')
            : 'Select a type to see its findings.'}
        </Card>
      )}
    </div>
  );
}

/**
 * A keyset-paged list's client-side page cache.
 *
 * Each entry is one fetched page; `cursors[i]` fetches the page after
 * `pages[i]`. Stepping forward past the cached frontier fetches and appends;
 * stepping back just moves `pageIndex` — the page is still here. Shared by both
 * panels so the two caches are independent by construction rather than by two
 * copies of the same bookkeeping agreeing.
 */
function usePagedList<T>(
  forResponse: object,
  firstPage: T[],
  // The cursor that fetches the page AFTER `firstPage`. Required, never
  // defaulted: a default reads as safe at every call site that omits it, and
  // omitting it leaves `hasNextPage` false on page 1 — a Next button that is
  // disabled on a list which plainly has more, with nothing thrown and nothing
  // logged. Required, the compiler names each caller that has to supply one.
  firstCursor: string | null,
  fetchAfter: (
    cursor: string,
    pages: T[][],
  ) => Promise<{ items: T[]; next: { nextCursor: string | null } }>,
) {
  const [pages, setPages] = useState<T[][]>([firstPage]);
  const [cursors, setCursors] = useState<(string | null)[]>([firstCursor]);
  const [pageIndex, setPageIndex] = useState(0);
  const [loading, startLoading] = useTransition();

  // Reset the cache when the server hands back a different first page — checked
  // DURING RENDER against the response object's identity, not in an effect. An
  // effect would commit one frame in which the previous query's page is rendered
  // under the new one, with duplicate React keys.
  const [forData, setForData] = useState(forResponse);
  if (forData !== forResponse) {
    setForData(forResponse);
    setPages([firstPage]);
    setCursors([firstCursor]);
    setPageIndex(0);
  }

  return {
    pages,
    items: pages[pageIndex] ?? [],
    pageStart: pageStartOf(pages, pageIndex),
    hasNextPage: pageIndex + 1 < pages.length || cursors[pageIndex] !== null,
    hasPreviousPage: pageIndex > 0,
    loading,
    onPreviousPage: () => {
      setPageIndex((i) => Math.max(0, i - 1));
    },
    onNextPage: () => {
      if (!needsFetch(pages.length, pageIndex)) {
        setPageIndex((i) => i + 1);
        return;
      }
      const cursor = cursors[pageIndex];
      if (cursor === null || cursor === undefined) return;
      startLoading(async () => {
        const { items, next } = await fetchAfter(cursor, pages);
        setPages((prev) => [...prev, items]);
        setCursors((prev) => [...prev, next.nextCursor]);
        setPageIndex((i) => i + 1);
      });
    },
  };
}

/**
 * A paginated list of findings plus its detail drawer — the right-hand panel of
 * the By-type view, and the whole of the flat view. One component rather than
 * two so the two cannot drift; what differs between them arrives as props.
 */
function InstancesPanel({
  data,
  loadMore,
  emptyState,
  renderedAt,
  pinnedType = false,
  header,
  initialSelected = null,
  renderDrawerFooter,
}: {
  data: ListFindingInstancesResponse;
  loadMore: (cursor: string) => Promise<ListFindingInstancesResponse>;
  emptyState: React.ReactNode;
  renderedAt: number;
  pinnedType?: boolean;
  header?: React.ReactNode;
  /**
   * A finding the server resolved from a `?finding=` deep link. It opens the
   * drawer directly rather than being looked up in `data`, which is what lets
   * the link resolve a finding that sorts onto no page this panel has fetched.
   */
  initialSelected?: FindingInstanceDetail | null;
  renderDrawerFooter?: (instance: FindingInstanceDetail) => React.ReactNode;
}) {
  const paged = usePagedList(data, data.items, data.nextCursor, (cursor) =>
    loadMore(cursor).then((next) => ({ items: next.items, next })),
  );
  const [selectedInstanceId, setSelectedInstanceId] = useState(initialSelected?.id ?? '');

  // Re-seed when an in-app navigation lands with a DIFFERENT deep-linked
  // finding. The initializer alone misses it: this component survives RSC
  // re-renders, and it is keyed by the selected type, so two findings of the
  // SAME type never remount it. State-adjustment-during-render, not an effect.
  //
  // Only a non-empty id re-seeds. The param draining to null just means an
  // ordinary filter or search push dropped the one-shot `?finding=`, which says
  // nothing about whatever the reader has selected since — clearing here would
  // snap shut a drawer they opened by hand during a pending debounced search.
  const [appliedDeepLink, setAppliedDeepLink] = useState(initialSelected?.id ?? '');
  if (appliedDeepLink !== (initialSelected?.id ?? '')) {
    setAppliedDeepLink(initialSelected?.id ?? '');
    if (initialSelected) setSelectedInstanceId(initialSelected.id);
  }

  // The deep-linked finding is shown even when this page does not contain it;
  // otherwise the selection names a row on the current page.
  const selected =
    (initialSelected?.id === selectedInstanceId ? initialSelected : null) ??
    paged.items.find((i) => i.id === selectedInstanceId) ??
    null;

  // Paging closes the drawer rather than leaving it pointing at a row the new
  // page no longer contains.
  const step = (move: () => void) => {
    setSelectedInstanceId('');
    move();
  };

  const table = (
    <FindingsFlatTableView
      renderedAt={renderedAt}
      {...(header === undefined ? {} : { header })}
      items={paged.items}
      selectedId={selectedInstanceId}
      pinnedType={pinnedType}
      onSelect={(instance) => {
        setSelectedInstanceId(instance.id);
      }}
      total={data.totals.findings}
      pageStart={paged.pageStart}
      hasNextPage={paged.hasNextPage}
      hasPreviousPage={paged.hasPreviousPage}
      loadingNextPage={paged.loading}
      onNextPage={() => {
        step(paged.onNextPage);
      }}
      onPreviousPage={() => {
        step(paged.onPreviousPage);
      }}
      {...(emptyState === undefined ? {} : { emptyState })}
    />
  );

  return (
    <>
      {table}

      <Sheet
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedInstanceId('');
        }}
      >
        {/* No description in this drawer — opt out of Radix's aria-describedby. */}
        <SheetContent className="p-0" aria-describedby={undefined}>
          {selected && (
            <FindingDetailView
              renderedAt={renderedAt}
              // Every row IS a single finding, so the drawer opens narrowed and
              // stays there — there is no group to step back to.
              selection={{ finding: instanceAsGroup(selected), instance: selected }}
              onSelectInstance={() => undefined}
              onBack={() => {
                setSelectedInstanceId('');
              }}
              {...(renderDrawerFooter ? { footer: renderDrawerFooter(selected) } : {})}
            />
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

/** The drawer footer on a session-scoped list: the firing tally + a way back. */
function SessionFooter({ firings, sessionHref }: { firings: number | null; sessionHref: string }) {
  return (
    <div className="flex flex-col items-start gap-2">
      {firings !== null && (
        <p className="text-xs text-text-3">
          {firings > 0
            ? `Fired ${String(firings)} times in this session's transcript — the session's "triggered" tally counts every firing, this drawer shows unique values.`
            : `Caught by live enforcement only — not re-detected in this session's transcript.`}
        </p>
      )}
      <Link
        href={sessionHref}
        className="inline-flex items-center gap-1.5 text-ui font-semibold text-primary underline-offset-2 hover:underline"
      >
        <TerminalIcon aria-hidden focusable={false} className="size-3.5" />
        View session in Activity
      </Link>
    </div>
  );
}

function FlatView({
  data,
  filters,
  query,
  session,
  from,
  tools,
  repo,
  file,
  emptyState,
  renderedAt,
}: {
  data: ListFindingInstancesResponse;
  filters: FindingsFilters;
  query: string;
  session: string;
  from: string | null;
  tools: string[];
  repo: string;
  file: string;
  emptyState: React.ReactNode;
  renderedAt: number;
}) {
  return (
    <InstancesPanel
      data={data}
      renderedAt={renderedAt}
      emptyState={emptyState}
      loadMore={(cursor) =>
        loadMoreFindingInstances({
          // Built from the SERVER-RENDERED filters, never the live debounced
          // query: a click during the debounce window would otherwise page a
          // different filtered set into this one.
          ...toInstancesQuery(filters, query, session, {
            ...(from ? { from } : {}),
            ...(tools.length ? { tools } : {}),
            ...(repo ? { repo } : {}),
            ...(file ? { file } : {}),
          }),
          cursor,
        })
      }
    />
  );
}

function LocationsView({
  data,
  emptyState,
  onSelectFile,
  renderedAt,
}: {
  data: ListFindingLocationsResponse;
  emptyState: React.ReactNode;
  onSelectFile: (repo: string, file: string) => void;
  renderedAt: number;
}) {
  const [expandedRepos, setExpandedRepos] = useState<ReadonlySet<string>>(
    // Open the worst-severity repo by default so the view is never a list of
    // collapsed rows with nothing to read.
    () => new Set(data.items[0] ? [data.items[0].repo] : []),
  );

  return (
    <FindingsLocationsView
      renderedAt={renderedAt}
      items={data.items}
      expandedRepos={expandedRepos}
      onToggleRepo={(repo) => {
        setExpandedRepos((prev) => {
          const next = new Set(prev);
          if (next.has(repo)) next.delete(repo);
          else next.add(repo);
          return next;
        });
      }}
      onSelectFile={onSelectFile}
      hasMore={data.hasMore}
      {...(emptyState === undefined ? {} : { emptyState })}
    />
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
//
// Exported (rather than file-local) so the page-cache derivation itself is
// directly unit-testable — see test/pages/findings-pagination.test.ts — without
// rendering GroupedView/FlatView, which this package's vitest setup (no DOM,
// no React renderer) cannot do.

/** 1-indexed position of `pages[pageIndex][0]` within the whole result set. */
export function pageStartOf(pages: unknown[][], pageIndex: number): number {
  let start = 1;
  for (let i = 0; i < pageIndex; i += 1) start += pages[i]?.length ?? 0;
  return start;
}

/**
 * Whether stepping to the page after `pageIndex` needs a server fetch, or can
 * just replay a page already sitting in the cache. `pageCount` is `pages.length`.
 */
export function needsFetch(pageCount: number, pageIndex: number): boolean {
  return pageIndex + 1 >= pageCount;
}

/**
 * Drop any item already rendered on an earlier page. The one case this matters
 * for today: GroupedView's `?finding=` deep link is appended to page 0 out of
 * sort order (see ListGroupedFindingsQuery.includeId) and resurfaces here at
 * its natural cursor position once paging reaches it — without this, that
 * group renders twice as the user pages through.
 */
export function dedupeAgainstPages<T extends { id: string }>(pages: T[][], incoming: T[]): T[] {
  const seen = new Set(pages.flat().map((item) => item.id));
  return incoming.filter((item) => !seen.has(item.id));
}

/**
 * A one-instance FindingGroup, so the shared detail view can render a flat row.
 * The group-level folds are that single instance's values — which is exact
 * here, not an approximation: the "group" has exactly one member.
 */
function instanceAsGroup(instance: FindingInstanceDetail): FindingGroup {
  return {
    id: instance.groupId,
    category: instance.category,
    subtype: instance.subtype,
    severity: instance.severity,
    match: instance.match,
    detection: instance.detection,
    policy: instance.policy,
    instanceCount: 1,
    providers: [instance.provider],
    // One instance, so the group's action IS that instance's — the aggregate is
    // exact here rather than a fold over a set.
    aggregateAction: instance.action,
    latestDetectedAt: instance.detectedAt,
    instances: [instance],
    ...(instance.status === undefined ? {} : { status: instance.status }),
  };
}

/**
 * The time window, including an explicit All time — which is this list's
 * DEFAULT, unlike every other range-driven page here. That is why it is not
 * TimeRangeSelect: that control's value is a non-null TimeRange, so it cannot
 * express "no window", and giving it one would change what a range means on
 * the pages that already use it.
 */
function RangeFilter({
  range,
  onChange,
}: {
  range: TimeRange | null;
  onChange: (next: TimeRange | null) => void;
}) {
  const ALL = '__all__';
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" tone="neutral" size="sm">
          {range === null ? 'All time' : rangeLabel(range)}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuRadioGroup
          value={range ?? ALL}
          onValueChange={(v) => {
            onChange(v === ALL ? null : (v as TimeRange));
          }}
        >
          <DropdownMenuRadioItem value={ALL}>All time</DropdownMenuRadioItem>
          {TIME_RANGE_OPTIONS.map((r) => (
            <DropdownMenuRadioItem key={r.value} value={r.value}>
              {r.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** The three-way view switch. */
function ViewToggle({
  view,
  onChange,
}: {
  view: FindingsView;
  onChange: (next: FindingsView) => void;
}) {
  return (
    <div
      role="group"
      aria-label="Findings view"
      className="inline-flex items-center rounded-lg border border-border bg-surface-2 p-0.5"
    >
      {FINDINGS_VIEWS.map((candidate) => (
        <button
          key={candidate}
          type="button"
          aria-pressed={candidate === view}
          onClick={() => {
            if (candidate !== view) onChange(candidate);
          }}
          className={cn(
            'h-7 cursor-pointer rounded-md px-2.5 text-xs font-medium transition-colors',
            candidate === view ? 'bg-surface text-text shadow-sm' : 'text-text-3 hover:text-text-2',
          )}
        >
          {FINDINGS_VIEW_LABEL[candidate]}
        </button>
      ))}
    </div>
  );
}

/** The active scope, visible, linkable and clearable. */
function ScopeChips({
  session,
  sessionHref,
  tools,
  repo,
  file,
  onClearSession,
  onClearTools,
  onClearLocation,
  transcriptOnly,
}: {
  session: string;
  sessionHref: string | null;
  tools: string[];
  repo: string;
  file: string;
  onClearSession: () => void;
  onClearTools: () => void;
  onClearLocation: () => void;
  transcriptOnly: [string, number][];
}) {
  if (!sessionHref && tools.length === 0 && !repo && !file) return null;
  return (
    <div className="mb-4 mt-3 flex flex-wrap items-center gap-2 text-ui text-text-2">
      {sessionHref && (
        <>
          <span>Showing findings enforced live in session</span>
          <Link href={sessionHref}>
            <Badge variant="primary" className="h-6 gap-1.5 font-mono hover:underline">
              <TerminalIcon aria-hidden focusable={false} className="size-3" />
              {session}
            </Badge>
          </Link>
          <Button
            variant="outline"
            size="sm"
            aria-label="Clear session filter"
            onClick={onClearSession}
          >
            <XIcon aria-hidden focusable={false} className="size-3.5" />
            Clear
          </Button>
        </>
      )}

      {tools.length > 0 && (
        <>
          <span>Tool</span>
          {tools.map((tool) => (
            <Badge key={tool} variant="default" className="h-6 font-mono">
              {tool}
            </Badge>
          ))}
          <Button variant="outline" size="sm" aria-label="Clear tool filter" onClick={onClearTools}>
            <XIcon aria-hidden focusable={false} className="size-3.5" />
            Clear
          </Button>
        </>
      )}

      {(repo || file) && (
        <>
          <span>Location</span>
          <Badge variant="default" className="h-6 font-mono">
            {[repo, file].filter(Boolean).join(' / ')}
          </Badge>
          <Button
            variant="outline"
            size="sm"
            aria-label="Clear location filter"
            onClick={onClearLocation}
          >
            <XIcon aria-hidden focusable={false} className="size-3.5" />
            Clear
          </Button>
        </>
      )}

      {transcriptOnly.length > 0 && (
        <p className="w-full text-xs text-text-3">
          {`Also detected in this session's transcript without live enforcement: `}
          {transcriptOnly.map(([rule, n]) => `${rule} ×${String(n)}`).join(', ')}
        </p>
      )}
    </div>
  );
}
