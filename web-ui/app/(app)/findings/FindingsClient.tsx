'use client';

import {
  ColumnsMenu,
  type ColumnVisibility,
  FindingDetailView,
  FINDINGS_COLUMNS,
  FINDINGS_VIEW_LABEL,
  FINDINGS_VIEWS,
  type FindingsFilters,
  FindingsFlatTableView,
  FindingsLocationsView,
  FindingsTableView,
  FindingsToolbarView,
  type FindingsView,
  PageHead,
  rangeLabel,
  type Selection,
  TIME_RANGE_OPTIONS,
  type TimeRange,
} from '@akasecurity/dashboard-ui';
import type {
  FindingGroup,
  FindingInstanceDetail,
  ListFindingInstancesResponse,
  ListFindingLocationsResponse,
  ListGroupedFindingsResponse,
} from '@akasecurity/schema';
import {
  Badge,
  Button,
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
import { loadMoreFindingInstances, loadMoreGroupedFindings } from './actions';
import { buildFindingsParams, toGroupedQuery, toInstancesQuery } from './filters';

/**
 * The ?finding= deep link → the drawer's Selection: a group id opens the grouped
 * view; an instance id opens that instance narrowed inside its group. Unknown ids
 * (stale links, instances outside the preview page) resolve to null — no drawer.
 */
function findSelection(groups: FindingGroup[], id: string): Selection | null {
  if (!id) return null;
  const group = groups.find((g) => g.id === id);
  if (group) return { finding: group };
  for (const g of groups) {
    const instance = g.instances.find((i) => i.id === id);
    if (instance) return { finding: g, instance };
  }
  return null;
}

interface CommonProps {
  filters: FindingsFilters;
  query: string;
  /** Session id the list is scoped to ('' when unscoped). */
  session: string;
  /** The ?finding= deep-link target ('' when absent). */
  selectedId: string;
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
}

type ViewProps =
  | { view: 'grouped'; data: ListGroupedFindingsResponse }
  | { view: 'flat'; flat: ListFindingInstancesResponse }
  | { view: 'files'; locations: ListFindingLocationsResponse };

/**
 * Client shell for the OSS findings page. The data + facets + current filters
 * come from the Server Component (which reads the local store per URL);
 * filter/search/view changes push a new URL so the server re-queries — the OSS
 * store is server-only, so filtering can't happen in the browser.
 *
 * Pagination is the exception: "Load more" appends through a data-returning
 * Server Action rather than a URL push, so the pages already accumulated
 * survive and no history entry is created per page.
 */
export function FindingsClient(props: CommonProps & ViewProps) {
  const {
    filters,
    query: initialQuery,
    session,
    selectedId,
    range,
    from,
    tools,
    repo,
    file,
  } = props;
  const pathname = usePathname();
  const { isPending, push } = useNavigationTransition();
  const view = props.view;

  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>({});

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
      } = {},
    ) => {
      const qs = buildFindingsParams(nextFilters, nextQuery, nextSession, {
        view: overrides.view ?? view,
        range: overrides.range === undefined ? range : overrides.range,
        tools: overrides.tools ?? tools,
        repo: overrides.repo ?? repo,
        file: overrides.file ?? file,
      }).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname, view, range, tools, repo, file],
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

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-10 pt-7">
      <PageHead
        title="Findings"
        sub="Every sensitive-data finding across providers"
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
                  ...(next === 'grouped' ? { tools: [], repo: '', file: '' } : {}),
                  ...(next === 'files' ? { repo: '', file: '' } : {}),
                });
              }}
            />
            {view === 'grouped' && (
              <ColumnsMenu
                columns={FINDINGS_COLUMNS}
                visibility={columnVisibility}
                onChange={setColumnVisibility}
              />
            )}
          </div>
        }
      />

      {/* The locations view has no facets of its own — it counts repos and
          files, where the toolbar's dimensions count findings. */}
      {props.view !== 'files' && (
        <FindingsToolbarView
          facets={props.view === 'flat' ? props.flat.facets : props.data.facets}
          filters={filters}
          onFiltersChange={(next) => {
            pushState(next, query, session);
          }}
          query={query}
          onQueryChange={setQuery}
          findingCount={
            props.view === 'flat' ? props.flat.totals.findings : props.data.totals.findings
          }
          typeCount={
            props.view === 'flat' ? props.flat.facets.subtype.length : props.data.totals.groups
          }
        />
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
          props.view === 'grouped' && props.data.sessionFirings
            ? Object.entries(props.data.sessionFirings).filter(
                ([rule]) => !props.data.items.some((g) => g.id === rule),
              )
            : []
        }
      />

      <div
        aria-busy={isPending}
        className={cn(
          'mt-4 min-h-0 flex-1 transition-shadow duration-150',
          isPending && 'rounded-lg ring-2 ring-primary/40 ring-inset',
        )}
      >
        {props.view === 'grouped' && (
          <GroupedView
            data={props.data}
            filters={filters}
            query={query}
            session={session}
            selectedId={selectedId}
            from={from}
            columnVisibility={columnVisibility}
            sessionHref={sessionHref}
            emptyState={emptyState}
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
          />
        )}
        {props.view === 'files' && (
          <LocationsView
            data={props.locations}
            emptyState={emptyState}
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

// ─── Views ───────────────────────────────────────────────────────────────────

function GroupedView({
  data,
  filters,
  query,
  session,
  selectedId,
  from,
  columnVisibility,
  sessionHref,
  emptyState,
}: {
  data: ListGroupedFindingsResponse;
  filters: FindingsFilters;
  query: string;
  session: string;
  selectedId: string;
  from: string | null;
  columnVisibility: ColumnVisibility;
  sessionHref: string | null;
  emptyState: React.ReactNode;
}) {
  const [pages, setPages] = useState<FindingGroup[][]>([]);
  const [cursor, setCursor] = useState<string | null>(data.nextCursor);
  const [loading, startLoading] = useTransition();

  // Reset accumulation when the server hands back a different first page —
  // checked DURING RENDER against the data object's identity, not in an effect.
  // An effect would commit one frame in which the appended pages from the
  // previous query are rendered under the new one, with duplicate React keys.
  const [forData, setForData] = useState(data);
  if (forData !== data) {
    setForData(data);
    setPages([]);
    setCursor(data.nextCursor);
  }

  // Dedupe by id: an includeId-appended group is out of sort order, so it
  // reappears at its natural position on whichever later page reaches it.
  const groups = dedupeById([...data.items, ...pages.flat()]);

  const [selected, setSelected] = useState<Selection | null>(() =>
    findSelection(data.items, selectedId),
  );
  // Re-seed the drawer when an in-app navigation lands with a different
  // ?finding= (the client component survives RSC re-renders, so the initializer
  // alone would miss it). State-adjustment-during-render, not an effect. Only a
  // NON-empty id re-seeds: the param draining to '' just means an ordinary
  // filter/search push dropped the one-shot ?finding=, which says nothing about
  // whatever the user has selected since — nulling here would snap shut a
  // drawer they opened by hand during a pending debounced search.
  const [appliedDeepLink, setAppliedDeepLink] = useState(selectedId);
  if (appliedDeepLink !== selectedId) {
    setAppliedDeepLink(selectedId);
    if (selectedId) setSelected(findSelection(data.items, selectedId));
  }

  const [expandedIds, setExpandedIds] = useState<ReadonlySet<string>>(new Set());
  const visibleColumns = FINDINGS_COLUMNS.filter((c) => columnVisibility[c.id] !== false);

  // The selected group's transcript-firing tally (session-scoped lists only) —
  // surfaces in the drawer footer so the "45 triggered vs 6 listed" gap is
  // explained right where the user is looking.
  const selectedFirings =
    selected && data.sessionFirings ? (data.sessionFirings[selected.finding.id] ?? 0) : null;

  return (
    <>
      <FindingsTableView
        groups={groups}
        columns={visibleColumns}
        selection={selected}
        expandedIds={expandedIds}
        onToggleExpand={(groupId) => {
          setExpandedIds((prev) => {
            const next = new Set(prev);
            if (next.has(groupId)) next.delete(groupId);
            else next.add(groupId);
            return next;
          });
        }}
        onSelectGroup={(group) => {
          setSelected({ finding: group });
        }}
        onSelectInstance={(group, instance) => {
          setSelected({ finding: group, instance });
        }}
        statusFilter={filters.status}
        {...(data.sessionFirings ? { sessionFirings: data.sessionFirings } : {})}
        {...(emptyState === undefined ? {} : { emptyState })}
        onLoadMore={
          cursor === null
            ? undefined
            : () => {
                startLoading(async () => {
                  // Built from the SERVER-RENDERED filters, never the live
                  // debounced query: a click during the debounce window would
                  // otherwise page a different filtered set into this one.
                  const next = await loadMoreGroupedFindings({
                    ...toGroupedQuery(filters, query, session, {
                      ...(from ? { from } : {}),
                    }),
                    cursor,
                  });
                  setPages((prev) => [...prev, next.items]);
                  setCursor(next.nextCursor);
                });
              }
        }
        loadingMore={loading}
        total={data.totals.groups}
      />

      <Sheet
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        {/* No description in this drawer — opt out of Radix's aria-describedby. */}
        <SheetContent className="p-0" aria-describedby={undefined}>
          {selected && (
            <FindingDetailView
              selection={selected}
              onSelectInstance={(instance) => {
                setSelected({ finding: selected.finding, instance });
              }}
              onBack={() => {
                setSelected({ finding: selected.finding });
              }}
              footer={
                sessionHref ? (
                  <div className="flex flex-col items-start gap-2">
                    {selectedFirings !== null && (
                      <p className="text-xs text-text-3">
                        {selectedFirings > 0
                          ? `Fired ${String(selectedFirings)} times in this session's transcript — the session's "triggered" tally counts every firing, this drawer shows unique values.`
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
                ) : undefined
              }
            />
          )}
        </SheetContent>
      </Sheet>
    </>
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
}) {
  const [pages, setPages] = useState<FindingInstanceDetail[][]>([]);
  const [cursor, setCursor] = useState<string | null>(data.nextCursor);
  const [loading, startLoading] = useTransition();
  const [selectedInstanceId, setSelectedInstanceId] = useState('');

  const [forData, setForData] = useState(data);
  if (forData !== data) {
    setForData(data);
    setPages([]);
    setCursor(data.nextCursor);
  }

  const items = dedupeById([...data.items, ...pages.flat()]);
  const selected = items.find((i) => i.id === selectedInstanceId) ?? null;

  return (
    <>
      <FindingsFlatTableView
        items={items}
        selectedId={selectedInstanceId}
        onSelect={(instance) => {
          setSelectedInstanceId(instance.id);
        }}
        total={data.totals.findings}
        hasMore={cursor !== null}
        loadingMore={loading}
        onLoadMore={() => {
          startLoading(async () => {
            const next = await loadMoreFindingInstances({
              ...toInstancesQuery(filters, query, session, {
                ...(from ? { from } : {}),
                ...(tools.length ? { tools } : {}),
                ...(repo ? { repo } : {}),
                ...(file ? { file } : {}),
              }),
              cursor,
            });
            setPages((prev) => [...prev, next.items]);
            setCursor(next.nextCursor);
          });
        }}
        {...(emptyState === undefined ? {} : { emptyState })}
      />

      <Sheet
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedInstanceId('');
        }}
      >
        <SheetContent className="p-0" aria-describedby={undefined}>
          {selected && (
            <FindingDetailView
              // The flat list has no group to step back to — every row IS a
              // single instance, so the drawer opens narrowed and stays there.
              selection={{ finding: instanceAsGroup(selected), instance: selected }}
              onSelectInstance={() => undefined}
              onBack={() => {
                setSelectedInstanceId('');
              }}
            />
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

function LocationsView({
  data,
  emptyState,
  onSelectFile,
}: {
  data: ListFindingLocationsResponse;
  emptyState: React.ReactNode;
  onSelectFile: (repo: string, file: string) => void;
}) {
  const [expandedRepos, setExpandedRepos] = useState<ReadonlySet<string>>(
    // Open the worst-severity repo by default so the view is never a list of
    // collapsed rows with nothing to read.
    () => new Set(data.items[0] ? [data.items[0].repo] : []),
  );

  return (
    <FindingsLocationsView
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

/**
 * First occurrence wins. The grouped list can append an includeId group out of
 * sort order, so that group arrives again at its natural cursor position on a
 * later page; without this the second copy would collide on its React key.
 */
function dedupeById<T extends { id: string }>(rows: T[]): T[] {
  const seen = new Set<string>();
  return rows.filter((r) => (seen.has(r.id) ? false : (seen.add(r.id), true)));
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
    <div className="mt-3 flex flex-wrap items-center gap-2 text-ui text-text-2">
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
            variant="ghost"
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
          <Button variant="ghost" size="sm" aria-label="Clear tool filter" onClick={onClearTools}>
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
            variant="ghost"
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
