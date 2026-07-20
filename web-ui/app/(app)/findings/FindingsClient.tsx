'use client';

import {
  ColumnsMenu,
  type ColumnVisibility,
  FindingDetailView,
  FINDINGS_COLUMNS,
  type FindingsFilters,
  FindingsTableView,
  FindingsToolbarView,
  PageHead,
  type Selection,
} from '@akasecurity/dashboard-ui';
import type { FindingGroup, ListGroupedFindingsResponse } from '@akasecurity/schema';
import { Badge, Button, Sheet, SheetContent } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useState } from 'react';

import { TerminalIcon, XIcon } from '../../components/icons';
import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { buildFindingsParams } from './filters';

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

/**
 * Client shell for the OSS findings page. The grouped data + facets + current
 * filters come from the Server Component (which reads the local store per URL);
 * filter/search changes push a new URL so the server re-queries — the OSS store
 * is server-only, so filtering can't happen in the browser. Expansion, selection
 * (the detail sheet) and column visibility are local client state; the Activity
 * page's ?finding= deep link seeds the selection, and its ?session= scope rides
 * every pushed URL so the context survives filter changes.
 */
export function FindingsClient({
  data,
  filters,
  query: initialQuery,
  session,
  selectedId,
  hasMore,
}: {
  data: ListGroupedFindingsResponse;
  filters: FindingsFilters;
  query: string;
  /** Session id the list is scoped to ('' when unscoped). */
  session: string;
  /** The ?finding= deep-link target ('' when absent). */
  selectedId: string;
  hasMore: boolean;
}) {
  const router = useRouter();
  const pathname = usePathname();

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
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>({});

  const buildUrl = useCallback(
    (nextFilters: FindingsFilters, nextQuery: string, nextSession: string) => {
      const qs = buildFindingsParams(nextFilters, nextQuery, nextSession).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook; a
  // debounced search keeps the current filters and session scope.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl(filters, term, session),
  );

  // Push filters + search into the URL so the Server Component re-queries.
  const pushState = useCallback(
    (nextFilters: FindingsFilters, nextQuery: string, nextSession: string) => {
      onNavigate(nextQuery);
      router.push(buildUrl(nextFilters, nextQuery, nextSession));
    },
    [onNavigate, router, buildUrl],
  );

  const visibleColumns = FINDINGS_COLUMNS.filter((c) => columnVisibility[c.id] !== false);

  // Distinguish an empty local store (first run — nothing captured yet) from a
  // filter/search that simply matched nothing, so a fresh self-hosted install
  // gets an onboarding hint instead of a filter-implying "no matches" message.
  const noActiveFilters =
    query.trim() === '' &&
    session === '' &&
    filters.severity.length === 0 &&
    filters.type.length === 0 &&
    filters.provider.length === 0 &&
    filters.action.length === 0;

  const toggleExpand = (groupId: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) next.delete(groupId);
      else next.add(groupId);
      return next;
    });
  };

  const sessionHref = session ? `/activity?id=${encodeURIComponent(session)}` : null;

  // The selected group's transcript-firing tally (session-scoped lists only) —
  // surfaces in the drawer footer so the "45 triggered vs 6 listed" gap is
  // explained right where the user is looking.
  const selectedFirings =
    selected && data.sessionFirings ? (data.sessionFirings[selected.finding.id] ?? 0) : null;

  // Rules that fired in the session's transcript but were never enforced live
  // have no group row here — without naming them, part of the session's
  // "N triggered" tally would reconcile against nothing on this page.
  const transcriptOnly = data.sessionFirings
    ? Object.entries(data.sessionFirings).filter(([rule]) => !data.items.some((g) => g.id === rule))
    : [];

  return (
    <div className="flex flex-col px-8 pb-10 pt-7">
      <PageHead
        title="Findings"
        sub="Every sensitive-data finding across providers"
        actions={
          <ColumnsMenu
            columns={FINDINGS_COLUMNS}
            visibility={columnVisibility}
            onChange={setColumnVisibility}
          />
        }
      />

      <FindingsToolbarView
        facets={data.facets}
        filters={filters}
        onFiltersChange={(next) => {
          pushState(next, query, session);
        }}
        query={query}
        onQueryChange={setQuery}
        findingCount={data.totals.findings}
        typeCount={data.totals.groups}
      />

      {/* The Activity page's session scope — visible, linkable and clearable. */}
      {sessionHref && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-ui text-text-2">
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
            onClick={() => {
              pushState(filters, query, '');
            }}
          >
            <XIcon aria-hidden focusable={false} className="size-3.5" />
            Clear
          </Button>
          {transcriptOnly.length > 0 && (
            <p className="w-full text-xs text-text-3">
              {`Also detected in this session's transcript without live enforcement: `}
              {transcriptOnly.map(([rule, n]) => `${rule} ×${String(n)}`).join(', ')}
            </p>
          )}
        </div>
      )}

      <div className="mt-4">
        <FindingsTableView
          groups={data.items}
          columns={visibleColumns}
          selection={selected}
          expandedIds={expandedIds}
          onToggleExpand={toggleExpand}
          onSelectGroup={(group) => {
            setSelected({ finding: group });
          }}
          onSelectInstance={(group, instance) => {
            setSelected({ finding: group, instance });
          }}
          hasMore={hasMore}
          {...(data.sessionFirings ? { sessionFirings: data.sessionFirings } : {})}
          emptyState={
            noActiveFilters ? (
              <p className="py-8 text-center text-sm text-text-3">
                No findings yet — run the plugin or <code>aka scan</code> to populate the local
                store.
              </p>
            ) : undefined
          }
        />
      </div>

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
    </div>
  );
}
