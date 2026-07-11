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
import type { ListGroupedFindingsResponse } from '@akasecurity/schema';
import { Sheet, SheetContent } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useState } from 'react';

import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { buildFindingsParams } from './filters';

/**
 * Client shell for the OSS findings page. The grouped data + facets + current
 * filters come from the Server Component (which reads the local store per URL);
 * filter/search changes push a new URL so the server re-queries — the OSS store
 * is server-only, so filtering can't happen in the browser. Expansion, selection
 * (the detail sheet) and column visibility are local client state.
 *
 * The detail sheet passes no `footer`, so the drawer omits the optional
 * matched-policy / Resolve / Action sections — there are no finding mutations here.
 */
export function FindingsClient({
  data,
  filters,
  query: initialQuery,
  hasMore,
}: {
  data: ListGroupedFindingsResponse;
  filters: FindingsFilters;
  query: string;
  hasMore: boolean;
}) {
  const router = useRouter();
  const pathname = usePathname();

  const [selected, setSelected] = useState<Selection | null>(null);
  const [expandedIds, setExpandedIds] = useState<ReadonlySet<string>>(new Set());
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibility>({});

  const buildUrl = useCallback(
    (nextFilters: FindingsFilters, nextQuery: string) => {
      const qs = buildFindingsParams(nextFilters, nextQuery).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook; a
  // debounced search keeps the current filters.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl(filters, term),
  );

  // Push filters + search into the URL so the Server Component re-queries.
  const pushState = useCallback(
    (nextFilters: FindingsFilters, nextQuery: string) => {
      onNavigate(nextQuery);
      router.push(buildUrl(nextFilters, nextQuery));
    },
    [onNavigate, router, buildUrl],
  );

  const visibleColumns = FINDINGS_COLUMNS.filter((c) => columnVisibility[c.id] !== false);

  // Distinguish an empty local store (first run — nothing captured yet) from a
  // filter/search that simply matched nothing, so a fresh self-hosted install
  // gets an onboarding hint instead of a filter-implying "no matches" message.
  const noActiveFilters =
    query.trim() === '' &&
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
          pushState(next, query);
        }}
        query={query}
        onQueryChange={setQuery}
        findingCount={data.totals.findings}
        typeCount={data.totals.groups}
      />

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
            />
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
