'use client';
// The findings master list, folded by WHERE a finding lives: one row per
// (repo, file) pair. Props-driven — the app owns the selection, the paging and
// the data fetch, exactly as it does for the sibling type list.
//
// Every field on a row is a FOLD over the findings at that location, because a
// location owns nothing of its own. That is why the page renders one filter
// toolbar above both panels rather than splitting the dimensions between them:
// each filter narrows the findings first and the locations fall out of what
// survives, so a row's count is exactly what the panel beside it lists.
//
// It is a flat list rather than repos nesting files. A rollup can only be paged
// by repo, which leaves the file list inside it unbounded, and two-level
// pagination inside an expand/collapse table is what pushed the by-type view to
// master/detail in the first place.
//
// Unlike the type list this one DOES render a time, so it takes `renderedAt`
// rather than reading a clock: a component that picks its own instant renders
// one string on the server and another when the browser hydrates it. It uses
// the SHORT form, which fits the column and is also the only one that closes
// the hydration question outright — the long form goes through
// Intl.RelativeTimeFormat, and a locale mismatch is what passing an instant
// explicitly does not reconcile.
import type { FindingLocationSummary } from '@akasecurity/schema';
import {
  Badge,
  Card,
  cn,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  SeverityBadge,
} from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { compactCount, numberFormat } from '../lib/numberFormat.ts';
import { relativeTimeShort } from '../lib/relativeTime.ts';
import { findingStatusMeta } from './meta.ts';

/**
 * How many rule names a row spells out before it summarises the rest.
 *
 * A display bound, not a data one: the read returns every distinct rule at a
 * location, so `ruleIds.length` is a tally and the row can say truthfully how
 * many it is not showing. It used to be a cap in the store, where the row had
 * no way to tell a location with 20 rules from one with 200.
 */
const LOCATION_RULE_CHIPS = 3;

function LocationRow({
  location,
  sel,
  onClick,
  renderedAt,
}: {
  location: FindingLocationSummary;
  sel: boolean;
  onClick: () => void;
  renderedAt: number;
}) {
  const shown = location.ruleIds.slice(0, LOCATION_RULE_CHIPS);
  // Counted against the WHOLE list, never against `shown` — off the slice this
  // is always zero and the row silently claims to show everything it has.
  const hidden = location.ruleIds.length - shown.length;
  const status = location.status === undefined ? null : findingStatusMeta(location.status);

  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={sel ? 'true' : undefined}
      className={cn(
        'w-full cursor-pointer rounded-lg px-3 py-2.5 text-left transition-colors',
        sel ? 'bg-primary-tint' : 'hover:bg-surface-2',
      )}
    >
      <div className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={location.maxSeverity} />
        <span
          className={cn(
            'min-w-0 flex-1 text-xs break-words [word-break:break-word]',
            location.repo ? 'text-text-3' : 'italic text-text-3',
          )}
        >
          {location.repo || 'No repository recorded'}
        </span>
        {status && (
          <Badge variant={status.badge} className="h-5 shrink-0">
            {status.label}
          </Badge>
        )}
      </div>

      {/* Wrapped, never truncated. Tailwind's `truncate` puts the ellipsis at the
          END, which on a path elides the filename — the one part that
          distinguishes two rows under the same directory, and the part a reader
          is scanning for. `[word-break:break-word]` is what lets a long
          unbroken segment wrap instead of overflowing the panel. */}
      <div
        className={cn(
          'mt-1 text-sm font-semibold break-words [word-break:break-word]',
          location.file ? 'text-text' : 'italic text-text-3',
        )}
      >
        {location.file || 'No file recorded'}
      </div>

      <div className="mt-1 flex min-w-0 items-center gap-1.5">
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-1">
          {shown.map((ruleId) => (
            <span
              key={ruleId}
              className="max-w-full truncate rounded border border-border px-1.5 py-px text-label text-text-3"
            >
              {ruleId}
            </span>
          ))}
          {hidden > 0 && <span className="shrink-0 text-label text-text-3">+{hidden} more</span>}
        </span>
        {/* Compact, with the exact count on the title. The short form rounds
            across its own boundary — 9,999 reads `10k` — so the number a reader
            might act on has to stay reachable. Both formatters pin en-US, so
            neither is a hydration mismatch. */}
        <span
          className="shrink-0 text-xs font-semibold tabular-nums text-text-2"
          title={`${numberFormat.format(location.instanceCount)} ${
            location.instanceCount === 1 ? 'finding' : 'findings'
          }`}
        >
          {compactCount(location.instanceCount)}
        </span>
        <span className="shrink-0 text-xs text-text-3">
          {relativeTimeShort(location.latestDetectedAt, renderedAt)}
        </span>
      </div>
    </button>
  );
}

/**
 * Layout contract, matching the sibling lists: the card fills its container's
 * height and scrolls its rows internally, so the caller must mount it in a
 * height-constrained parent (an unbroken h-full/min-h-0 chain).
 */
export function FindingLocationsListView({
  locations,
  activeId,
  onSelect,
  renderedAt,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  loadingNextPage = false,
  pageStart,
  total,
  emptyState,
}: {
  locations: FindingLocationSummary[];
  /** The selected location's id, or '' when none is pinned. */
  activeId: string;
  onSelect: (location: FindingLocationSummary) => void;
  /**
   * The instant this render is measured against, in epoch milliseconds. The
   * host captures one and every relative label below reads it. Required: a view
   * that picks its own instant renders one string while the server renders it
   * and another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  onNextPage?: (() => void) | undefined;
  onPreviousPage?: (() => void) | undefined;
  loadingNextPage?: boolean;
  pageStart?: number | undefined;
  total?: number | undefined;
  /**
   * Rendered instead of the default message when the list is empty, so the host
   * can distinguish an empty store (onboarding hint) from a filter that matched
   * nothing. Absent ⇒ the default message.
   */
  emptyState?: ReactNode;
}) {
  return (
    <Card className="flex h-full flex-col overflow-hidden shadow-sm">
      <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-3">
        {locations.length === 0 ? (
          <div className="grid flex-1 place-items-center p-6 text-center text-xs text-text-3">
            {emptyState ?? 'No locations match these filters.'}
          </div>
        ) : (
          locations.map((location) => (
            <LocationRow
              key={location.id}
              location={location}
              sel={location.id === activeId}
              renderedAt={renderedAt}
              onClick={() => {
                onSelect(location);
              }}
            />
          ))
        )}
      </div>

      {/* Gated on the PAGINATION state, not on `locations.length`. A page can
          arrive empty and still have somewhere to go back to: the caller appends
          the selected location to page 0 out of sort order, and dropping that
          repeat when paging reaches its natural position can empty the page.
          Gated on the row count, the footer carrying Previous then vanishes at
          exactly the moment it is the only way out. */}
      {onNextPage && (hasPreviousPage || hasNextPage || locations.length > 0) && (
        <Pagination>
          <PaginationPrevious
            disabled={!hasPreviousPage || loadingNextPage}
            onClick={onPreviousPage}
          />
          <PaginationStatus>
            {/* An EMPTY page takes the count branch, not the range one. A page
                can arrive empty behind a live cursor — the caller drops the
                appended selection once paging reaches its natural position — and
                the range then runs backwards (`52–51 of 51`), directly above the
                Previous button that is the only way out of it. */}
            {locations.length === 0 || total === undefined || pageStart === undefined
              ? `${String(locations.length)} shown`
              : `${String(pageStart)}–${String(pageStart + locations.length - 1)} of ${String(total)} locations`}
          </PaginationStatus>
          <PaginationNext
            disabled={!hasNextPage || loadingNextPage}
            loading={loadingNextPage}
            onClick={onNextPage}
          />
        </Pagination>
      )}
    </Card>
  );
}
