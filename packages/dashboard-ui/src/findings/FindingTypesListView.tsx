'use client';
// The findings master list: a search box and a scrollable list of finding TYPES
// (rules), one row each. Props-driven — the app owns the query/selection state
// and the data fetch.
//
// Each row carries only what is a property of the TYPE: its severity, its
// category, its name, and how many findings it holds. Everything that varies
// between the findings of one type — provider, action, status, location, when —
// belongs to the findings themselves and is rendered by the detail panel beside
// this one, never folded into a row here.
//
// A row carries the type name, its category, and how many findings it holds —
// nothing else. Severity is a property of the rule too, but it is the FILTER
// above this list rather than a badge on every row: repeating one value down a
// column costs width the panel would rather spend on the name.
//
// It renders NO time. That is deliberate and worth keeping: with no relative
// label there is no clock to thread, so this component needs no `renderedAt` and
// cannot disagree with itself between the server render and hydration.
import type { FindingTypeSummary } from '@akasecurity/schema';
import {
  Card,
  cn,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  SEVERITY_DOT_CLASS,
} from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { KeyIcon, SearchIcon } from '../shared/icons.tsx';
import { CATEGORY_ICON_FALLBACK, categoryLabel, categoryStyle, SEVERITIES } from './meta.ts';

/**
 * The severity toggles, above the list they narrow.
 *
 * Severity lives here rather than in the page toolbar because it is a property
 * of the RULE: every finding of one type shares it, so it selects TYPES and
 * belongs beside the type list. The toolbar keeps the dimensions that vary
 * BETWEEN one type's findings, which narrow the detail panel instead.
 *
 * Every severity always renders, in fixed order, with its count from the facet
 * (absent ⇒ 0) — a closed enum, so no value can drop out of the row as the data
 * changes and shift the ones beside it.
 */
function SeverityFilter({
  counts,
  selected,
  onChange,
}: {
  counts: ReadonlyMap<string, number>;
  selected: readonly string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="mt-2.5 flex flex-wrap gap-1.5">
      {SEVERITIES.map((sev) => {
        const on = selected.includes(sev);
        return (
          <button
            key={sev}
            type="button"
            aria-pressed={on}
            onClick={() => {
              onChange(on ? selected.filter((s) => s !== sev) : [...selected, sev]);
            }}
            className={cn(
              'inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-full border px-2.5 text-xs font-semibold capitalize',
              on
                ? 'border-primary bg-primary-tint text-primary'
                : 'border-border bg-surface text-text-2',
            )}
          >
            <span className={cn('size-1.5 rounded-full', SEVERITY_DOT_CLASS[sev])} />
            {sev}
            <span className="text-label font-bold opacity-70">{counts.get(sev) ?? 0}</span>
          </button>
        );
      })}
    </div>
  );
}

function TypeRow({
  type,
  sel,
  onClick,
}: {
  type: FindingTypeSummary;
  sel: boolean;
  onClick: () => void;
}) {
  const Icon = CATEGORY_ICON_FALLBACK[type.category] ?? KeyIcon;
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
      <div className="flex min-w-0 items-center gap-2.5">
        <span
          className={cn(
            'flex size-7 shrink-0 items-center justify-center rounded-lg',
            categoryStyle(type.category),
          )}
        >
          <Icon aria-hidden focusable={false} className="size-4" />
        </span>
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <span className="truncate text-sm font-semibold text-text" title={type.subtype}>
            {type.subtype}
          </span>
          <span className="truncate text-xs text-text-3">{categoryLabel(type.category)}</span>
        </div>
        <span className="shrink-0 text-xs font-semibold tabular-nums text-text-2">
          {type.instanceCount}
        </span>
      </div>
    </button>
  );
}

/**
 * Layout contract, matching the sibling tables: the card fills its container's
 * height and scrolls its rows internally, so the caller must mount it in a
 * height-constrained parent (an unbroken h-full/min-h-0 chain).
 */
export function FindingTypesListView({
  types,
  activeId,
  onSelect,
  query,
  onQueryChange,
  severityCounts,
  selectedSeverities,
  onSeverityChange,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  loadingNextPage = false,
  pageStart,
  total,
  emptyState,
}: {
  types: FindingTypeSummary[];
  /** The selected type's id (its rule id), or '' when nothing is selected. */
  activeId: string;
  onSelect: (type: FindingTypeSummary) => void;
  query: string;
  onQueryChange: (next: string) => void;
  /** severity → how many TYPES carry it, with this filter's own value excluded. */
  severityCounts: ReadonlyMap<string, number>;
  selectedSeverities: readonly string[];
  onSeverityChange: (next: string[]) => void;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  /**
   * Advance to the next page. Absent ⇒ the caller cannot paginate and the footer
   * is not rendered at all.
   */
  onNextPage?: (() => void) | undefined;
  onPreviousPage?: (() => void) | undefined;
  loadingNextPage?: boolean;
  /** 1-indexed position of `types[0]` in the whole result set — for "51–100 of N". */
  pageStart?: number | undefined;
  /** Types matching the filters across the whole scope, not just this page. */
  total?: number | undefined;
  /**
   * Shown instead of the default copy when `types` is empty — lets a caller
   * distinguish an empty store (onboarding hint) from a filter that matched
   * nothing. Absent ⇒ the default message.
   */
  emptyState?: ReactNode;
}) {
  return (
    <Card className="flex h-full flex-col overflow-hidden shadow-sm">
      <div className="border-b border-border p-3">
        <div className="relative">
          <SearchIcon
            aria-hidden
            focusable={false}
            className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-3"
          />
          <input
            type="text"
            aria-label="Search finding types"
            value={query}
            onChange={(ev) => {
              onQueryChange(ev.target.value);
            }}
            spellCheck={false}
            placeholder="Search types…"
            className="h-9 w-full rounded-lg border border-border-field bg-surface-2 pl-9 pr-3 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40"
          />
        </div>
        <SeverityFilter
          counts={severityCounts}
          selected={selectedSeverities}
          onChange={onSeverityChange}
        />
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-3">
        {types.length === 0 ? (
          <div className="grid flex-1 place-items-center p-6 text-center text-xs text-text-3">
            {emptyState ?? 'No types match these filters.'}
          </div>
        ) : (
          types.map((t) => (
            <TypeRow
              key={t.id}
              type={t}
              sel={t.id === activeId}
              onClick={() => {
                onSelect(t);
              }}
            />
          ))
        )}
      </div>

      {onNextPage && types.length > 0 && (
        <Pagination>
          <PaginationPrevious
            disabled={!hasPreviousPage || loadingNextPage}
            onClick={onPreviousPage}
          />
          <PaginationStatus>
            {total === undefined || pageStart === undefined
              ? `${String(types.length)} shown`
              : `${String(pageStart)}–${String(pageStart + types.length - 1)} of ${String(total)} types`}
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
