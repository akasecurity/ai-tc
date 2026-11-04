'use client';
// The one footer every paged table renders: the range on the left, and Previous,
// the page selector and Next on the right. Props-driven like the rest of this
// package — the host owns which page is showing and how it gets there.
import {
  Input,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import { formatNumber, parseCount } from '../lib/numberFormat.ts';

/** The footer's page indicator and selector, as a view takes them from its host. */
export interface TablePageProps {
  /** The page showing now, 1-indexed. Absent, or no `pageCount` ⇒ no page indicator. */
  page?: number | undefined;
  pageCount?: number | undefined;
  /** Moves to a 1-indexed page. Absent ⇒ the page number is plain text. */
  onPageChange?: ((page: number) => void) | undefined;
  /** Why the last page move did not happen. */
  pageError?: string | null | undefined;
}

export interface TablePaginationProps extends TablePageProps {
  /** Rows on the page showing now. */
  itemCount: number;
  /** 1-indexed position of the page's first row. Absent ⇒ "{itemCount} shown". */
  pageStart?: number | undefined;
  /** Rows across the whole list. Absent ⇒ "{itemCount} shown". */
  total?: number | undefined;
  /** What the rows are, as the range names them: `findings`. */
  noun?: string | undefined;
  hasPreviousPage: boolean;
  hasNextPage: boolean;
  onPreviousPage?: (() => void) | undefined;
  onNextPage?: (() => void) | undefined;
  loading?: boolean | undefined;
  /**
   * The locale counts are formatted in: the one the host resolved for this
   * request. Required for the reason `renderedAt` is. See ../lib/locale.ts.
   */
  locale: string;
}

/**
 * The range line. An empty page takes the zero form rather than the range one: a
 * page can arrive empty behind a live cursor, and `pageStart + itemCount - 1`
 * would then read backwards (`52–51 of 51`).
 */
function statusText({
  itemCount,
  pageStart,
  total,
  noun,
  locale,
}: Pick<TablePaginationProps, 'itemCount' | 'pageStart' | 'total' | 'noun' | 'locale'>): string {
  const suffix = noun === undefined ? '' : ` ${noun}`;
  if (total === undefined || pageStart === undefined) {
    return `${formatNumber(itemCount, locale)} shown`;
  }
  const whole = `${formatNumber(total, locale)}${suffix}`;
  if (itemCount === 0) return `${formatNumber(0, locale)} of ${whole}`;
  const first = formatNumber(pageStart, locale);
  const last = formatNumber(pageStart + itemCount - 1, locale);
  return `${first}–${last} of ${whole}`;
}

/**
 * The value a typed page number commits to, or null when the text names no page.
 * It may carry the grouping the footer itself displays (`1,000` in en-US). A
 * number past either end lands on that end, since the reader's intent is plain.
 */
export function committedPage(text: string, pageCount: number, locale: string): number | null {
  const value = parseCount(text, locale);
  return value === null ? null : Math.min(Math.max(1, value), pageCount);
}

/**
 * A number box rather than a dropdown, because a page list can run to thousands.
 * It holds a draft until Enter, so typing `120` does not visit pages 1 and 12 on
 * the way and clicking elsewhere never navigates: leaving the field or pressing
 * Escape drops the draft. While a page loads the field is read-only rather than
 * disabled, because disabling the focused element would drop keyboard focus.
 */
function PageSelector({
  page,
  pageCount,
  onPageChange,
  busy,
  locale,
}: {
  page: number;
  pageCount: number;
  onPageChange: (page: number) => void;
  busy: boolean;
  locale: string;
}) {
  const [draft, setDraft] = useState(String(page));

  // Follows a page change from Previous, Next or the host, and a load that ended
  // without one, so a move the host refused does not leave its number showing.
  // Adjusted during render so no frame shows the old number beside the new rows.
  const [synced, setSynced] = useState({ page, busy });
  if (synced.page !== page || synced.busy !== busy) {
    setSynced({ page, busy });
    if (synced.page !== page || !busy) setDraft(String(page));
  }

  const commit = () => {
    // An untouched number is not a request to move, even where it reads past a
    // page count that is behind the store.
    if (busy || draft === String(page)) return;
    const next = committedPage(draft, pageCount, locale);
    setDraft(String(next ?? page));
    if (next !== null && next !== page) onPageChange(next);
  };

  const revert = () => {
    if (!busy) setDraft(String(page));
  };

  return (
    <Input
      aria-label="Go to page"
      aria-busy={busy}
      inputMode="numeric"
      autoComplete="off"
      value={draft}
      readOnly={busy}
      disabled={pageCount <= 1}
      onChange={(event) => {
        setDraft(event.target.value);
      }}
      onBlur={revert}
      onKeyDown={(event) => {
        if (event.key === 'Enter') commit();
        if (event.key === 'Escape') revert();
      }}
      className="h-8 w-14 px-1.5 text-center text-xs tabular-nums"
    />
  );
}

export function TablePagination({
  itemCount,
  pageStart,
  total,
  noun,
  page,
  pageCount,
  onPageChange,
  pageError,
  hasPreviousPage,
  hasNextPage,
  onPreviousPage,
  onNextPage,
  loading = false,
  locale,
}: TablePaginationProps) {
  return (
    <Pagination className="flex-wrap justify-end gap-x-3 gap-y-2 border-t border-border px-5 py-3">
      <PaginationStatus className="mr-auto">
        {statusText({ itemCount, pageStart, total, noun, locale })}
      </PaginationStatus>
      {pageError !== undefined && pageError !== null && (
        <p role="alert" className="text-xs text-sev-high-ink">
          {pageError}
        </p>
      )}
      <div className="flex items-center gap-3">
        <PaginationPrevious disabled={!hasPreviousPage || loading} onClick={onPreviousPage} />
        {page !== undefined && pageCount !== undefined && (
          <span className="flex items-center gap-1.5 whitespace-nowrap text-xs text-text-2">
            Page{' '}
            {onPageChange === undefined ? (
              formatNumber(page, locale)
            ) : (
              <PageSelector
                page={page}
                pageCount={pageCount}
                onPageChange={onPageChange}
                busy={loading}
                locale={locale}
              />
            )}{' '}
            of {formatNumber(pageCount, locale)}
          </span>
        )}
        <PaginationNext disabled={!hasNextPage || loading} loading={loading} onClick={onNextPage} />
      </div>
    </Pagination>
  );
}
