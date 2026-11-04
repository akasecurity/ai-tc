// @vitest-environment jsdom
//
// The page selector is why this suite needs a DOM: what it owes the reader is
// all about what happens after typing, and a server render sees none of that.
import { act } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { parseCount } from '../../src/lib/numberFormat.ts';
import {
  appendPage,
  pageCountOf,
  type PagedRun,
  planNextMove,
  planPageMove,
  runHasNext,
  runHasPrevious,
  runItems,
  runPage,
  runPageCount,
  runPageStart,
  startRun,
} from '../../src/lib/pagination.ts';
import {
  committedPage,
  TablePagination,
  type TablePaginationProps,
} from '../../src/shared/TablePagination.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const BASE: TablePaginationProps = {
  itemCount: 50,
  pageStart: 1,
  total: 266775,
  noun: 'findings',
  page: 1,
  pageCount: 5336,
  onPageChange: () => undefined,
  hasPreviousPage: false,
  hasNextPage: true,
  locale: 'en-US',
};

const statusOf = (props: Partial<TablePaginationProps>): string | undefined => {
  const html = renderToStaticMarkup(<TablePagination {...BASE} {...props} />);
  return /data-slot="pagination-status"[^>]*>([^<]*)</.exec(html)?.[1];
};

describe('TablePagination status', () => {
  it('formats the range and the total in the given locale', () => {
    expect(statusOf({ pageStart: 1001, itemCount: 50 })).toBe('1,001–1,050 of 266,775 findings');
    expect(statusOf({ pageStart: 1001, itemCount: 50, locale: 'de-DE' })).toBe(
      '1.001–1.050 of 266.775 findings',
    );
  });

  it('never reads backwards on an empty page', () => {
    expect(statusOf({ pageStart: 52, itemCount: 0, total: 51 })).toBe('0 of 51 findings');
  });

  it('falls back to the row count when the total or the position is unknown', () => {
    expect(statusOf({ total: undefined, itemCount: 2000 })).toBe('2,000 shown');
    expect(statusOf({ pageStart: undefined, itemCount: 3 })).toBe('3 shown');
  });

  it('leaves the noun off when there is none', () => {
    expect(statusOf({ noun: undefined })).toBe('1–50 of 266,775');
  });
});

describe('TablePagination layout', () => {
  it('orders the status, Previous, the page and Next', () => {
    const html = renderToStaticMarkup(<TablePagination {...BASE} />);
    const at = (needle: string) => html.indexOf(needle);
    expect(at('pagination-status')).toBeGreaterThan(-1);
    expect(at('pagination-status')).toBeLessThan(at('pagination-previous'));
    expect(at('pagination-previous')).toBeLessThan(at('Go to page'));
    expect(at('Go to page')).toBeLessThan(at('pagination-next'));
  });

  it('formats the page count in the given locale', () => {
    expect(renderToStaticMarkup(<TablePagination {...BASE} locale="de-DE" />)).toContain(
      'of 5.336',
    );
  });

  it('renders plain text without a page handler and nothing without a page', () => {
    const plain = renderToStaticMarkup(<TablePagination {...BASE} onPageChange={undefined} />);
    expect(plain).not.toContain('Go to page');
    expect(plain).toContain('Page');
    const none = renderToStaticMarkup(<TablePagination {...BASE} page={undefined} />);
    expect(none).not.toContain('Page');
  });

  it('disables the selector with only one page', () => {
    const html = renderToStaticMarkup(<TablePagination {...BASE} pageCount={1} />);
    expect(/<input[^>]*disabled=""/.test(html)).toBe(true);
  });
});

describe('committedPage', () => {
  it('reads a number in range as itself', () => {
    expect(committedPage('12', 5336, 'en-US')).toBe(12);
    expect(committedPage(' 12 ', 5336, 'en-US')).toBe(12);
  });

  it('lands a number past either end on that end', () => {
    expect(committedPage('9999', 5336, 'en-US')).toBe(5336);
    expect(committedPage('0', 5336, 'en-US')).toBe(1);
  });

  it('refuses text that names no page', () => {
    for (const text of ['', ' ', 'abc', '1.5', '-3']) {
      expect(committedPage(text, 5336, 'en-US')).toBeNull();
    }
  });

  it('reads the grouping the footer displays', () => {
    expect(committedPage('1,000', 5336, 'en-US')).toBe(1000);
    expect(committedPage('1.000', 5336, 'de-DE')).toBe(1000);
  });
});

describe('parseCount', () => {
  it('reads each locale’s own grouping, and only that', () => {
    expect(parseCount('1,000', 'en-US')).toBe(1000);
    expect(parseCount('1,00,000', 'en-IN')).toBe(100000);
    expect(parseCount('1.000', 'de-DE')).toBe(1000);
    expect(parseCount('1 000', 'fr-FR')).toBe(1000);
    expect(parseCount('1.000', 'en-US')).toBeNull();
    expect(parseCount('1,000', 'de-DE')).toBeNull();
  });

  it('refuses text that only looks grouped', () => {
    expect(parseCount('1.5', 'de-DE')).toBeNull();
    expect(parseCount('1,0000', 'en-US')).toBeNull();
    expect(parseCount('1000,000', 'en-US')).toBeNull();
    expect(parseCount(',000', 'en-US')).toBeNull();
    expect(parseCount('12a', 'en-US')).toBeNull();
  });
});

describe('page arithmetic', () => {
  it('counts whole pages, rounding a partial one up', () => {
    expect(pageCountOf(266775, 50)).toBe(5336);
    expect(pageCountOf(100, 50)).toBe(2);
    expect(pageCountOf(101, 50)).toBe(3);
  });

  it('reads an empty list as one page', () => {
    expect(pageCountOf(0, 50)).toBe(1);
  });

  // Pages 10, 11 and 12 are cached.
  const CACHED: PagedRun<string> = {
    pages: [['a'], ['b'], ['c']],
    cursors: ['c1', 'c2', 'c3'],
    index: 1,
    firstCached: 10,
    total: 1000,
  };

  it('replays a page inside the cached run', () => {
    expect(planPageMove(10, CACHED, 50)).toEqual({ kind: 'cached', index: 0 });
    expect(planPageMove(12, CACHED, 50)).toEqual({ kind: 'cached', index: 2 });
  });

  it('reads a page outside the cached run from its row position', () => {
    expect(planPageMove(9, CACHED, 50)).toEqual({ kind: 'fetch', offset: 450 });
    expect(planPageMove(13, CACHED, 50)).toEqual({ kind: 'fetch', offset: 650 });
  });

  it('steps forward through the run, then by cursor, then stops', () => {
    expect(planNextMove(CACHED)).toEqual({ kind: 'cached', index: 2 });
    expect(planNextMove({ ...CACHED, index: 2 })).toEqual({ kind: 'fetch', cursor: 'c3' });
    expect(planNextMove(startRun(['a'], null, 1))).toBeNull();
  });

  it('numbers a page from its place in the list, whatever its neighbours held', () => {
    // 51 rows on the first page: the selected row the server appended.
    const first = startRun(Array.from({ length: 51 }, String), 'c', 214);
    const second = appendPage(first, ['x'], null, 214);
    expect(runPageStart(first, 50)).toBe(1);
    expect(runPageStart(second, 50)).toBe(51);
    expect(runPageStart(startRun(['x'], null, 214, 1), 50)).toBe(51);
  });

  it('reports where the run stands', () => {
    expect(runPage(CACHED)).toBe(12);
    expect(runItems(CACHED)).toEqual(['b']);
    expect(runHasPrevious(CACHED)).toBe(true);
    expect(runHasPrevious(startRun(['a'], null, 1))).toBe(false);
    expect(runHasPrevious(startRun(['a'], null, 1, 1))).toBe(true);
    expect(runHasNext(CACHED)).toBe(true);
    expect(runHasNext(startRun(['a'], 'c', 1))).toBe(true);
    expect(runHasNext(startRun(['a'], null, 1))).toBe(false);
  });

  it('never counts fewer pages than the one showing', () => {
    expect(runPageCount(startRun(['a'], null, 500), 50)).toBe(10);
    expect(runPageCount(startRun(['a'], null, 500, 11), 50)).toBe(12);
  });

  it('adopts the total of the page it appends', () => {
    const grown = appendPage(startRun(['a'], 'c', 50), ['b'], null, 75);
    expect(grown.total).toBe(75);
    expect(grown.index).toBe(1);
    expect(grown.cursors).toEqual(['c', null]);
  });
});

describe('page selector', () => {
  let mounted: MountedRoot;

  beforeEach(() => {
    mounted = mountRoot();
  });

  afterEach(() => {
    unmountMountedRoot(mounted);
  });

  const field = (): HTMLInputElement => {
    const el = mounted.host.querySelector('input');
    if (el === null) throw new Error('no page field');
    return el;
  };

  const type = (value: string) => {
    act(() => {
      const input = field();
      // A property descriptor's `set`, applied with an explicit receiver below.
      // eslint-disable-next-line @typescript-eslint/unbound-method
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      if (setter === undefined) throw new Error('no value setter');
      Reflect.apply(setter, input, [value]);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  };

  const press = (key: string) => {
    act(() => {
      field().dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
    });
  };

  const blur = () => {
    act(() => {
      field().focus();
      field().blur();
    });
  };

  const show = (props: Partial<TablePaginationProps> = {}) => {
    renderRoot(mounted.root, <TablePagination {...BASE} {...props} />);
  };

  it('does not move while the reader is still typing', () => {
    const onPageChange = vi.fn();
    show({ onPageChange });
    type('120');
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('moves on Enter', () => {
    const onPageChange = vi.fn();
    show({ onPageChange });
    type('120');
    press('Enter');
    expect(onPageChange).toHaveBeenCalledExactlyOnceWith(120);
  });

  it('drops the draft on leaving the field, without moving', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 4 });
    type('7');
    blur();
    expect(onPageChange).not.toHaveBeenCalled();
    expect(field().value).toBe('4');
  });

  it('drops the draft on Escape, without moving', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 4 });
    type('7');
    press('Escape');
    expect(onPageChange).not.toHaveBeenCalled();
    expect(field().value).toBe('4');
  });

  it('stays focusable while a page loads, and ignores Enter until it lands', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 4 });
    type('9');
    show({ onPageChange, page: 4, loading: true });
    expect(field().disabled).toBe(false);
    expect(field().readOnly).toBe(true);
    expect(field().getAttribute('aria-busy')).toBe('true');
    press('Enter');
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('does not move on an untouched number past a stale page count', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 360, pageCount: 359 });
    press('Enter');
    expect(onPageChange).not.toHaveBeenCalled();
    expect(field().value).toBe('360');
  });

  it('reads a typed number in the footer’s own locale', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, locale: 'de-DE' });
    type('1.000');
    press('Enter');
    expect(onPageChange).toHaveBeenCalledExactlyOnceWith(1000);
  });

  it('shows why a move did not happen', () => {
    show({ pageError: 'That page is no longer there.' });
    expect(mounted.host.querySelector('[role="alert"]')?.textContent).toBe(
      'That page is no longer there.',
    );
    show({ pageError: null });
    expect(mounted.host.querySelector('[role="alert"]')).toBeNull();
  });

  it('lands a number past the end on the last page and shows it', () => {
    const onPageChange = vi.fn();
    show({ onPageChange });
    type('999999');
    press('Enter');
    expect(onPageChange).toHaveBeenCalledExactlyOnceWith(5336);
    expect(field().value).toBe('5336');
  });

  it('puts the current page back when the text names no page', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 4 });
    type('abc');
    press('Enter');
    expect(onPageChange).not.toHaveBeenCalled();
    expect(field().value).toBe('4');
  });

  it('does not move when the number is the page already showing', () => {
    const onPageChange = vi.fn();
    show({ onPageChange, page: 4 });
    type('4');
    press('Enter');
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('keeps the typed number during a load, and drops it if the page never changes', () => {
    show({ page: 4 });
    type('12');
    press('Enter');
    show({ page: 4, loading: true });
    expect(field().value).toBe('12');
    show({ page: 4, loading: false });
    expect(field().value).toBe('4');
  });

  it('follows a page change made by Previous or Next', () => {
    show({ page: 4 });
    type('12');
    show({ page: 5 });
    expect(field().value).toBe('5');
  });
});
