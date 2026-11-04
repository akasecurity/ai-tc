/**
 * The bookkeeping behind a paged list, shared by every host that keeps a
 * client-side run of fetched pages. Pure, so each host owns only its own policy
 * for a read: how it reports a failure and which responses it still accepts.
 */

/** How many pages `total` rows fill. An empty list still reads as one page. */
export function pageCountOf(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

/** Where a page is read from: after a cursor, or at a row position. */
export type PagePosition = { cursor: string } | { offset: number };

/**
 * One consecutive run of fetched pages. `cursors[i]` fetches the page after
 * `pages[i]`, and `firstCached` is the 0-based page number of `pages[0]`. Stepping
 * inside the run replays a page; a move outside it starts a new run. `total` is
 * the row count the latest read reported.
 */
export interface PagedRun<T> {
  pages: T[][];
  cursors: (string | null)[];
  index: number;
  firstCached: number;
  total: number;
}

/** A run holding one page. `firstCached` is that page's 0-based number. */
export function startRun<T>(
  items: T[],
  nextCursor: string | null,
  total: number,
  firstCached = 0,
): PagedRun<T> {
  return { pages: [items], cursors: [nextCursor], index: 0, firstCached, total };
}

export function runItems<T>(run: PagedRun<T>): T[] {
  return run.pages[run.index] ?? [];
}

/** The page showing now, 1-indexed. */
export function runPage<T>(run: PagedRun<T>): number {
  return run.firstCached + run.index + 1;
}

/**
 * 1-indexed rank of the page's first row. Taken from the page number alone, so a
 * page reads the same range however the reader reached it.
 */
export function runPageStart<T>(run: PagedRun<T>, pageSize: number): number {
  return (run.firstCached + run.index) * pageSize + 1;
}

/**
 * The pages the list fills, and never fewer than the page showing: the store can
 * grow while a reader steps, and Next follows the cursor past an older count.
 */
export function runPageCount<T>(run: PagedRun<T>, pageSize: number): number {
  return Math.max(pageCountOf(run.total, pageSize), runPage(run));
}

export function runHasPrevious<T>(run: PagedRun<T>): boolean {
  return runPage(run) > 1;
}

export function runHasNext<T>(run: PagedRun<T>): boolean {
  return run.index + 1 < run.pages.length || (run.cursors[run.index] ?? null) !== null;
}

/** Where a move to another page gets its rows from. */
export type PageMove = { kind: 'cached'; index: number } | { kind: 'fetch'; offset: number };

/** Plan a move to `page` (0-based): replayed inside the run, else read by position. */
export function planPageMove<T>(page: number, run: PagedRun<T>, pageSize: number): PageMove {
  const index = page - run.firstCached;
  return index >= 0 && index < run.pages.length
    ? { kind: 'cached', index }
    : { kind: 'fetch', offset: page * pageSize };
}

/** Where Next gets its rows from, or null at the end of the list. */
export type NextMove = { kind: 'cached'; index: number } | { kind: 'fetch'; cursor: string } | null;

export function planNextMove<T>(run: PagedRun<T>): NextMove {
  if (run.index + 1 < run.pages.length) return { kind: 'cached', index: run.index + 1 };
  const cursor = run.cursors[run.index] ?? null;
  return cursor === null ? null : { kind: 'fetch', cursor };
}

/** The run with a page fetched by cursor added to its end, and showing. */
export function appendPage<T>(
  run: PagedRun<T>,
  items: T[],
  nextCursor: string | null,
  total: number,
): PagedRun<T> {
  return {
    ...run,
    pages: [...run.pages, items],
    cursors: [...run.cursors, nextCursor],
    index: run.pages.length,
    total,
  };
}
