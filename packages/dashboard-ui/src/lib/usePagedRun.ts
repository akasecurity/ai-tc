'use client';
import { useEffect, useRef, useState, useTransition } from 'react';

import {
  appendPage,
  type PagePosition,
  placePage,
  planNextMove,
  planPageMove,
  runHasNext,
  runHasPrevious,
  runItems,
  runPage,
  runPageCount,
  runPageStart,
  runRangeCount,
  startRun,
} from './pagination.ts';

export interface PagedRunOptions<T, P extends { items: T[]; nextCursor: string | null }> {
  /** The first page, as the server read it. A new object starts the list over. */
  first: P;
  /** Reads a page. A filter the list depends on is carried in this closure. */
  fetchPage: (position: PagePosition) => Promise<P>;
  /** The whole-list row count a response reports. */
  totalOf: (page: P) => number;
  pageSize: number;
  /**
   * This list's ROW identity, which the dedup keys on. The caller names it because
   * only the caller knows it: `pointerId` is a row identity for the vault's
   * inventory and reuse lists, and a VALUE identity on its de-reference trail,
   * whose rows share it. There is no safe default, so there is no default.
   */
  keyOf: (row: T) => string;
  /** What the rows are, as an error message names them: `vaulted values`. */
  what: string;
  /**
   * Returns to page 1 from `first` rather than reading it again. For a list whose
   * first page holds something a later read would not, and whose rows no `patch`
   * has rewritten.
   */
  replayFirstPage?: boolean;
  /** Called once a move has happened, and not for one that was refused or failed. */
  onMoved?: () => void;
}

/**
 * One paged list's client state: exactly one page on screen, with a consecutive
 * run of fetched pages kept so moving inside it is free. Next reads by cursor; a
 * move outside the run reads by row position.
 *
 * The reset is checked DURING RENDER against the first page's identity, not in an
 * effect. An effect would commit one frame in which the previous read's page is
 * rendered under the new one, with duplicate React keys.
 */
export function usePagedRun<T, P extends { items: T[]; nextCursor: string | null }>({
  first,
  fetchPage,
  totalOf,
  pageSize,
  keyOf,
  what,
  replayFirstPage = false,
  onMoved,
}: PagedRunOptions<T, P>) {
  const [run, setRun] = useState(() => startRun(first.items, first.nextCursor, totalOf(first)));
  const [latest, setLatest] = useState(first);
  const [error, setError] = useState<string | null>(null);
  const [loading, startLoading] = useTransition();

  const [forFirst, setForFirst] = useState(first);
  if (forFirst !== first) {
    setForFirst(first);
    setRun(startRun(first.items, first.nextCursor, totalOf(first)));
    setLatest(first);
    setError(null);
  }

  // Mirrors the current first page for the async continuation below, which needs
  // the LATEST one rather than the one its own closure captured. Written in an
  // effect because a ref may not be touched during render. The gap that leaves,
  // between the reset's commit and this effect, cannot hold the continuation,
  // which is parked on a Server Action round trip.
  const firstRef = useRef(first);
  useEffect(() => {
    firstRef.current = first;
  }, [first]);

  // The in-flight read, as an identity token. A response is applied only while its
  // token is still current and the list has not started over; anything else is
  // DROPPED, so a page read for a previous filter never lands in the new list.
  const requestRef = useRef<object | null>(null);

  const read = (position: PagePosition, apply: (page: P) => void, failure: string) => {
    const token = {};
    requestRef.current = token;
    const epoch = first;
    const isCurrent = () => requestRef.current === token && firstRef.current === epoch;
    startLoading(async () => {
      try {
        const page = await fetchPage(position);
        if (!isCurrent()) return;
        requestRef.current = null;
        setLatest(page);
        apply(page);
      } catch {
        // A read can fail: the CLI holding a write lock is enough.
        if (!isCurrent()) return;
        requestRef.current = null;
        setError(failure);
      }
    });
  };

  const showCached = (index: number) => {
    setRun((prev) => ({ ...prev, index }));
    onMoved?.();
  };

  const moveTo = (target: number) => {
    setError(null);
    const move = planPageMove(target, run, pageSize);
    if (move.kind === 'cached') {
      showCached(move.index);
      return;
    }
    if (target === 0 && replayFirstPage) {
      setRun((prev) => placePage(prev, 0, first.items, first.nextCursor, prev.total));
      onMoved?.();
      return;
    }
    read(
      { offset: move.offset },
      (page) => {
        // Stay put on an empty answer: the list shrank past that page, and moving
        // would strand the reader on a blank one.
        if (page.items.length === 0) {
          setError(`That page of ${what} is no longer there.`);
          return;
        }
        setRun((prev) => placePage(prev, target, page.items, page.nextCursor, totalOf(page)));
        onMoved?.();
      },
      `That page of ${what} could not be read.`,
    );
  };

  const next = () => {
    setError(null);
    const move = planNextMove(run);
    if (move === null) return;
    if (move.kind === 'cached') {
      showCached(move.index);
      return;
    }
    read(
      { cursor: move.cursor },
      (page) => {
        // A row can reappear on a later page: a write can move it, and a first
        // page can carry a selected row out of its sort order. Drop the repeat so
        // it never renders twice.
        const seen = new Set(run.pages.flat().map(keyOf));
        const fresh = page.items.filter((row) => !seen.has(keyOf(row)));
        // Nothing left to step onto. Advancing would land the reader on a blank
        // page, so stay put and take the current page's cursor to what the store
        // just said, which is what disables Next at the end of the list.
        if (fresh.length === 0) {
          setRun((prev) => ({
            ...prev,
            cursors: prev.cursors.map((c, i) => (i === prev.index ? page.nextCursor : c)),
            total: totalOf(page),
          }));
          setError(`The rest of ${what} moved while you were reading it.`);
          return;
        }
        setRun((prev) => appendPage(prev, fresh, page.nextCursor, totalOf(page)));
        onMoved?.();
      },
      `The next page of ${what} could not be read.`,
    );
  };

  return {
    items: runItems(run),
    /** The latest response read, for what a list reports beside its rows. */
    latest,
    pageStart: runPageStart(run, pageSize),
    rangeCount: runRangeCount(run, pageSize),
    page: runPage(run),
    pageCount: runPageCount(run, pageSize),
    total: run.total,
    hasNextPage: runHasNext(run),
    hasPreviousPage: runHasPrevious(run),
    loading,
    error,
    next,
    previous: () => {
      moveTo(Math.max(0, runPage(run) - 2));
    },
    /** Moves to a 1-indexed page. */
    goToPage: (page: number) => {
      moveTo(page - 1);
    },
    /** Rewrites rows in place, across every page in the run. */
    patch: (update: (row: T) => T) => {
      setRun((prev) => ({ ...prev, pages: prev.pages.map((page) => page.map(update)) }));
    },
    /** Drops any read still in flight, for a host about to replace the list. */
    invalidate: () => {
      requestRef.current = null;
    },
  };
}
