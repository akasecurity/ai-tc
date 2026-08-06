import { describe, expect, it } from 'vitest';

import {
  dedupeAgainstPages,
  needsFetch,
  pageStartOf,
} from '../../app/(app)/findings/FindingsClient.tsx';

// The findings list's discrete-page cache (GroupedView/FlatView in
// FindingsClient.tsx) is a plain useState state machine, but this package's
// vitest setup has no DOM and no React renderer, so the component itself
// cannot be mounted here. These three functions are the derivation the cache
// depends on — pageStart numbering, the fetch-vs-replay decision, and the
// dedup that keeps a paged-through deep link from rendering twice — and they
// are plain data-in data-out functions, so they are testable directly.

describe('pageStartOf', () => {
  it('is 1 for the first page regardless of its size', () => {
    expect(pageStartOf([['a', 'b', 'c']], 0)).toBe(1);
  });

  it('sums unequal preceding page lengths', () => {
    const pages = [
      ['a', 'b', 'c'], // 3
      ['d'], // 1
      ['e', 'f'], // 2
    ];
    expect(pageStartOf(pages, 0)).toBe(1);
    expect(pageStartOf(pages, 1)).toBe(4); // 1 + 3
    expect(pageStartOf(pages, 2)).toBe(5); // 1 + 3 + 1
  });

  it('is unaffected by pages past the requested index', () => {
    const pages = [['a'], ['b'], ['c', 'd', 'e']];
    expect(pageStartOf(pages, 1)).toBe(2);
  });
});

describe('needsFetch', () => {
  it('is false when the target page is already cached — Next replays it', () => {
    // pages.length === 2 (indices 0 and 1 cached); stepping from 0 to 1 needs no fetch.
    expect(needsFetch(2, 0)).toBe(false);
  });

  it('is false stepping back into any cached page', () => {
    // Back-navigation only ever moves pageIndex downward within the cache, so
    // every reachable (pageCount, pageIndex) pair for "back" is one of these.
    expect(needsFetch(3, 0)).toBe(false);
    expect(needsFetch(3, 1)).toBe(false);
  });

  it('is true only at the cached frontier', () => {
    // pages.length === 2 (indices 0 and 1); index 1 is the last cached page, so
    // stepping past it is the one case that must reach the server.
    expect(needsFetch(2, 1)).toBe(true);
  });
});

describe('dedupeAgainstPages', () => {
  it('drops an incoming item already present on an earlier page', () => {
    const pages = [[{ id: 'a' }, { id: 'b' }]];
    const incoming = [{ id: 'b' }, { id: 'c' }];
    expect(dedupeAgainstPages(pages, incoming)).toEqual([{ id: 'c' }]);
  });

  it('keeps every incoming item when none overlap', () => {
    const pages = [[{ id: 'a' }]];
    const incoming = [{ id: 'b' }, { id: 'c' }];
    expect(dedupeAgainstPages(pages, incoming)).toEqual([{ id: 'b' }, { id: 'c' }]);
  });

  it('checks against every earlier page, not just the immediately preceding one', () => {
    // The deep-linked group is appended to page 0 and can resurface many pages
    // later — a dedup that only looked at pages[pageIndex] would miss it.
    const pages = [[{ id: 'deep-linked' }], [{ id: 'x' }], [{ id: 'y' }]];
    const incoming = [{ id: 'deep-linked' }, { id: 'z' }];
    expect(dedupeAgainstPages(pages, incoming)).toEqual([{ id: 'z' }]);
  });
});
