import { describe, expect, it } from 'vitest';

import { dedupeAgainstPages } from '../../app/(app)/findings/FindingsClient.tsx';

// The dedup that keeps a paged-through deep link from rendering twice, as a plain
// data-in data-out function. The cache's own arithmetic is pinned with `PagedRun`
// in dashboard-ui's TablePagination suite.

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
