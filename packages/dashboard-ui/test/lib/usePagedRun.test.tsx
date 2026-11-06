// @vitest-environment jsdom
//
// The hook's policy, driven through a small host: what each move reads, and what a
// late, empty or failed answer does to the list.
import { act, type ReactElement, useEffect } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { PagePosition } from '../../src/lib/pagination.ts';
import { usePagedRun } from '../../src/lib/usePagedRun.ts';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

interface Row {
  id: string;
  flag?: boolean;
}
interface Read {
  items: Row[];
  nextCursor: string | null;
  total: number;
}

const read = (ids: string[], nextCursor: string | null, total = 500): Read => ({
  items: ids.map((id) => ({ id })),
  nextCursor,
  total,
});

type Run = ReturnType<typeof usePagedRun<Row, Read>>;

let mounted: MountedRoot;
let current: Run;
const fetchPage = vi.fn<(position: PagePosition) => Promise<Read>>();
const onMoved = vi.fn();

function Host({ first, replayFirstPage }: { first: Read; replayFirstPage: boolean }): ReactElement {
  const run = usePagedRun<Row, Read>({
    first,
    fetchPage,
    totalOf: (page) => page.total,
    pageSize: 50,
    keyOf: (row) => row.id,
    what: 'rows',
    replayFirstPage,
    onMoved,
  });
  useEffect(() => {
    current = run;
  });
  return <div />;
}

function show(first: Read, replayFirstPage = false): void {
  renderRoot(mounted.root, <Host first={first} replayFirstPage={replayFirstPage} />);
}

async function settle(move: () => void): Promise<void> {
  await act(async () => {
    move();
    await Promise.resolve();
  });
}

const ids = () => current.items.map((row) => row.id);
const FIRST = read(['a', 'b'], 'cursor-a');

beforeEach(() => {
  mounted = mountRoot();
  fetchPage.mockReset();
  onMoved.mockReset();
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

describe('usePagedRun', () => {
  it('starts on the first page', () => {
    show(FIRST);
    expect(ids()).toEqual(['a', 'b']);
    expect(current.page).toBe(1);
    expect(current.pageStart).toBe(1);
    expect(current.pageCount).toBe(10);
    expect(current.total).toBe(500);
    expect(current.hasPreviousPage).toBe(false);
    expect(current.hasNextPage).toBe(true);
    expect(current.latest).toBe(FIRST);
  });

  it('reads the next page by cursor, then replays it', async () => {
    const page = read(['c'], null, 600);
    fetchPage.mockResolvedValue(page);
    show(FIRST);

    await settle(current.next);
    expect(current.latest).toBe(page);
    expect(fetchPage).toHaveBeenCalledExactlyOnceWith({ cursor: 'cursor-a' });
    expect(ids()).toEqual(['c']);
    expect(current.pageStart).toBe(51);
    expect(current.total).toBe(600);
    expect(current.hasNextPage).toBe(false);
    expect(onMoved).toHaveBeenCalledTimes(1);

    await settle(current.previous);
    expect(ids()).toEqual(['a', 'b']);
    await settle(current.next);
    expect(ids()).toEqual(['c']);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(onMoved).toHaveBeenCalledTimes(3);
  });

  it('does nothing at the end of the list', async () => {
    show(read(['a'], null));
    await settle(current.next);
    expect(fetchPage).not.toHaveBeenCalled();
    expect(onMoved).not.toHaveBeenCalled();
  });

  it('drops a row an earlier page already showed', async () => {
    fetchPage.mockResolvedValue(read(['b', 'c'], null));
    show(FIRST);
    await settle(current.next);
    expect(ids()).toEqual(['c']);
  });

  it('stays put when the next page repeats everything, and takes its cursor', async () => {
    fetchPage.mockResolvedValue(read(['a'], null, 2));
    show(FIRST);
    await settle(current.next);

    expect(ids()).toEqual(['a', 'b']);
    expect(current.hasNextPage).toBe(false);
    expect(current.total).toBe(2);
    expect(current.error).toBe('The rest of rows moved while you were reading it.');
    expect(onMoved).not.toHaveBeenCalled();
  });

  it('reports a next page it could not read, and clears that on the next move', async () => {
    fetchPage.mockRejectedValueOnce(new Error('locked'));
    show(FIRST);
    await settle(current.next);
    expect(current.error).toBe('The next page of rows could not be read.');
    expect(onMoved).not.toHaveBeenCalled();

    fetchPage.mockResolvedValueOnce(read(['c'], null));
    await settle(current.next);
    expect(current.error).toBeNull();
    expect(ids()).toEqual(['c']);
  });

  it('reads a far page by position and starts a new run there', async () => {
    fetchPage.mockResolvedValue(read(['p'], 'cursor-p'));
    show(FIRST);
    await settle(() => {
      current.goToPage(7);
    });

    expect(fetchPage).toHaveBeenCalledExactlyOnceWith({ offset: 300 });
    expect(ids()).toEqual(['p']);
    expect(current.page).toBe(7);
    expect(current.pageStart).toBe(301);
    expect(onMoved).toHaveBeenCalledTimes(1);
  });

  it('keeps the forward pages when stepping back from the start of a run', async () => {
    fetchPage.mockResolvedValueOnce(read(['p'], 'cursor-p'));
    show(FIRST);
    await settle(() => {
      current.goToPage(7);
    });
    fetchPage.mockResolvedValueOnce(read(['o'], 'cursor-o'));
    await settle(current.previous);
    expect(fetchPage).toHaveBeenLastCalledWith({ offset: 250 });
    expect(current.page).toBe(6);

    await settle(current.next);
    expect(ids()).toEqual(['p']);
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it('stays put when a jump finds nothing there', async () => {
    fetchPage.mockResolvedValue(read([], null));
    show(FIRST);
    await settle(() => {
      current.goToPage(7);
    });

    expect(current.page).toBe(1);
    expect(current.error).toBe('That page of rows is no longer there.');
    expect(onMoved).not.toHaveBeenCalled();
  });

  it('reports a jump it could not read', async () => {
    fetchPage.mockRejectedValue(new Error('locked'));
    show(FIRST);
    await settle(() => {
      current.goToPage(7);
    });

    expect(current.page).toBe(1);
    expect(current.error).toBe('That page of rows could not be read.');
    expect(current.loading).toBe(false);
  });

  it('replays the first page when asked to, without reading', async () => {
    fetchPage.mockResolvedValue(read(['p'], 'cursor-p', 700));
    show(FIRST, true);
    await settle(() => {
      current.goToPage(7);
    });
    onMoved.mockClear();

    await settle(() => {
      current.goToPage(1);
    });

    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(ids()).toEqual(['a', 'b']);
    expect(current.total).toBe(700);
    expect(current.hasNextPage).toBe(true);
    expect(onMoved).toHaveBeenCalledTimes(1);
  });

  it('reads the first page again otherwise', async () => {
    fetchPage.mockResolvedValue(read(['p'], 'cursor-p'));
    show(FIRST);
    await settle(() => {
      current.goToPage(7);
    });
    await settle(() => {
      current.goToPage(1);
    });
    expect(fetchPage).toHaveBeenLastCalledWith({ offset: 0 });
  });

  it('rewrites rows across every page in the run', async () => {
    fetchPage.mockResolvedValue(read(['c'], null));
    show(FIRST);
    await settle(current.next);
    await settle(() => {
      current.patch((row) => ({ ...row, flag: true }));
    });

    expect(current.items[0]?.flag).toBe(true);
    await settle(current.previous);
    expect(current.items.every((row) => row.flag === true)).toBe(true);
  });

  it('starts over on a new first page', async () => {
    fetchPage.mockRejectedValueOnce(new Error('locked'));
    show(FIRST);
    await settle(current.next);
    expect(current.error).not.toBeNull();

    const fresh = read(['z'], null, 1);
    show(fresh);

    expect(ids()).toEqual(['z']);
    expect(current.page).toBe(1);
    expect(current.total).toBe(1);
    expect(current.latest).toBe(fresh);
    expect(current.error).toBeNull();
  });

  describe('a read that is no longer wanted', () => {
    function parked(): {
      release: (page: Read) => void;
      fail: () => void;
    } {
      let release: (page: Read) => void = () => undefined;
      let fail: () => void = () => undefined;
      fetchPage.mockReturnValueOnce(
        new Promise<Read>((resolve, reject) => {
          release = resolve;
          fail = () => {
            reject(new Error('locked'));
          };
        }),
      );
      return {
        release: (page) => {
          release(page);
        },
        fail: () => {
          fail();
        },
      };
    }

    it('is dropped when the list has started over', async () => {
      const flight = parked();
      show(FIRST);
      await settle(current.next);
      const fresh = read(['z'], null, 1);
      show(fresh);

      await settle(() => {
        flight.release(read(['stale'], null));
      });

      expect(ids()).toEqual(['z']);
      expect(current.latest).toBe(fresh);
    });

    it('fails quietly when the list has started over', async () => {
      const flight = parked();
      show(FIRST);
      await settle(current.next);
      show(read(['z'], null, 1));

      await settle(() => {
        flight.fail();
      });

      expect(current.error).toBeNull();
    });

    it('is dropped once invalidated', async () => {
      const flight = parked();
      show(FIRST);
      await settle(current.next);
      await settle(current.invalidate);

      await settle(() => {
        flight.release(read(['stale'], null));
      });

      expect(ids()).toEqual(['a', 'b']);
    });
  });
});
