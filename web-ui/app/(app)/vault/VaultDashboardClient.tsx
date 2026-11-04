'use client';

import {
  appendPage,
  DerefAuditTableView,
  type PagedRun,
  type PagePosition,
  planNextMove,
  planPageMove,
  runHasNext,
  runHasPrevious,
  runItems,
  runPage,
  runPageCount,
  runPageStart,
  ScrubbedValue,
  startRun,
  VaultInventoryView,
  VaultReuseView,
} from '@akasecurity/dashboard-ui';
import {
  DEFAULT_VAULT_DEREFS_LIMIT,
  DEFAULT_VAULT_INVENTORY_LIMIT,
  type ListVaultDerefsResponse,
  type ListVaultInventoryResponse,
  type ListVaultReuseResponse,
  type VaultInventoryEntry,
} from '@akasecurity/schema';
import { Button, Input, Tabs, TabsContent, TabsList, TabsTrigger } from '@akasecurity/ui-kit';
import { useState, useTransition } from 'react';

import type { PurgeVaultResult, RotateVaultKeyResult } from './actions';
import {
  loadMoreVaultInventory,
  loadMoreVaultReuse,
  loadVaultDerefs,
  purgeVault,
  revealEntry,
  revokeRevealGrant,
  rotateVaultKey,
} from './actions';

interface VaultDashboardClientProps {
  // The FIRST page of each list, as the Server Component read it. Later pages
  // arrive through the load-more actions and are appended in state here.
  inventory: ListVaultInventoryResponse;
  reuse: ListVaultReuseResponse;
  // The audit trail with the batched render reasons hidden (the default). The
  // toggle re-queries rather than filtering a second copy shipped up front.
  derefs: ListVaultDerefsResponse;
  /**
   * The instant the SERVER rendered against. Passed down rather than read here:
   * a client that picked its own would render different text than the HTML it
   * is hydrating.
   */
  renderedAt: number;
  /** The locale the SERVER resolved from the request's Accept-Language header. */
  locale: string;
}

// The `{ items, nextCursor }` half the three vault list responses share.
// Derived from one of them rather than re-declared, so a change to the schema
// contract reaches this hook instead of quietly diverging from it.
type Page<T> = Pick<ListVaultInventoryResponse, 'nextCursor'> & { items: T[] };

interface WindowState<T> {
  // Keyset cursors only run forward, so stepping back inside the run reads from
  // its cache rather than re-querying — there is no "previous" cursor to ask the
  // store for.
  run: PagedRun<T>;
  // The in-flight page request, as an identity token. A response is applied
  // only while its own token is still the pending one; anything that
  // invalidates the window — a reset, a newer request — clears or replaces it,
  // and the older response is DROPPED. Without that, a page computed against
  // the pre-reset window lands in the post-reset one, leaving an unreachable
  // gap and a cursor that skips past it.
  //
  // A token rather than a counter, and in state rather than a ref: the check
  // has to see the LATEST value from inside an async callback, and the React
  // compiler forbids reading a ref during render. A state updater is handed
  // exactly that.
  pending: object | null;
}

interface PagedWindow<T> {
  rows: T[];
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  /** 1-based position of this window's first row in the whole list. */
  pageStart: number;
  /** The page showing now, 1-indexed. */
  page: number;
  pageCount: number;
  /** Rows the latest read reported across the whole list. */
  total: number;
  next: () => void;
  previous: () => void;
  /** Moves to a 1-indexed page. */
  goToPage: (page: number) => void;
  /**
   * Rewrite rows in place, across every walked page rather than just the one on
   * screen. This is what lets a per-row write skip `revalidatePath`: the route
   * would hand down a fresh first page and discard the walk.
   */
  patch: (update: (row: T) => T) => void;
}

/**
 * One list's windowed client state: exactly one page on screen, with the pages
 * already walked kept so stepping back is free.
 *
 * The reset is checked DURING RENDER against the first page's object identity,
 * not in an effect. An effect would commit one frame in which the previous
 * read's page is rendered under the new one — with duplicate React keys, since
 * a revalidate (a revoke, a purge) re-runs the route and hands down a first
 * page covering the same rows.
 */
function usePagedWindow<T, P extends Page<T>>(
  firstPage: P,
  fetchPage: (query: PagePosition) => Promise<P>,
  /** The whole-list row count a response reports. */
  totalOf: (page: P) => number,
  pageSize: number,
  /**
   * This list's ROW identity, which the dedup below keys on. The caller names it
   * because only the caller knows it: `pointerId` is a row identity for the
   * inventory and reuse lists, where it is the table's primary key, and a VALUE
   * identity on the de-reference trail, whose rows share it — keying that list
   * on the pointer would collapse the trail to one row per value and lose the
   * audit. There is no safe default, so there is no default.
   */
  keyOf: (row: T) => string,
  start: (fn: () => Promise<void>) => void,
  onError: (message: string) => void,
  what: string,
): PagedWindow<T> {
  const firstState = (): WindowState<T> => ({
    run: startRun(firstPage.items, firstPage.nextCursor, totalOf(firstPage)),
    pending: null,
  });
  const [state, setState] = useState<WindowState<T>>(firstState);

  const [forPage, setForPage] = useState(firstPage);
  if (forPage !== firstPage) {
    setForPage(firstPage);
    setState(firstState());
  }

  const run = state.run;

  const next = (): void => {
    const move = planNextMove(run);
    if (move === null) return;
    // Already walked: stepping forward is just a move, no read.
    if (move.kind === 'cached') {
      setState((prev) => ({ ...prev, run: { ...prev.run, index: move.index } }));
      return;
    }
    const token = {};
    setState((prev) => ({ ...prev, pending: token }));
    start(async () => {
      try {
        const page = await fetchPage({ cursor: move.cursor });
        setState((prev) => {
          if (prev.pending !== token) return prev;
          // The window can shift under a walk, because `upsert` bumps the
          // column each list sorts on. Dropping a row already on an earlier
          // page keeps it from rendering twice under one React key; a MISS is
          // the commoner direction and cannot be repaired here — see the
          // store's note on listInventory.
          const seen = new Set(prev.run.pages.flat().map(keyOf));
          const fresh = page.items.filter((e) => !seen.has(keyOf(e)));
          // Nothing left to step onto. Both routes here are real: the store can
          // hand back an empty later page (one repeat detection bumps the last
          // unwalked row above the cursor, and a purge empties every later
          // page), and the dedup above can filter a whole page away. Advancing
          // would land the reader on a blank page whose only way back is
          // Previous — so stay put, and take the current page's cursor to what
          // the store just said, which is what disables Next.
          if (fresh.length === 0) {
            onError(`The rest of the ${what} list moved while you were reading it.`);
            return {
              run: {
                ...prev.run,
                cursors: prev.run.cursors.map((c, i) =>
                  i === prev.run.index ? page.nextCursor : c,
                ),
                total: totalOf(page),
              },
              pending: null,
            };
          }
          return {
            run: appendPage(prev.run, fresh, page.nextCursor, totalOf(page)),
            pending: null,
          };
        });
      } catch {
        // A read can fail — the CLI holding a write lock is enough. Every
        // mutating action on this page reports its errors; a page that just
        // stopped spinning over an unchanged list would be the one silent one.
        onError(`The next page of ${what} could not be read.`);
        setState((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const moveTo = (target: number): void => {
    const move = planPageMove(target, run, pageSize);
    if (move.kind === 'cached') {
      setState((prev) => ({ ...prev, run: { ...prev.run, index: move.index } }));
      return;
    }
    const token = {};
    setState((prev) => ({ ...prev, pending: token }));
    start(async () => {
      try {
        const page = await fetchPage({ offset: move.offset });
        setState((prev) => {
          if (prev.pending !== token) return prev;
          // Stay put on an empty answer, as `next` does: the list shrank past
          // that page, and moving would strand the reader on a blank one.
          if (page.items.length === 0) {
            onError(`That page of ${what} is no longer there.`);
            return { ...prev, pending: null };
          }
          return {
            run: startRun(page.items, page.nextCursor, totalOf(page), target),
            pending: null,
          };
        });
      } catch {
        onError(`That page of ${what} could not be read.`);
        setState((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const previous = (): void => {
    moveTo(Math.max(0, runPage(run) - 2));
  };

  const goToPage = (page: number): void => {
    moveTo(page - 1);
  };

  const patch = (update: (row: T) => T): void => {
    setState((prev) => ({
      ...prev,
      run: { ...prev.run, pages: prev.run.pages.map((page) => page.map(update)) },
    }));
  };

  return {
    rows: runItems(run),
    hasNextPage: runHasNext(run),
    hasPreviousPage: runHasPrevious(run),
    pageStart: runPageStart(run, pageSize),
    page: runPage(run),
    pageCount: runPageCount(run, pageSize),
    total: run.total,
    next,
    previous,
    goToPage,
    patch,
  };
}

function SectionHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h2 className="text-sm font-semibold text-text">{title}</h2>
      <p className="mt-0.5 text-xs text-text-3">{sub}</p>
    </div>
  );
}

/**
 * The interactive half of the vault page: the inventory with its reveal and
 * revoke actions, the reuse and audit views, and the maintenance panel (key
 * rotation and the purge). Revealed values live in component state only —
 * never persisted, gone when the strip is hidden or the page unmounts.
 */
export function VaultDashboardClient({
  inventory,
  reuse,
  derefs: firstDerefs,
  renderedAt,
  locale,
}: VaultDashboardClientProps) {
  // pointerId → the revealed value (null when the vault could not resolve it)
  // AND the row it was revealed from. The row is CARRIED rather than looked up
  // in the current page: the reader may have revealed something on page 3, and
  // any later reset would take that row out of the list while their value is
  // still on screen — leaving a completed, audited reveal rendering nothing.
  const [revealed, setRevealed] = useState<
    Record<string, { value: string | null; entry: VaultInventoryEntry }>
  >({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [rowBusy, startRowTransition] = useTransition();

  const [inventoryBusy, startInventoryTransition] = useTransition();
  const [reuseBusy, startReuseTransition] = useTransition();

  const inventoryPages = usePagedWindow<VaultInventoryEntry, ListVaultInventoryResponse>(
    inventory,
    loadMoreVaultInventory,
    (page) => page.totals.values,
    DEFAULT_VAULT_INVENTORY_LIMIT,
    (entry) => entry.pointerId,
    startInventoryTransition,
    setActionError,
    'vaulted values',
  );
  const reusePages = usePagedWindow<VaultInventoryEntry, ListVaultReuseResponse>(
    reuse,
    loadMoreVaultReuse,
    (page) => page.totals.reused,
    DEFAULT_VAULT_INVENTORY_LIMIT,
    (entry) => entry.pointerId,
    startReuseTransition,
    setActionError,
    'reused values',
  );

  const inventoryRows = inventoryPages.rows;
  const reuseRows = reusePages.rows;

  // The trail is the one list whose FIRST page can change without the route
  // re-rendering: flipping the batched toggle re-queries it. So its window
  // carries the filter its pages were read under, alongside the same page
  // cache and claim token every other list here uses.
  //
  // The token matters more on this list than the others: the toggle and the
  // pager are two controls over ONE trail, and the toggle is not disabled while
  // a page is in flight. Without it a page fetched under one filter lands in a
  // window read under the other, producing a list that is neither trail and a
  // cursor pointing into the wrong one.
  const startDeref = (page: ListVaultDerefsResponse, batched: boolean, firstCached = 0) => ({
    run: startRun(page.items, page.nextCursor, page.totals.derefs, firstCached),
    hiddenBatched: page.hiddenBatched,
    showBatched: batched,
    pending: null as object | null,
  });
  const [deref, setDeref] = useState(() => startDeref(firstDerefs, false));
  const [derefBusy, startDerefTransition] = useTransition();

  const derefRun = deref.run;
  const derefRows = runItems(derefRun);
  const showBatched = deref.showBatched;

  // A revalidate (a revoke, a purge) hands down a fresh first page — adopt it
  // and drop the walked pages, checked during render for the same reason
  // usePagedWindow checks its own. The toggle resets with it because the server
  // only ever reads the batched-hidden variant: leaving it on would label those
  // rows as including the display/render ones, which they do not.
  const [forDerefs, setForDerefs] = useState(firstDerefs);
  if (forDerefs !== firstDerefs) {
    setForDerefs(firstDerefs);
    setDeref(startDeref(firstDerefs, false));
  }

  /**
   * Claim the trail's next request, invalidating any still in flight, and
   * record the filter that request is for.
   *
   * `showBatched` moves HERE rather than when the response lands. Applied only
   * on arrival, a reveal landing inside the toggle's round trip would read the
   * pre-flip value, reload the other variant, and cancel the flip by token —
   * the toggle silently doing nothing. It also makes a second click during the
   * flight compute `!showBatched` from the requested value rather than the
   * stale one, so the toggle is reversible mid-flight.
   */
  const claimDeref = (batched: boolean): object => {
    const token = {};
    setDeref((prev) => ({ ...prev, showBatched: batched, pending: token }));
    return token;
  };

  // Replace the whole trail (a filter flip, or a refresh after a reveal). No
  // cursor: a different filter is a different list, so it restarts from the top
  // rather than resuming into a window the other query defined.
  const reloadDerefs = (batched: boolean) => {
    const token = claimDeref(batched);
    startDerefTransition(async () => {
      try {
        const page = await loadVaultDerefs(batched ? { includeBatched: true } : {});
        setDeref((prev) => (prev.pending !== token ? prev : startDeref(page, batched)));
      } catch {
        // A read can fail — the CLI holding a write lock is enough. Say so and
        // clear the claim, rather than stopping the spinner over an unchanged
        // list with no explanation.
        setActionError('The de-reference trail could not be read.');
        setDeref((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const toggleBatched = (next: boolean) => {
    reloadDerefs(next);
  };

  // A reveal writes an audit row but deliberately does not revalidate the route
  // (see revealEntry), so the trail is refreshed here instead — under whichever
  // filter is currently showing.
  const refreshDerefs = () => {
    reloadDerefs(showBatched);
  };

  const nextDerefPage = () => {
    const move = planNextMove(derefRun);
    if (move === null) return;
    // Already walked: stepping forward is just a move, no read.
    if (move.kind === 'cached') {
      setDeref((prev) => ({ ...prev, run: { ...prev.run, index: move.index } }));
      return;
    }
    // Read at BUILD time alongside the filter, so a click that raced a flip
    // sends the old pair — and the token is what stops the answer landing.
    const batched = showBatched;
    const token = claimDeref(batched);
    startDerefTransition(async () => {
      try {
        const page = await loadVaultDerefs({
          ...(batched ? { includeBatched: true } : {}),
          cursor: move.cursor,
        });
        setDeref((prev) => {
          if (prev.pending !== token) return prev;
          // The same guard `usePagedWindow` carries. This trail is append-only,
          // so an empty later page is not reachable here today — but the pager
          // is the same and the dead end it would leave is the same, and the
          // reachability is a property of the STORE rather than of this file.
          if (page.items.length === 0) {
            setActionError('The rest of the de-reference trail moved while you were reading it.');
            return {
              ...prev,
              run: {
                ...prev.run,
                cursors: prev.run.cursors.map((c, i) =>
                  i === prev.run.index ? page.nextCursor : c,
                ),
                total: page.totals.derefs,
              },
              hiddenBatched: page.hiddenBatched,
              pending: null,
            };
          }
          return {
            ...prev,
            run: appendPage(prev.run, page.items, page.nextCursor, page.totals.derefs),
            hiddenBatched: page.hiddenBatched,
            pending: null,
          };
        });
      } catch {
        setActionError('The next page of the de-reference trail could not be read.');
        setDeref((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const moveDeref = (target: number) => {
    const move = planPageMove(target, derefRun, DEFAULT_VAULT_DEREFS_LIMIT);
    if (move.kind === 'cached') {
      setDeref((prev) => ({ ...prev, run: { ...prev.run, index: move.index } }));
      return;
    }
    const batched = showBatched;
    const token = claimDeref(batched);
    startDerefTransition(async () => {
      try {
        const page = await loadVaultDerefs({
          ...(batched ? { includeBatched: true } : {}),
          offset: move.offset,
        });
        setDeref((prev) => {
          if (prev.pending !== token) return prev;
          // Stay put on an empty answer: a purge can shrink the trail past that
          // page, and moving would strand the reader on a blank one.
          if (page.items.length === 0) {
            setActionError('That page of the de-reference trail is no longer there.');
            return { ...prev, pending: null };
          }
          return startDeref(page, batched, target);
        });
      } catch {
        setActionError('That page of the de-reference trail could not be read.');
        setDeref((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const previousDerefPage = () => {
    moveDeref(Math.max(0, runPage(derefRun) - 2));
  };

  const [purgeText, setPurgeText] = useState('');
  const [purgeResult, setPurgeResult] = useState<PurgeVaultResult | null>(null);
  const [purgeBusy, startPurgeTransition] = useTransition();

  const [rotateResult, setRotateResult] = useState<RotateVaultKeyResult | null>(null);
  const [rotateBusy, startRotateTransition] = useTransition();

  const onReveal = (pointerId: string) => {
    // The row is on screen, so it is in the list the click came from. If that
    // ever stops holding, SAY SO: the value is already decrypted and the
    // `explicit-reveal` audit row already written, so failing quietly would
    // leave a completed, audited reveal rendering nothing at all.
    const entry = inventoryRows.find((row) => row.pointerId === pointerId);
    if (entry === undefined) {
      setActionError('That row is no longer in the list — reload and try again.');
      return;
    }
    startRowTransition(async () => {
      const result = await revealEntry({ pointerId });
      if (result.ok) {
        setActionError(null);
        setRevealed((prev) => ({ ...prev, [pointerId]: { value: result.value, entry } }));
        // The reveal wrote an `explicit-reveal` row the audit table should show.
        refreshDerefs();
      } else {
        setActionError(result.error);
      }
    });
  };

  const onRevoke = (grantId: string) => {
    if (
      !window.confirm(
        'Revoke this reveal-to-model grant? The model stops receiving the raw value at the next tool boundary.',
      )
    ) {
      return;
    }
    startRowTransition(async () => {
      const result = await revokeRevealGrant({ grantId });
      setActionError(result.ok ? null : result.error);
      if (!result.ok) return;
      // The action deliberately does not revalidate — see its comment — so the
      // badge is cleared here instead. Both lists carry `revealGrantId` (the
      // reuse read returns inventory rows), so a grant left on either would
      // outlive its revocation on screen.
      const clear = (row: VaultInventoryEntry): VaultInventoryEntry =>
        row.revealGrantId === grantId ? { ...row, revealGrantId: null } : row;
      inventoryPages.patch(clear);
      reusePages.patch(clear);
    });
  };

  const hide = (pointerId: string) => {
    setRevealed((prev) =>
      Object.fromEntries(Object.entries(prev).filter(([id]) => id !== pointerId)),
    );
  };

  const submitPurge = () => {
    startPurgeTransition(async () => {
      const result = await purgeVault({ confirmation: purgeText });
      setPurgeResult(result);
      if (result.ok) {
        setPurgeText('');
        // The values behind these are gone; drop them from the page too.
        setRevealed({});
      }
    });
  };

  const submitRotate = () => {
    startRotateTransition(async () => {
      setRotateResult(await rotateVaultKey());
    });
  };

  // Rows the user revealed, newest reveal last. Read from the reveal state
  // rather than filtered out of the current page, so a value stays on screen
  // however the list underneath it has since been paged or reset. A purge
  // clears the state outright, and the strip disappears with it.
  const revealedEntries = Object.values(revealed);

  return (
    <Tabs defaultValue="inventory" className="flex flex-col gap-4">
      <TabsList className="self-start">
        <TabsTrigger value="inventory">Vaulted values</TabsTrigger>
        <TabsTrigger value="reuse">Reuse</TabsTrigger>
        <TabsTrigger value="audit">De-reference audit</TabsTrigger>
        <TabsTrigger value="maintenance">Maintenance</TabsTrigger>
      </TabsList>

      {/*
        OUTSIDE the tab panels, because every tab writes to it. Each list reports
        its own read failures and its own "the list moved under you" notice, and
        inside `TabsContent value="inventory"` those messages render on the one
        tab that did not raise them — the reader on Reuse or the audit trail gets
        a control that silently did nothing, which is the failure this line
        exists to prevent.
      */}
      {actionError !== null && <p className="text-xs text-sev-critical-ink">{actionError}</p>}

      <TabsContent value="inventory" className="flex flex-col gap-3">
        <SectionHead
          title="Vaulted values"
          sub="Every value this machine holds, masked, with everywhere its pointer has been written. Each reveal is audited."
        />
        {/*
          ABOVE the table, not below it. A reveal renders here rather than in the
          row that was clicked — the row keeps its mask — so below the table this
          strip sits a full page length past the button that fills it: measured at
          ~2900px down, four viewport-heights from a click on row 1, with nothing
          changing anywhere the reader was looking. The button reads as broken
          while the reveal has in fact completed and been audited.

          Position is the whole fix; the strip stays a strip rather than moving
          into the row, because it must outlive the row. A value revealed on page
          3 has to stay on screen after a reset takes that row out of the list,
          which is why `revealed` carries its own entry.
        */}
        {revealedEntries.length > 0 && (
          <div className="rounded-xl border border-border bg-surface p-4">
            <div className="mb-2 text-label font-semibold uppercase tracking-wider text-text-3">
              Revealed on this page only — hidden again on refresh
            </div>
            <ul className="space-y-2">
              {revealedEntries.map(({ entry, value }) => {
                return (
                  <li
                    key={entry.pointerId}
                    className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2"
                  >
                    <ScrubbedValue value={value} descriptor={entry} />
                    {value === null && (
                      <span className="text-xs text-text-3">
                        could not be resolved — purged or key material unavailable
                      </span>
                    )}
                    <Button
                      variant="ghost"
                      tone="neutral"
                      size="sm"
                      disabled={rowBusy}
                      onClick={() => {
                        hide(entry.pointerId);
                      }}
                    >
                      Hide
                    </Button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        <VaultInventoryView
          renderedAt={renderedAt}
          entries={inventoryRows}
          onReveal={onReveal}
          onRevoke={onRevoke}
          total={inventoryPages.total}
          pageStart={inventoryPages.pageStart}
          page={inventoryPages.page}
          pageCount={inventoryPages.pageCount}
          onPageChange={inventoryPages.goToPage}
          locale={locale}
          hasNextPage={inventoryPages.hasNextPage}
          hasPreviousPage={inventoryPages.hasPreviousPage}
          loadingNextPage={inventoryBusy}
          onNextPage={inventoryPages.next}
          onPreviousPage={inventoryPages.previous}
        />
      </TabsContent>

      <TabsContent value="reuse" className="flex flex-col gap-3">
        <SectionHead
          title="Reuse on this machine"
          sub="Values detected in more than one place. Reuse widens the blast radius of a single leak."
        />
        {/*
          Its OWN read, never the inventory's. Reuse is a property of the whole
          store, so filtering the inventory window here would answer "which
          values are reused" with "the ones on this page that happen to be".
        */}
        <VaultReuseView
          entries={reuseRows}
          total={reusePages.total}
          pageStart={reusePages.pageStart}
          page={reusePages.page}
          pageCount={reusePages.pageCount}
          onPageChange={reusePages.goToPage}
          locale={locale}
          hasNextPage={reusePages.hasNextPage}
          hasPreviousPage={reusePages.hasPreviousPage}
          loadingNextPage={reuseBusy}
          onNextPage={reusePages.next}
          onPreviousPage={reusePages.previous}
        />
      </TabsContent>

      <TabsContent value="audit" className="flex flex-col gap-3">
        <SectionHead
          title="De-reference audit"
          sub="Every resolution of a vaulted value — never the value itself. Model crossings render loud."
        />
        <DerefAuditTableView
          renderedAt={renderedAt}
          rows={derefRows}
          hiddenBatched={deref.hiddenBatched}
          showBatched={showBatched}
          onToggleBatched={toggleBatched}
          pageStart={runPageStart(derefRun, DEFAULT_VAULT_DEREFS_LIMIT)}
          total={derefRun.total}
          page={runPage(derefRun)}
          pageCount={runPageCount(derefRun, DEFAULT_VAULT_DEREFS_LIMIT)}
          onPageChange={(page) => {
            moveDeref(page - 1);
          }}
          locale={locale}
          hasNextPage={runHasNext(derefRun)}
          hasPreviousPage={runHasPrevious(derefRun)}
          loadingNextPage={derefBusy}
          onNextPage={nextDerefPage}
          onPreviousPage={previousDerefPage}
        />
      </TabsContent>

      <TabsContent value="maintenance" className="flex flex-col gap-3">
        <SectionHead title="Vault maintenance" sub="Key rotation is routine; the purge is not." />
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
            Rotate vault key
          </div>
          <p className="mb-3 text-xs text-text-3">
            Mints the next key epoch and re-encrypts every stored value under it. Existing pointers
            keep working — only the ciphertext changes.
          </p>
          {rotateResult?.ok === true && (
            <p className="mb-3 text-xs text-ok-ink">
              Key rotated to version {rotateResult.version} —{' '}
              {rotateResult.reEncrypted === 1
                ? '1 entry re-encrypted'
                : `${String(rotateResult.reEncrypted)} entries re-encrypted`}{' '}
              under it.
            </p>
          )}
          {rotateResult?.ok === false && (
            <p className="mb-3 text-xs text-sev-critical-ink">{rotateResult.error}</p>
          )}
          <Button
            variant="outline"
            tone="neutral"
            size="sm"
            disabled={rotateBusy}
            onClick={submitRotate}
          >
            {rotateBusy ? 'Rotating…' : 'Rotate key'}
          </Button>
        </div>

        <div className="rounded-xl border border-sev-critical-fill bg-surface p-5">
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-sev-critical-ink">
            Purge vault
          </div>
          <p className="mb-3 text-xs text-text-3">
            Destroys every stored value. Every pointer everywhere — in files, transcripts, and
            prompts — becomes permanently unresolvable. The audit trail survives. This cannot be
            undone.
          </p>
          {purgeResult?.ok === true && (
            <p className="mb-3 text-xs text-text-2">
              Vault purged —{' '}
              {purgeResult.destroyed === 1
                ? '1 value destroyed'
                : `${String(purgeResult.destroyed)} values destroyed`}
              . The audit trail below is retained.
            </p>
          )}
          {purgeResult?.ok === false && (
            <p className="mb-3 text-xs text-sev-critical-ink">{purgeResult.error}</p>
          )}
          <div className="flex items-center gap-2">
            <Input
              value={purgeText}
              onChange={(e) => {
                setPurgeText(e.target.value);
              }}
              placeholder="Type 'purge' to confirm"
              className="max-w-56 font-mono"
            />
            <Button
              variant="solid"
              tone="danger"
              size="sm"
              disabled={purgeText !== 'purge' || purgeBusy}
              onClick={submitPurge}
            >
              {purgeBusy ? 'Purging…' : 'Purge vault'}
            </Button>
          </div>
        </div>
      </TabsContent>
    </Tabs>
  );
}
