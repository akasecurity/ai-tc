'use client';

import {
  DerefAuditTableView,
  ScrubbedValue,
  VaultInventoryView,
  VaultReuseView,
} from '@akasecurity/dashboard-ui';
import type {
  ListVaultDerefsResponse,
  ListVaultInventoryResponse,
  ListVaultReuseResponse,
  VaultInventoryEntry,
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
}

// The `{ items, nextCursor }` half the three vault list responses share.
// Derived from one of them rather than re-declared, so a change to the schema
// contract reaches this hook instead of quietly diverging from it.
type Page<T> = Pick<ListVaultInventoryResponse, 'nextCursor'> & { items: T[] };

interface WindowState<T> {
  // Each entry is one fetched page; `cursors[i]` fetches the page AFTER
  // `pages[i]`. Keyset cursors only run forward, so stepping back has to read
  // from this cache rather than re-query — there is no "previous" cursor to ask
  // the store for.
  pages: T[][];
  cursors: (string | null)[];
  index: number;
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
  next: () => void;
  previous: () => void;
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
function usePagedWindow<T extends { pointerId: string }>(
  firstPage: Page<T>,
  fetchPage: (query: { cursor: string }) => Promise<Page<T>>,
  start: (fn: () => Promise<void>) => void,
  onError: (message: string) => void,
  what: string,
): PagedWindow<T> {
  const [state, setState] = useState<WindowState<T>>({
    pages: [firstPage.items],
    cursors: [firstPage.nextCursor],
    index: 0,
    pending: null,
  });

  const [forPage, setForPage] = useState(firstPage);
  if (forPage !== firstPage) {
    setForPage(firstPage);
    setState({
      pages: [firstPage.items],
      cursors: [firstPage.nextCursor],
      index: 0,
      pending: null,
    });
  }

  const rows = state.pages[state.index] ?? [];
  const cursor = state.cursors[state.index] ?? null;
  // Cached ahead, or the store says there is another page to fetch.
  const hasNextPage = state.index + 1 < state.pages.length || cursor !== null;

  const next = (): void => {
    // Already walked: stepping forward is just a move, no read.
    if (state.index + 1 < state.pages.length) {
      setState((prev) => ({ ...prev, index: prev.index + 1 }));
      return;
    }
    if (cursor === null) return;
    const token = {};
    setState((prev) => ({ ...prev, pending: token }));
    start(async () => {
      try {
        const page = await fetchPage({ cursor });
        setState((prev) => {
          if (prev.pending !== token) return prev;
          // The window can shift under a walk, because `upsert` bumps the
          // column each list sorts on. Dropping a row already on an earlier
          // page keeps it from rendering twice under one React key; a MISS is
          // the commoner direction and cannot be repaired here — see the
          // store's note on listInventory.
          const seen = new Set(prev.pages.flat().map((e) => e.pointerId));
          const fresh = page.items.filter((e) => !seen.has(e.pointerId));
          return {
            pages: [...prev.pages, fresh],
            cursors: [...prev.cursors, page.nextCursor],
            index: prev.index + 1,
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

  const previous = (): void => {
    setState((prev) => ({ ...prev, index: Math.max(0, prev.index - 1) }));
  };

  return {
    rows,
    hasNextPage,
    hasPreviousPage: state.index > 0,
    pageStart: pageStartOf(state.pages, state.index),
    next,
    previous,
  };
}

/** 1-based index of the first row on `pageIndex`, counting the pages before it. */
function pageStartOf(pages: unknown[][], pageIndex: number): number {
  let start = 1;
  for (let i = 0; i < pageIndex; i += 1) start += pages[i]?.length ?? 0;
  return start;
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

  const inventoryPages = usePagedWindow(
    inventory,
    loadMoreVaultInventory,
    startInventoryTransition,
    setActionError,
    'vaulted values',
  );
  const reusePages = usePagedWindow(
    reuse,
    loadMoreVaultReuse,
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
  const [deref, setDeref] = useState<{
    pages: ListVaultDerefsResponse['items'][];
    cursors: (string | null)[];
    index: number;
    hiddenBatched: number;
    showBatched: boolean;
    pending: object | null;
  }>({
    pages: [firstDerefs.items],
    cursors: [firstDerefs.nextCursor],
    index: 0,
    hiddenBatched: firstDerefs.hiddenBatched,
    showBatched: false,
    pending: null,
  });
  const [derefBusy, startDerefTransition] = useTransition();

  const derefRows = deref.pages[deref.index] ?? [];
  const showBatched = deref.showBatched;
  const derefHasNext = deref.index + 1 < deref.pages.length || deref.cursors[deref.index] != null;

  const resetDeref = (page: ListVaultDerefsResponse, batched: boolean) => ({
    pages: [page.items],
    cursors: [page.nextCursor],
    index: 0,
    hiddenBatched: page.hiddenBatched,
    showBatched: batched,
    pending: null,
  });

  // A revalidate (a revoke, a purge) hands down a fresh first page — adopt it
  // and drop the walked pages, checked during render for the same reason
  // usePagedWindow checks its own. The toggle resets with it because the server
  // only ever reads the batched-hidden variant: leaving it on would label those
  // rows as including the display/render ones, which they do not.
  const [forDerefs, setForDerefs] = useState(firstDerefs);
  if (forDerefs !== firstDerefs) {
    setForDerefs(firstDerefs);
    setDeref(resetDeref(firstDerefs, false));
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
        setDeref((prev) => (prev.pending !== token ? prev : resetDeref(page, batched)));
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
    // Already walked: stepping forward is just a move, no read.
    if (deref.index + 1 < deref.pages.length) {
      setDeref((prev) => ({ ...prev, index: prev.index + 1 }));
      return;
    }
    // Read at BUILD time alongside the filter, so a click that raced a flip
    // sends the old pair — and the token is what stops the answer landing.
    const cursor = deref.cursors[deref.index] ?? null;
    const batched = showBatched;
    if (cursor === null) return;
    const token = claimDeref(batched);
    startDerefTransition(async () => {
      try {
        const page = await loadVaultDerefs({
          ...(batched ? { includeBatched: true } : {}),
          cursor,
        });
        setDeref((prev) =>
          prev.pending !== token
            ? prev
            : {
                ...prev,
                pages: [...prev.pages, page.items],
                cursors: [...prev.cursors, page.nextCursor],
                index: prev.index + 1,
                hiddenBatched: page.hiddenBatched,
                pending: null,
              },
        );
      } catch {
        setActionError('The next page of the de-reference trail could not be read.');
        setDeref((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
  };

  const previousDerefPage = () => {
    setDeref((prev) => ({ ...prev, index: Math.max(0, prev.index - 1) }));
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
      <TabsList>
        <TabsTrigger value="inventory">Vaulted values</TabsTrigger>
        <TabsTrigger value="reuse">Reuse</TabsTrigger>
        <TabsTrigger value="audit">De-reference audit</TabsTrigger>
        <TabsTrigger value="maintenance">Maintenance</TabsTrigger>
      </TabsList>

      <TabsContent value="inventory" className="flex flex-col gap-3">
        <SectionHead
          title="Vaulted values"
          sub="Every value this machine holds, masked, with everywhere its pointer has been written. Each reveal is audited."
        />
        {actionError !== null && <p className="text-xs text-sev-critical-ink">{actionError}</p>}
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
          entries={inventoryRows}
          onReveal={onReveal}
          onRevoke={onRevoke}
          total={inventory.totals.values}
          pageStart={inventoryPages.pageStart}
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
          total={reuse.totals.reused}
          pageStart={reusePages.pageStart}
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
          rows={derefRows}
          hiddenBatched={deref.hiddenBatched}
          showBatched={showBatched}
          onToggleBatched={toggleBatched}
          pageStart={pageStartOf(deref.pages, deref.index)}
          hasNextPage={derefHasNext}
          hasPreviousPage={deref.index > 0}
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
