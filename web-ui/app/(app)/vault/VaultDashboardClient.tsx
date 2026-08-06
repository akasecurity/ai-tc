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
import { Button, Input } from '@akasecurity/ui-kit';
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

interface PagedState<T> {
  pages: T[][];
  cursor: string | null;
  // The in-flight page request, as an identity token. A response is applied
  // only while its own token is still the pending one; anything that
  // invalidates the window — a reset, a newer request — clears or replaces it,
  // and the older response is DROPPED. Without that, a page computed against
  // the pre-reset window merges into the post-reset one, leaving an
  // unreachable gap in the middle of the list and a cursor that skips past it.
  //
  // A token rather than a counter, and in state rather than a ref: the check
  // has to see the LATEST value from inside an async callback, and the React
  // compiler forbids reading a ref during render. A state updater is handed
  // exactly that.
  pending: object | null;
}

/**
 * One paged list's client state: the server's first page plus whatever the
 * reader has appended.
 *
 * The reset is checked DURING RENDER against the first page's object identity,
 * not in an effect. An effect would commit one frame in which the appended
 * pages from the previous read are rendered under the new one — with duplicate
 * React keys, since a revalidate (a revoke, a purge) re-runs the route and
 * hands down a first page covering the same rows.
 */
function usePagedList<T extends { pointerId: string }>(
  firstPage: Page<T>,
): {
  rows: T[];
  cursor: string | null;
  /** Claim the next page request; returns the token to apply it under. */
  claim: () => object;
  append: (token: object, next: Page<T>) => void;
  /** Release a claim whose request failed, so the retry is not dropped. */
  abandon: (token: object) => void;
} {
  const [state, setState] = useState<PagedState<T>>({
    pages: [],
    cursor: firstPage.nextCursor,
    pending: null,
  });

  const [forPage, setForPage] = useState(firstPage);
  if (forPage !== firstPage) {
    setForPage(firstPage);
    setState({ pages: [], cursor: firstPage.nextCursor, pending: null });
  }

  return {
    rows: dedupeByPointerId([...firstPage.items, ...state.pages.flat()]),
    cursor: state.cursor,
    claim: () => {
      const token = {};
      setState((prev) => ({ ...prev, pending: token }));
      return token;
    },
    append: (token: object, next: Page<T>) => {
      setState((prev) =>
        prev.pending !== token
          ? prev
          : { pages: [...prev.pages, next.items], cursor: next.nextCursor, pending: null },
      );
    },
    abandon: (token: object) => {
      setState((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
    },
  };
}

/**
 * First occurrence wins.
 *
 * The window can shift under a walk, because `upsert` bumps the column each
 * list sorts on. The usual outcome of that is a MISS, not a duplicate, and a
 * miss cannot be repaired here — see the store's note on listInventory. What
 * this guards is the rarer direction (a row moving down past the cursor, which
 * takes two writers disagreeing on the clock) plus the ordinary case of a
 * revalidated first page overlapping rows already appended: either way the
 * second copy would collide on its React key.
 */
function dedupeByPointerId<T extends { pointerId: string }>(entries: T[]): T[] {
  const seen = new Set<string>();
  return entries.filter((e) => (seen.has(e.pointerId) ? false : (seen.add(e.pointerId), true)));
}

/**
 * The load-more handler for one paged list. Always defined: this caller CAN
 * paginate, so the view keeps rendering its footer — the count line is what
 * tells a reader the list is complete, and it must not vanish on the last page.
 * `hasMore` is what governs the button.
 *
 * The cursor is read at BUILD time, so a click that raced a reset sends the
 * stale one; the token it claims is what stops the answer being applied.
 */
function loadMore<T extends { pointerId: string }>(
  list: {
    cursor: string | null;
    claim: () => object;
    append: (token: object, next: Page<T>) => void;
    abandon: (token: object) => void;
  },
  fetchPage: (query: { cursor: string }) => Promise<Page<T>>,
  start: (fn: () => Promise<void>) => void,
  onError: (message: string) => void,
  what: string,
): () => void {
  const { cursor } = list;
  return () => {
    if (cursor === null) return;
    const token = list.claim();
    start(async () => {
      try {
        list.append(token, await fetchPage({ cursor }));
      } catch {
        // A read can fail — the CLI holding a write lock is enough. Every
        // mutating action on this page reports its errors; a page that just
        // stopped spinning over an unchanged list would be the one silent one.
        onError(`The next page of ${what} could not be read.`);
        list.abandon(token);
      }
    });
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

  const inventoryPages = usePagedList(inventory);
  const reusePages = usePagedList(reuse);
  const [inventoryBusy, startInventoryTransition] = useTransition();
  const [reuseBusy, startReuseTransition] = useTransition();

  const inventoryRows = inventoryPages.rows;
  const reuseRows = reusePages.rows;

  // The trail is the one list whose FIRST page can change without the route
  // re-rendering: flipping the batched toggle re-queries it. `page` holds
  // whatever that query last returned, seeded from the server's read;
  // `showBatched` names the filter those rows were read under; `pending` is the
  // same claim token usePagedList uses, and matters more here — the toggle and
  // the load-more button are two controls over ONE list, and the toggle is not
  // disabled while a page is in flight. Without it an append computed under one
  // filter lands on rows read under the other, producing a list that is neither
  // trail and a cursor pointing into the wrong window.
  const [deref, setDeref] = useState<{
    page: ListVaultDerefsResponse;
    showBatched: boolean;
    pending: object | null;
  }>({ page: firstDerefs, showBatched: false, pending: null });
  const [derefBusy, startDerefTransition] = useTransition();
  const derefs = deref.page;
  const showBatched = deref.showBatched;

  // A revalidate (a revoke, a purge) hands down a fresh first page — adopt it
  // and drop the accumulated trail, checked during render for the same reason
  // usePagedList checks its own. The toggle resets with it because the server
  // only ever reads the batched-hidden variant: leaving it on would label those
  // rows as including the display/render ones, which they do not.
  const [forDerefs, setForDerefs] = useState(firstDerefs);
  if (forDerefs !== firstDerefs) {
    setForDerefs(firstDerefs);
    setDeref({ page: firstDerefs, showBatched: false, pending: null });
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
        setDeref((prev) =>
          prev.pending !== token ? prev : { page, showBatched: batched, pending: null },
        );
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

  const loadMoreDerefs = () => {
    // Read at BUILD time alongside the filter, so a click that raced a flip
    // sends the old pair — and the token is what stops the answer landing.
    const cursor = derefs.nextCursor;
    const batched = showBatched;
    if (cursor === null) return;
    const token = claimDeref(batched);
    startDerefTransition(async () => {
      try {
        const page = await loadVaultDerefs({
          ...(batched ? { includeBatched: true } : {}),
          cursor,
        });
        // Appended in place, so the toggle and the pages stay one list rather
        // than two sources the view has to reconcile.
        setDeref((prev) =>
          prev.pending !== token
            ? prev
            : {
                page: {
                  items: [...prev.page.items, ...page.items],
                  nextCursor: page.nextCursor,
                  hiddenBatched: page.hiddenBatched,
                },
                showBatched: prev.showBatched,
                pending: null,
              },
        );
      } catch {
        setActionError('The next page of the de-reference trail could not be read.');
        setDeref((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
      }
    });
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
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <SectionHead
          title="Vaulted values"
          sub="Every value this machine holds, masked, with everywhere its pointer has been written. Each reveal is audited."
        />
        {actionError !== null && <p className="text-xs text-sev-critical-ink">{actionError}</p>}
        <VaultInventoryView
          entries={inventoryRows}
          onReveal={onReveal}
          onRevoke={onRevoke}
          total={inventory.totals.values}
          hasMore={inventoryPages.cursor !== null}
          loadingMore={inventoryBusy}
          onLoadMore={loadMore(
            inventoryPages,
            loadMoreVaultInventory,
            startInventoryTransition,
            setActionError,
            'vaulted values',
          )}
        />
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
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead
          title="Reuse on this machine"
          sub="Values detected in more than one place. Reuse widens the blast radius of a single leak."
        />
        <VaultReuseView
          entries={reuseRows}
          total={reuse.totals.reused}
          hasMore={reusePages.cursor !== null}
          loadingMore={reuseBusy}
          onLoadMore={loadMore(
            reusePages,
            loadMoreVaultReuse,
            startReuseTransition,
            setActionError,
            'reused values',
          )}
        />
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead
          title="De-reference audit"
          sub="Every resolution of a vaulted value — never the value itself. Model crossings render loud."
        />
        <DerefAuditTableView
          rows={derefs.items}
          hiddenBatched={derefs.hiddenBatched}
          showBatched={showBatched}
          onToggleBatched={toggleBatched}
          hasMore={derefs.nextCursor !== null}
          loadingMore={derefBusy}
          onLoadMore={loadMoreDerefs}
        />
      </section>

      <section className="flex flex-col gap-3">
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
      </section>
    </div>
  );
}
