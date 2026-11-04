'use client';

import {
  DerefAuditTableView,
  ScrubbedValue,
  usePagedRun,
  VaultInventoryView,
  VaultReuseView,
} from '@akasecurity/dashboard-ui';
import {
  DEFAULT_VAULT_DEREFS_LIMIT,
  DEFAULT_VAULT_INVENTORY_LIMIT,
  type ListVaultDerefsResponse,
  type ListVaultInventoryResponse,
  type ListVaultReuseResponse,
  type VaultDeref,
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

  const inventoryPages = usePagedRun<VaultInventoryEntry, ListVaultInventoryResponse>({
    first: inventory,
    fetchPage: loadMoreVaultInventory,
    totalOf: (page) => page.totals.values,
    pageSize: DEFAULT_VAULT_INVENTORY_LIMIT,
    keyOf: (entry) => entry.pointerId,
    what: 'vaulted values',
  });
  const reusePages = usePagedRun<VaultInventoryEntry, ListVaultReuseResponse>({
    first: reuse,
    fetchPage: loadMoreVaultReuse,
    totalOf: (page) => page.totals.reused,
    pageSize: DEFAULT_VAULT_INVENTORY_LIMIT,
    keyOf: (entry) => entry.pointerId,
    what: 'reused values',
  });

  const inventoryRows = inventoryPages.items;
  const reuseRows = reusePages.items;

  // The trail is the one list whose FIRST page can change without the route
  // re-rendering: flipping the batched toggle re-queries it. So the first page and
  // the filter it was read under live here, with a claim token of their own for
  // the re-query.
  const [derefRead, setDerefRead] = useState({
    first: firstDerefs,
    showBatched: false,
    pending: null as object | null,
  });
  const showBatched = derefRead.showBatched;
  const [reloadBusy, startReloadTransition] = useTransition();
  const derefPages = usePagedRun<VaultDeref, ListVaultDerefsResponse>({
    first: derefRead.first,
    fetchPage: (position) =>
      loadVaultDerefs({ ...(showBatched ? { includeBatched: true } : {}), ...position }),
    totalOf: (page) => page.totals.derefs,
    pageSize: DEFAULT_VAULT_DEREFS_LIMIT,
    // A resolution's own id: `pointerId` is shared by every resolution of a value,
    // and keying on it would collapse the audit to one row per value.
    keyOf: (row) => row.id,
    what: 'the de-reference trail',
  });

  // A revalidate (a revoke, a purge) hands down a fresh first page — adopt it and
  // drop the walked pages, checked during render as the paged lists check their
  // own. The toggle resets with it because the server only ever reads the
  // batched-hidden variant: leaving it on would label those rows as including the
  // display/render ones, which they do not.
  const [forDerefs, setForDerefs] = useState(firstDerefs);
  if (forDerefs !== firstDerefs) {
    setForDerefs(firstDerefs);
    setDerefRead({ first: firstDerefs, showBatched: false, pending: null });
  }

  // Replace the whole trail (a filter flip, or a refresh after a reveal). No
  // cursor: a different filter is a different list, so it restarts from the top
  // rather than resuming into a window the other query defined.
  //
  // `showBatched` moves HERE rather than when the response lands. Applied only on
  // arrival, a reveal landing inside the toggle's round trip would read the
  // pre-flip value, reload the other variant, and cancel the flip by token — the
  // toggle silently doing nothing. It also makes a second click during the flight
  // compute `!showBatched` from the requested value rather than the stale one, so
  // the toggle is reversible mid-flight.
  const reloadDerefs = (batched: boolean) => {
    derefPages.invalidate();
    const token = {};
    setDerefRead((prev) => ({ ...prev, showBatched: batched, pending: token }));
    startReloadTransition(async () => {
      try {
        const page = await loadVaultDerefs(batched ? { includeBatched: true } : {});
        setDerefRead((prev) =>
          prev.pending !== token ? prev : { first: page, showBatched: batched, pending: null },
        );
      } catch {
        // A read can fail — the CLI holding a write lock is enough. Say so and
        // clear the claim, rather than stopping the spinner over an unchanged
        // list with no explanation.
        setActionError('The de-reference trail could not be read.');
        setDerefRead((prev) => (prev.pending !== token ? prev : { ...prev, pending: null }));
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
          pageError={inventoryPages.error}
          locale={locale}
          hasNextPage={inventoryPages.hasNextPage}
          hasPreviousPage={inventoryPages.hasPreviousPage}
          loadingNextPage={inventoryPages.loading}
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
          pageError={reusePages.error}
          locale={locale}
          hasNextPage={reusePages.hasNextPage}
          hasPreviousPage={reusePages.hasPreviousPage}
          loadingNextPage={reusePages.loading}
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
          rows={derefPages.items}
          hiddenBatched={derefPages.latest.hiddenBatched}
          showBatched={showBatched}
          onToggleBatched={toggleBatched}
          pageStart={derefPages.pageStart}
          total={derefPages.total}
          page={derefPages.page}
          pageCount={derefPages.pageCount}
          onPageChange={derefPages.goToPage}
          pageError={derefPages.error}
          locale={locale}
          hasNextPage={derefPages.hasNextPage}
          hasPreviousPage={derefPages.hasPreviousPage}
          loadingNextPage={derefPages.loading || reloadBusy}
          onNextPage={derefPages.next}
          onPreviousPage={derefPages.previous}
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
