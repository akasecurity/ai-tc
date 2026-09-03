'use client';

import {
  DataShareDetailView,
  DataSharesKindTabsView,
  DataSharesTableView,
  NeedsReviewListView,
  NeedsReviewStripView,
  type ShareSelection,
} from '@akasecurity/dashboard-ui';
import type {
  DestinationKind,
  ReviewDestination,
  ShareDestinationDetail,
  ShareDestinationGroup,
} from '@akasecurity/schema';
import {
  Card,
  cn,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  Tabs,
  TabsContent,
} from '@akasecurity/ui-kit';
import { usePathname } from 'next/navigation';
import { useCallback, useState, useTransition } from 'react';

import { SearchIcon } from '../../components/icons';
import { useNavigationTransition } from '../../components/NavigationTransition';
import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { setEgressDecision } from './actions';
import { buildDataSharesParams } from './filters';
import {
  makeCloseDrawerHandler,
  makeExpandToggleHandler,
  makeOnBackHandler,
  makeOnPickHandler,
  makeOpenDestHandler,
  makeOpenEndpointHandler,
  makeOpenReviewedDestHandler,
  makeReviewOpenHandler,
  makeReviewSheetOpenChangeHandler,
  makeSetDecisionHandler,
  makeTabsValueChangeHandler,
} from './interactions.ts';

/**
 * Client shell for the OSS Data Shares page. The grouped register, needs-review
 * strip and selected destination detail come from the Server Component (which
 * reads the local store per URL); search + selection push a new URL so the server
 * re-queries — the OSS store is server-only. Expanded rows + whether the
 * needs-review sheet is open are local-only client state. The egress-decision
 * write goes through a Server Action (the detail view's onSetDecision).
 */
export function DataSharesClient({
  q,
  groups,
  review,
  destination,
  selectedDest,
  selectedEndpoint,
  renderedAt,
}: {
  q: string;
  groups: ShareDestinationGroup[];
  review: ReviewDestination[];
  destination: ShareDestinationDetail | null;
  selectedDest: string | null;
  selectedEndpoint: string | null;
  /**
   * The instant the SERVER rendered against. Passed down rather than read here:
   * a client that picked its own would render different text than the HTML it
   * is hydrating.
   */
  renderedAt: number;
}) {
  const pathname = usePathname();
  // Navigation transition (search/selection pushes) — distinct from the write
  // transition below, which tracks the egress-decision Server Action.
  const { isPending: navPending, push: pushUrl } = useNavigationTransition();

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [reviewOpen, setReviewOpen] = useState(false);
  const [activeKind, setActiveKind] = useState<DestinationKind | null>(null);
  const [isSettingDecision, startTransition] = useTransition();
  // Surface a failed egress write instead of silently keeping the old toggle —
  // this is a security-posture control, so a silent no-op is the worst mode.
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const buildUrl = useCallback(
    (opts: { q?: string; dest?: string | null; ep?: string | null }) => {
      const qs = buildDataSharesParams(opts).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook. A
  // debounced search drops any open selection (the destination may not be in the
  // new results).
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(q, (term) => buildUrl({ q: term }));

  const push = useCallback(
    (opts: { q?: string; dest?: string | null; ep?: string | null }) => {
      onNavigate(opts.q ?? '');
      pushUrl(buildUrl(opts));
    },
    [onNavigate, pushUrl, buildUrl],
  );

  const selection: ShareSelection | null = selectedDest
    ? { id: selectedDest, ...(selectedEndpoint ? { endpointId: selectedEndpoint } : {}) }
    : null;
  const drawerOpen = selectedDest !== null;
  const selectedEp =
    destination && selectedEndpoint
      ? (destination.endpoints.find((e) => e.id === selectedEndpoint) ?? null)
      : null;
  // Re-derived every render rather than synced with an effect: if the active
  // tab's group disappears (e.g. a search narrows results to other kinds),
  // this falls back to the first remaining group without an extra render.
  // Undefined (not just an empty groups[]) whenever there's nothing to tab.
  const activeGroup = groups.find((g) => g.kind === activeKind) ?? groups[0];

  const openDest = makeOpenDestHandler(push, q);
  const closeDrawer = makeCloseDrawerHandler(push, q, setDecisionError);
  const openReviewedDest = makeOpenReviewedDestHandler(
    push,
    q,
    (id) => groups.find((g) => g.items.some((d) => d.id === id))?.kind,
    setActiveKind,
  );

  const ql = q.trim();

  return (
    <>
      {/* Body */}
      <div
        aria-busy={navPending}
        className={cn(
          'flex min-h-0 flex-1 flex-col transition-shadow duration-150',
          navPending && 'rounded-lg ring-2 ring-primary/70 ring-inset',
        )}
      >
        <div className="shrink-0">
          <NeedsReviewStripView items={review} onOpen={makeReviewOpenHandler(setReviewOpen)} />
        </div>
        {/*
          One Tabs root spanning both the populated and empty cases, so the
          search input keeps the same position in the element tree either way.
          Rooting the two cases at different element types (Tabs vs a plain
          div) made React remount the whole subtree whenever a search crossed
          the has-results boundary, destroying the <input> and dropping
          keyboard focus mid-type.

          The tab strip is a sibling of the Card, outside its scroll
          container, so it stays put while the table scrolls under it — which
          is why the Tabs root is owned here rather than inside
          DataSharesTableView: TabsList and TabsContent only need a common
          ui-kit Tabs ancestor, not a common parent element.
        */}
        <Tabs
          {...(activeGroup ? { value: activeGroup.kind } : {})}
          onValueChange={makeTabsValueChangeHandler(setActiveKind)}
          className="flex min-h-0 flex-1 flex-col"
        >
          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-2.5">
            <DataSharesKindTabsView groups={groups} />
            {/* Shrinks before it wraps: flex-1 grows it to fill the row up to
                max-w-80, and it shrinks to min-w-48 as the kind tabs beside it
                (which don't shrink — see DataSharesKindTabsView) take more. */}
            <div className="flex h-9 min-w-48 max-w-80 flex-1 items-center gap-2 rounded-lg border border-border bg-surface-2 px-3">
              <SearchIcon aria-hidden focusable={false} className="size-4 shrink-0 text-text-3" />
              <input
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                }}
                placeholder="Search destinations, URLs & call sites…"
                aria-label="Search data shares"
                className="min-w-0 flex-1 bg-transparent text-sm text-text placeholder:text-text-3 focus:outline-none"
              />
            </div>
          </div>
          <Card className="flex min-h-112 flex-1 flex-col overflow-hidden">
            {activeGroup ? (
              <TabsContent
                value={activeGroup.kind}
                className="min-h-0 flex-1 overflow-y-auto p-3.5"
              >
                <DataSharesTableView
                  renderedAt={renderedAt}
                  group={activeGroup}
                  expanded={expanded}
                  forceExpand={!!ql}
                  selection={selection}
                  drawerOpen={drawerOpen}
                  onToggle={makeExpandToggleHandler(setExpanded)}
                  onOpenDest={openDest}
                  onOpenEndpoint={makeOpenEndpointHandler(push, q)}
                />
              </TabsContent>
            ) : (
              <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-2 overflow-y-auto p-3.5 text-center text-text-3">
                <SearchIcon aria-hidden focusable={false} className="size-6" />
                <div className="text-sm">
                  {ql ? `No destinations match “${q}”` : 'No outbound data shares detected'}
                </div>
              </div>
            )}
          </Card>
        </Tabs>
      </div>

      {/*
        One Sheet root for both panels rather than two, so opening a detail
        from the review list never unmounts the overlay between them. `dest`
        arrives a round trip after the click, so a second Sheet would spend
        that gap with neither panel open.
      */}
      <Sheet
        open={reviewOpen || drawerOpen}
        onOpenChange={makeReviewSheetOpenChangeHandler(drawerOpen, closeDrawer, setReviewOpen)}
      >
        <SheetContent
          className={cn(
            'transition-[width] duration-200 ease-out',
            drawerOpen ? 'w-117 max-w-[92%] gap-0 p-0' : 'w-160 max-w-[94%] gap-0 p-0',
          )}
          {...(drawerOpen ? { 'aria-describedby': undefined } : {})}
        >
          {drawerOpen ? (
            <>
              <SheetTitle className="sr-only">
                {destination ? destination.name : 'Data share detail'}
              </SheetTitle>
              {destination ? (
                <>
                  {decisionError && (
                    <div
                      role="alert"
                      className="border-b border-border bg-sev-critical-fill px-4 py-2.5 text-sm text-sev-critical-ink"
                    >
                      {decisionError}
                    </div>
                  )}
                  <DataShareDetailView
                    renderedAt={renderedAt}
                    destination={destination}
                    endpoint={selectedEp}
                    isSettingDecision={isSettingDecision}
                    onSetDecision={makeSetDecisionHandler({
                      isSettingDecision,
                      destinationId: destination.id,
                      setDecisionError,
                      startTransition,
                      setEgressDecision,
                    })}
                    onPick={makeOnPickHandler(push, q, destination.id)}
                    onBack={makeOnBackHandler(push, q, destination.id)}
                  />
                </>
              ) : (
                <div className="grid h-full place-items-center p-6 text-center text-sm text-text-3">
                  Not found
                </div>
              )}
            </>
          ) : (
            // Header pinned, rows scrolling under it — matching the detail
            // panel's own header/body split, so a long list doesn't scroll
            // the sheet's title away.
            <div className="flex h-full min-h-0 flex-col">
              <SheetHeader className="border-b border-border px-4.5 py-4">
                <SheetTitle>Needs review</SheetTitle>
                <SheetDescription>
                  {review.length} destination{review.length === 1 ? '' : 's'} flagged for raw IPs,
                  plaintext transfers &amp; unverified domains
                </SheetDescription>
              </SheetHeader>
              <div className="min-h-0 flex-1 overflow-y-auto p-4.5">
                <NeedsReviewListView items={review} onReview={openReviewedDest} />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
