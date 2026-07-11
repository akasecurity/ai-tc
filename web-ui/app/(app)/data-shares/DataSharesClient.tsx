'use client';

import {
  DataShareDetailView,
  DataSharesTableView,
  NeedsReviewStripView,
  type ShareSelection,
} from '@akasecurity/dashboard-ui';
import type {
  EgressDecision,
  ReviewDestination,
  ShareDestinationDetail,
  ShareDestinationGroup,
  SharesStats,
} from '@akasecurity/schema';
import { Card, Sheet, SheetContent, SheetTitle } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useState, useTransition } from 'react';

import { SearchIcon } from '../../components/icons';
import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { setEgressDecision } from './actions';
import { buildDataSharesParams } from './filters';

/**
 * Client shell for the OSS Data Shares page. The grouped register, needs-review
 * strip and selected destination detail come from the Server Component (which
 * reads the local store per URL); search + selection push a new URL so the server
 * re-queries — the OSS store is server-only. Expanded rows + the review-strip
 * collapse are local-only client state. The egress-decision write goes through a
 * Server Action (the detail view's onSetDecision).
 */
export function DataSharesClient({
  q,
  stats,
  groups,
  review,
  destination,
  selectedDest,
  selectedEndpoint,
}: {
  q: string;
  stats: SharesStats;
  groups: ShareDestinationGroup[];
  review: ReviewDestination[];
  destination: ShareDestinationDetail | null;
  selectedDest: string | null;
  selectedEndpoint: string | null;
}) {
  const router = useRouter();
  const pathname = usePathname();

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showReview, setShowReview] = useState(true);
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
      router.push(buildUrl(opts));
    },
    [onNavigate, router, buildUrl],
  );

  const selection: ShareSelection | null = selectedDest
    ? { id: selectedDest, ...(selectedEndpoint ? { endpointId: selectedEndpoint } : {}) }
    : null;
  const drawerOpen = selectedDest !== null;
  const selectedEp =
    destination && selectedEndpoint
      ? (destination.endpoints.find((e) => e.id === selectedEndpoint) ?? null)
      : null;

  const openDest = (id: string) => {
    push({ q, dest: id });
  };
  const closeDrawer = () => {
    setDecisionError(null);
    push({ q });
  };

  const ql = q.trim();

  return (
    <>
      {/* Filter bar */}
      <div className="mb-3.5 flex shrink-0 flex-wrap items-center gap-2.5">
        <div className="flex h-9 w-full items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 sm:w-80">
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
        <span className="h-6 w-px bg-border" />
        <span className="text-ui text-text-3">
          <b className="text-text">{stats.destinations}</b> destinations ·{' '}
          <b className="text-text">{stats.endpoints}</b> endpoints ·{' '}
          <b className="text-text">{stats.callSites}</b> call sites
        </span>
      </div>

      {/* Body */}
      <div className="flex min-h-0 flex-1 flex-col">
        {!ql && (
          <div className="shrink-0">
            <NeedsReviewStripView
              items={review}
              open={showReview}
              onToggle={() => {
                setShowReview((s) => !s);
              }}
              onReview={openDest}
            />
          </div>
        )}
        <Card className="flex min-h-112 flex-1 flex-col overflow-hidden">
          <div className="min-h-0 flex-1 overflow-y-auto p-3.5">
            {groups.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center text-text-3">
                <SearchIcon aria-hidden focusable={false} className="size-6" />
                <div className="text-sm">
                  {ql ? `No destinations match “${q}”` : 'No outbound data shares detected'}
                </div>
              </div>
            ) : (
              <DataSharesTableView
                groups={groups}
                expanded={expanded}
                forceExpand={!!ql}
                selection={selection}
                drawerOpen={drawerOpen}
                onToggle={(id) => {
                  setExpanded((m) => ({ ...m, [id]: !m[id] }));
                }}
                onOpenDest={openDest}
                onOpenEndpoint={(id, endpointId) => {
                  push({ q, dest: id, ep: endpointId });
                }}
              />
            )}
          </div>
        </Card>
      </div>

      {/* Detail drawer */}
      <Sheet
        open={drawerOpen}
        onOpenChange={(open) => {
          if (!open) closeDrawer();
        }}
      >
        <SheetContent className="w-117 max-w-[92%] gap-0 p-0" aria-describedby={undefined}>
          <SheetTitle className="sr-only">
            {destination ? destination.name : 'Data share detail'}
          </SheetTitle>
          {destination ? (
            <>
              {decisionError && (
                <div
                  role="alert"
                  className="border-b border-border bg-sev-critical-fill px-4 py-2.5 text-sm text-sev-critical"
                >
                  {decisionError}
                </div>
              )}
              <DataShareDetailView
                destination={destination}
                endpoint={selectedEp}
                isSettingDecision={isSettingDecision}
                onSetDecision={(decision: EgressDecision | null) => {
                  if (isSettingDecision) return;
                  setDecisionError(null);
                  startTransition(async () => {
                    try {
                      const ok = await setEgressDecision(destination.id, decision);
                      if (!ok) {
                        setDecisionError(
                          'This destination no longer exists — reload to refresh the list.',
                        );
                      }
                    } catch {
                      setDecisionError('Could not update the egress decision. Please try again.');
                    }
                  });
                }}
                onPick={(endpointId) => {
                  push({ q, dest: destination.id, ep: endpointId });
                }}
                onBack={() => {
                  push({ q, dest: destination.id });
                }}
              />
            </>
          ) : (
            <div className="grid h-full place-items-center p-6 text-center text-sm text-text-3">
              Not found
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
