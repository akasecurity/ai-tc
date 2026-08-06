'use client';

import {
  type BuildActivityLinkHref,
  SessionDetailView,
  SessionListView,
  type TimeRange,
} from '@akasecurity/dashboard-ui';
import type {
  ActivitySession,
  ActivitySessionSummary,
  Harness,
  SessionTokenReport,
} from '@akasecurity/schema';
import { Card, cn, Sheet, SheetContent, SheetTitle } from '@akasecurity/ui-kit';
import { usePathname } from 'next/navigation';
import { useCallback } from 'react';

import { useNavigationTransition } from '../../components/NavigationTransition';
import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { buildActivityParams } from './filters';

/**
 * Client shell for the OSS Activity page. The session list + selected detail come
 * from the Server Component (which reads the local store per URL); search/harness/
 * selection changes push a new URL so the server re-queries — the OSS store is
 * server-only, so filtering can't happen in the browser over a passed-down set.
 * Read-only page: no Server Actions here.
 */
export function ActivityClient({
  sessions,
  detail,
  tokenReport,
  liveFindings,
  q: initialQuery,
  harness,
  harnessOptions,
  range,
  selectedId,
  hasMore,
  emptyCount,
  showEmpty,
  expanded,
}: {
  sessions: ActivitySessionSummary[];
  detail: ActivitySession | null;
  tokenReport: SessionTokenReport | null;
  /** The selected session's live-enforced unique-findings count + its
   * session-scoped findings-page link (computed server-side; null when the
   * findings page has nothing to show for the session). */
  liveFindings: { count: number; href: string } | null;
  q: string;
  harness: Harness[];
  /** Harnesses that actually have sessions — the filter offers only these. */
  harnessOptions: Harness[];
  range: TimeRange;
  selectedId: string;
  hasMore: boolean;
  /** Zero-activity sessions in range (the collapse toggle's label). */
  emptyCount: number;
  /** Whether zero-activity sessions are currently listed (?empty=1). */
  showEmpty: boolean;
  /** Whether the full-width session inspector is open (?view=full). */
  expanded: boolean;
}) {
  const pathname = usePathname();
  const { isPending, push: pushUrl, replace: replaceUrl } = useNavigationTransition();

  // Timeline deep links: a detection event opens the findings page scoped to
  // this session (narrowed to the event's finding when the event carries one);
  // shares/inventory events open their surface's page. Defined here — functions
  // can't cross the Server→Client component boundary as props.
  const sessionId = detail?.id ?? '';
  const linkHref = useCallback<BuildActivityLinkHref>(
    (link, targetId) => {
      if (link === 'detections') {
        // The session scope is exact, so it stands alone — no range or harness
        // carry, which would only narrow a list already pinned to one session.
        const params = new URLSearchParams();
        if (sessionId) params.set('session', sessionId);
        if (targetId) params.set('finding', targetId);
        const qs = params.toString();
        return qs ? `/findings?${qs}` : '/findings';
      }
      return link === 'shares' ? '/data-shares' : '/inventory';
    },
    [sessionId],
  );

  const buildUrl = useCallback(
    (opts: {
      q: string;
      harness: Harness[];
      range: TimeRange;
      id?: string;
      showEmpty?: boolean;
      expanded?: boolean;
    }) => {
      const qs = buildActivityParams(opts).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook. A
  // debounced search drops the selection (?id) so the server lands on the first
  // match; explicit navigations preserve the current harness/range/empty toggle.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl({ q: term, harness, range, showEmpty }),
  );

  const push = useCallback(
    (opts: {
      q: string;
      harness: Harness[];
      range: TimeRange;
      id?: string;
      showEmpty?: boolean;
      expanded?: boolean;
    }) => {
      onNavigate(opts.q);
      pushUrl(buildUrl(opts));
    },
    [onNavigate, pushUrl, buildUrl],
  );

  // Push to open, replace to close.
  //
  // Opening is a real drill-down, so it earns a history entry: Back closes the
  // inspector and the open state survives a copied URL. Closing is the reverse of
  // that entry rather than a place of its own — pushing it would leave the panel
  // the reader just dismissed sitting on the Back path (and open/close/open would
  // stack a run of them), so the close overwrites the entry the open added.
  const setExpanded = useCallback(
    (next: boolean) => {
      const url = buildUrl({ q: query, harness, range, id: selectedId, showEmpty, expanded: next });
      // Settle the search debounce on both paths: it holds a URL built from the
      // pre-navigation state, so closing mid-typing would otherwise let the timer
      // fire a URL that predates the close and re-open the panel.
      onNavigate(query);
      (next ? pushUrl : replaceUrl)(url);
    },
    [buildUrl, onNavigate, pushUrl, replaceUrl, query, harness, range, selectedId, showEmpty],
  );

  // Shared by the docked pane and the inspector — one session, two frames, so
  // the deep links and figures must not drift between them.
  const detailProps = {
    session: detail,
    tokenReport,
    liveFindings,
    linkHref,
    isLoading: false,
    error: null,
    // Tool chips deep-link to the flat findings view filtered to that
    // tool. `?tool=` is a real filter on the capturing event's recorded
    // tool name, where the previous `?q=via Bash` was a text match
    // against a rendered label — it matched any finding whose search
    // text happened to contain the phrase, and missed nothing only by
    // luck. The session scope rides along so the link stays about this
    // session.
    toolHref: (toolName: string) => {
      const params = new URLSearchParams();
      params.set('view', 'flat');
      if (sessionId) params.set('session', sessionId);
      params.append('tool', toolName);
      return `/findings?${params.toString()}`;
    },
  };

  return (
    <div
      aria-busy={isPending}
      className={cn(
        'flex min-h-0 flex-1 gap-4 transition-shadow duration-150',
        isPending && 'rounded-lg ring-2 ring-primary/70 ring-inset',
      )}
    >
      <Card className="flex w-85 shrink-0 flex-col overflow-hidden shadow-sm">
        <SessionListView
          sessions={sessions}
          selectedId={selectedId}
          onSelect={(id) => {
            push({ q: query, harness, range, id, showEmpty });
          }}
          query={query}
          onQuery={setQuery}
          harness={harness}
          harnessOptions={harnessOptions}
          onHarness={(next) => {
            push({ q: query, harness: next, range, showEmpty });
          }}
          isLoading={false}
          error={null}
          hasMore={hasMore}
          emptyCount={emptyCount}
          showEmpty={showEmpty}
          onToggleEmpty={() => {
            push({ q: query, harness, range, id: selectedId, showEmpty: !showEmpty });
          }}
        />
      </Card>
      <Card className="flex min-w-0 flex-1 flex-col overflow-hidden shadow-sm">
        <SessionDetailView
          {...detailProps}
          onExpand={() => {
            setExpanded(true);
          }}
        />
      </Card>

      {/* The full-width inspector. Same view, more room: the docked pane shares
          the viewport with the session list, so a long timeline is read here.
          Open state is the URL's, not this component's — see setExpanded.

          `detail !== null` is a second guard, and it is the one that survives a
          hand-typed URL. parseExpanded already refuses `?view=full` with no ?id,
          but an id naming a session the store does not have parses as open and
          arrives here with nothing to render — so the panel stays shut on the
          session itself, not merely on the param that claims one. */}
      <Sheet
        open={expanded && detail !== null}
        onOpenChange={(open) => {
          if (!open) setExpanded(false);
        }}
      >
        {/* No description in this panel — opt out of Radix's aria-describedby. */}
        <SheetContent
          className="w-320 max-w-[96%] gap-0 overflow-hidden p-0"
          aria-describedby={undefined}
        >
          {/* The view renders its own visible heading; this is the accessible
              name Radix requires on the dialog. */}
          <SheetTitle className="sr-only">
            {detail ? `Session ${detail.title}` : 'Session'}
          </SheetTitle>
          <SessionDetailView {...detailProps} overlayClose />
        </SheetContent>
      </Sheet>
    </div>
  );
}
