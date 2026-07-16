'use client';

import { SessionDetailView, SessionListView, type TimeRange } from '@akasecurity/dashboard-ui';
import type {
  ActivitySession,
  ActivitySessionSummary,
  Harness,
  SessionTokenReport,
} from '@akasecurity/schema';
import { Card } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback } from 'react';

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
  q: initialQuery,
  harness,
  harnessOptions,
  range,
  selectedId,
  hasMore,
}: {
  sessions: ActivitySessionSummary[];
  detail: ActivitySession | null;
  tokenReport: SessionTokenReport | null;
  q: string;
  harness: Harness[];
  /** Harnesses that actually have sessions — the filter offers only these. */
  harnessOptions: Harness[];
  range: TimeRange;
  selectedId: string;
  hasMore: boolean;
}) {
  const router = useRouter();
  const pathname = usePathname();

  const buildUrl = useCallback(
    (opts: { q: string; harness: Harness[]; range: TimeRange; id?: string }) => {
      const qs = buildActivityParams(opts).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook. A
  // debounced search drops the selection (?id) so the server lands on the first
  // match; explicit navigations preserve the current harness/range.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl({ q: term, harness, range }),
  );

  const push = useCallback(
    (opts: { q: string; harness: Harness[]; range: TimeRange; id?: string }) => {
      onNavigate(opts.q);
      router.push(buildUrl(opts));
    },
    [onNavigate, router, buildUrl],
  );

  return (
    <div className="flex min-h-0 flex-1 gap-4">
      <Card className="flex w-85 shrink-0 flex-col overflow-hidden shadow-sm">
        <SessionListView
          sessions={sessions}
          selectedId={selectedId}
          onSelect={(id) => {
            push({ q: query, harness, range, id });
          }}
          query={query}
          onQuery={setQuery}
          harness={harness}
          harnessOptions={harnessOptions}
          onHarness={(next) => {
            push({ q: query, harness: next, range });
          }}
          isLoading={false}
          error={null}
          hasMore={hasMore}
        />
      </Card>
      <Card className="flex min-w-0 flex-1 flex-col overflow-hidden shadow-sm">
        <SessionDetailView
          session={detail}
          tokenReport={tokenReport}
          isLoading={false}
          error={null}
          // Tool chips deep-link to the findings page scoped to that tool —
          // `q` matches the instance location label ("via Bash") of findings
          // captured from that tool's input/output.
          toolHref={(toolName) => `/findings?q=${encodeURIComponent(`via ${toolName}`)}`}
        />
      </Card>
    </div>
  );
}
