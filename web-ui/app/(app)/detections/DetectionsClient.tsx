'use client';

import {
  DetectionDetailView,
  DetectionsListView,
  MatcherModal,
  provenanceState,
  UpdateModal,
} from '@akasecurity/dashboard-ui';
import type { DetectionDetail, ListDetectionsResponse } from '@akasecurity/schema';
import { Card } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useMemo, useState, useTransition } from 'react';

import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import {
  pullDetectionUpdate,
  recheckDetections,
  setDetectionEnabled,
  setDetectionPolicy,
} from './actions';
import { buildDetectionsParams } from './filters';

// Tabs: updates come from the available_packs mirror (what the running
// plugin/CLI ships); there is no local custom/customized rule model.
const OSS_TABS: readonly [string, string][] = [
  ['all', 'All'],
  ['library', 'Library'],
  ['updates', 'Updates'],
];

/**
 * Client shell for the OSS detections page. The list + selected detail come from
 * the Server Component (which reads the local store per URL); filter/search/select
 * changes push a new URL so the server re-queries — the OSS store is server-only.
 * The rule inspector is local client state.
 *
 * Enforcement-policy, enable/disable, and PULLING UPDATES go through Server
 * Actions. Updates are manual by design: the plugin/CLI only records what's
 * available; nothing moves an installed pack forward until the user confirms
 * here (or via `aka detections update`).
 */
export function DetectionsClient({
  list,
  detail,
  filter,
  query: initialQuery,
  selectedId,
}: {
  list: ListDetectionsResponse;
  detail: DetectionDetail | null;
  filter: string;
  query: string;
  selectedId: string;
}) {
  const router = useRouter();
  const pathname = usePathname();

  const [editRuleId, setEditRuleId] = useState<string | null>(null);
  const [updateOpen, setUpdateOpen] = useState(false);
  const [isPending, startTransition] = useTransition();
  // The update apply gets its own transition: sharing one flag would render the
  // modal's confirm as "Updating…"/disabled while a mere enable-toggle or
  // policy change is in flight (and vice versa).
  const [isUpdating, startUpdate] = useTransition();

  // id → latest version, for the per-row amber update badges. Derived straight
  // from the list items (the store sets latestVersion only when a newer
  // snapshot exists), so no extra fetch.
  const updatesById = useMemo(() => {
    const m = new Map<string, string>();
    for (const i of list.items) if (i.latestVersion) m.set(i.id, i.latestVersion);
    return m;
  }, [list.items]);

  const buildUrl = useCallback(
    (opts: { filter: string; q: string; id?: string }) => {
      const qs = buildDetectionsParams(opts).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // Search box + debounce/resync/cancel invariants live in the shared hook. A
  // debounced search drops the selection (?id) so the server lands on the first
  // match; explicit navigations preserve the current filter/search.
  const { query, setQuery, onNavigate } = useDebouncedUrlQuery(initialQuery, (term) =>
    buildUrl({ filter, q: term }),
  );

  const push = useCallback(
    (opts: { filter: string; q: string; id?: string }) => {
      onNavigate(opts.q);
      router.push(buildUrl(opts));
    },
    [onNavigate, router, buildUrl],
  );

  const editRule =
    detail && editRuleId ? (detail.rules.find((r) => r.id === editRuleId) ?? null) : null;

  // Single source of truth for the three provenance states (see meta.ts): the
  // detail affordances (Update button, "Check again") gate on this so they can
  // never disagree with what ProvenanceBlock renders.
  const provenance = detail ? provenanceState(detail) : null;

  return (
    <>
      <div className="mt-4 grid min-h-0 flex-1 grid-cols-[352px_1fr] gap-4">
        <DetectionsListView
          items={list.items}
          counts={list.counts}
          activeId={selectedId}
          query={query}
          filter={filter}
          onQueryChange={setQuery}
          onFilterChange={(f) => {
            push({ filter: f, q: query });
          }}
          onSelect={(id) => {
            setEditRuleId(null);
            push({ filter, q: query, id });
          }}
          filterTabs={OSS_TABS}
          updatesById={updatesById}
        />

        {/* detail */}
        <Card className="flex flex-col overflow-hidden shadow-sm">
          {detail ? (
            <DetectionDetailView
              d={detail}
              onOpenRule={setEditRuleId}
              onToggleEnabled={() => {
                // Ignore repeat clicks while a write is in flight: `detail.enabled`
                // only updates after the action revalidates, so a second click would
                // re-send the same (now stale) target instead of toggling back.
                if (isPending) return;
                // Pin this detection in the URL first. The action's revalidate re-runs
                // buildDetectionsList (enabled-first sort), so a just-disabled row drops
                // to the bottom; without a pinned ?id the implicit first-row selection
                // would jump to a different detection and look like the toggle hit the
                // wrong one.
                push({ filter, q: query, id: detail.id });
                startTransition(() => {
                  void setDetectionEnabled(detail.id, !detail.enabled);
                });
              }}
              onChangePolicy={(policyId) => {
                startTransition(() => {
                  void setDetectionPolicy(detail.id, policyId);
                });
              }}
              onOpenUpdate={
                provenance === 'update-available'
                  ? () => {
                      setUpdateOpen(true);
                    }
                  : undefined
              }
              onRecheck={
                // "Check again" for the unknown provenance state: re-read the
                // store (the CLI/plugin record inventories — see actions.ts).
                provenance === 'unknown'
                  ? () => {
                      startTransition(() => {
                        void recheckDetections();
                      });
                    }
                  : undefined
              }
              // unknownHint is consumer-supplied copy for the unknown state:
              // here the inventory is recorded by the local CLI/plugin, so
              // point the user at those.
              unknownHint={
                <>
                  run <code className="font-mono">aka detections</code> or start a Claude Code
                  session to record what your binaries ship
                </>
              }
            />
          ) : (
            <div className="grid flex-1 place-items-center p-6 text-center text-sm text-text-3">
              {/* counts.all distinguishes a truly empty store from a merely
                  empty FILTER — the updates tab is legitimately empty in steady
                  state (and right after applying the last update). */}
              {list.counts.all === 0
                ? 'No detections installed — run the plugin to populate the local store.'
                : list.items.length === 0
                  ? filter === 'updates'
                    ? 'No pending updates — every detection is up to date.'
                    : 'No detections in this view.'
                  : 'Select a detection to view its rules'}
            </div>
          )}
        </Card>
      </div>

      {/* rule inspector — `key` remounts it with fresh state per opened rule. */}
      <MatcherModal
        key={editRuleId ?? 'no-rule'}
        rule={editRule}
        onClose={() => {
          setEditRuleId(null);
        }}
      />

      {/* manual update confirm — the ONLY path that moves an installed pack to a
          newer snapshot. Pin ?id first (like the enable toggle) so the selection
          survives the revalidate re-sort, then apply + close. Gated on
          update.available so a revalidate/back-navigation that swaps in an
          up-to-date detail can't leave a broken "v2.0.0 → v" dialog open. */}
      <UpdateModal
        det={updateOpen && detail?.update?.available ? detail : null}
        isUpdating={isUpdating}
        onClose={() => {
          setUpdateOpen(false);
        }}
        onConfirm={(id) => {
          if (isUpdating) return;
          push({ filter, q: query, id });
          startUpdate(async () => {
            // The action never rejects by contract, but a transport-level
            // failure still must not escape the transition (it would replace
            // the page with the route error boundary) — close the modal either
            // way; the revalidated row is the honest outcome report.
            try {
              await pullDetectionUpdate(id);
            } finally {
              setUpdateOpen(false);
            }
          });
        }}
      />
    </>
  );
}
