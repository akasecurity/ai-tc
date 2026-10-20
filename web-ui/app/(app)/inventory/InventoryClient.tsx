'use client';

import {
  AssetDetail,
  EmptyState,
  HarnessInventory,
  InventoryDetailFallback,
  InventoryNav,
  type InventoryRow,
  type InventorySelection as Selection,
  inventoryTypeMeta,
  ProjectDetail,
  rowType,
  TypeInventory,
  typeRows,
  useRenderClock,
} from '@akasecurity/dashboard-ui';
import type {
  AssetDetail as AssetDetailData,
  AssetGroup,
  FileSummary,
  HarnessEventsResponse,
  HarnessSummary,
  ProjectSummary,
  SensitiveDataClass,
  TrustLevel,
} from '@akasecurity/schema';
import { Card, cn } from '@akasecurity/ui-kit';
import { usePathname } from 'next/navigation';
import { useState, useTransition } from 'react';

import { useNavigationTransition } from '../../components/NavigationTransition';
import { setMcpTrust } from './actions';
import { buildInventoryParams } from './filters';

/**
 * Client shell for the OSS Inventory page. The lists and the opened row's detail
 * come from the Server Component, which reads the local store per URL; changing
 * the selection pushes a new URL so the server re-queries. Each table's search,
 * filters, sort and page are client state, and the table stays mounted while a
 * row is open so they survive the trip to the details page and back. The
 * MCP-trust edit goes through a Server Action.
 */
export function InventoryClient({
  harnesses,
  assetGroups,
  projects,
  active,
  assetDetail,
  blocked,
  blockedError,
  sensitiveData,
  sensitiveDataError,
  harnessEvents,
  renderedAt,
  locale,
}: {
  harnesses: HarnessSummary[];
  assetGroups: AssetGroup[];
  projects: ProjectSummary[];
  /** The selection the server resolved from the URL. */
  active: Selection;
  assetDetail: AssetDetailData | null;
  /** The opened project's auto-blocked files. */
  blocked: FileSummary[];
  /** Set when the opened project's withheld files could not be read. */
  blockedError: string | null;
  /** The opened project's findings in the findings window by category. */
  sensitiveData: SensitiveDataClass[];
  /** Set when the opened project's sensitive data could not be read. */
  sensitiveDataError: string | null;
  harnessEvents: HarnessEventsResponse;
  /**
   * The instant the server rendered against, advanced through useRenderClock —
   * see that hook's doc for why freezing it would turn relative times and the
   * harness feed's day buckets false in a long-open tab.
   */
  renderedAt: number;
  /** The locale the server resolved from the request's Accept-Language header. */
  locale: string;
}) {
  const renderClock = useRenderClock(renderedAt);
  const pathname = usePathname();
  const { isPending: navPending, push: pushUrl } = useNavigationTransition();
  const [isWriting, startTransition] = useTransition();
  // A failed MCP-trust write surfaces here rather than silently keeping the old
  // value — it is a security-posture control.
  const [writeError, setWriteError] = useState<string | null>(null);

  const navigate = (sel: Selection) => {
    const qs = buildInventoryParams(sel).toString();
    pushUrl(qs ? `${pathname}?${qs}` : pathname);
  };

  const harness = harnesses.find((h) => h.id === active.harness) ?? null;
  const item = active.item;
  const project =
    item?.type === 'project'
      ? (projects.find((p) => p.id === item.id) ??
        harness?.projects.find((p) => p.id === item.id) ??
        null)
      : null;
  const backLabel =
    active.view === 'harness'
      ? (harness?.label ?? 'harness')
      : inventoryTypeMeta(active.type).label;

  const open = (row: InventoryRow) => {
    navigate({ ...active, item: { type: rowType(row), id: row.id } });
  };
  const back = () => {
    navigate({ ...active, item: null });
  };
  const updateTrust = (assetId: string, trust: TrustLevel) => {
    if (isWriting) return;
    setWriteError(null);
    startTransition(async () => {
      try {
        if (!(await setMcpTrust(assetId, trust))) {
          setWriteError("Couldn't update MCP trust — reload to refresh.");
        }
      } catch {
        setWriteError("Couldn't update MCP trust. Please try again.");
      }
    });
  };

  return (
    <>
      {writeError && (
        <div
          role="alert"
          className="mb-3 shrink-0 rounded-lg border border-border bg-sev-critical-fill px-4 py-2.5 text-sm text-sev-critical-ink"
        >
          {writeError}
        </div>
      )}
      <div
        aria-busy={navPending}
        className={cn(
          'flex min-h-0 flex-1 gap-4 transition-shadow duration-150',
          navPending && 'rounded-lg ring-2 ring-primary/70 ring-inset',
        )}
      >
        <InventoryNav
          harnesses={harnesses}
          projects={projects}
          assetGroups={assetGroups}
          view={active.view}
          onView={(view) => {
            navigate({ ...active, view, item: null });
          }}
          harness={active.harness}
          type={active.type}
          onSelectHarness={(id) => {
            navigate({ ...active, view: 'harness', harness: id, item: null });
          }}
          onSelectType={(type) => {
            navigate({ ...active, view: 'type', type, item: null });
          }}
        />

        <Card className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <div className={cn('flex min-h-0 flex-1 flex-col', item && 'hidden')}>
            {active.view === 'harness' ? (
              harness ? (
                <HarnessInventory
                  key={harness.id}
                  harness={harness}
                  events={harnessEvents}
                  onOpen={open}
                  renderedAt={renderClock}
                  locale={locale}
                />
              ) : (
                <div className="grid min-h-0 flex-1 place-items-center p-8">
                  <EmptyState message="No assets to display" />
                </div>
              )
            ) : (
              <TypeInventory
                key={active.type}
                type={active.type}
                rows={typeRows(active.type, projects, assetGroups)}
                onOpen={open}
                renderedAt={renderClock}
              />
            )}
          </div>

          {project ? (
            <ProjectDetail
              project={project}
              blocked={blocked}
              blockedError={blockedError}
              sensitiveData={sensitiveData}
              sensitiveDataError={sensitiveDataError}
              harnesses={harnesses}
              onBack={back}
              backLabel={backLabel}
              renderedAt={renderClock}
              locale={locale}
            />
          ) : item && assetDetail ? (
            <AssetDetail
              asset={assetDetail}
              onTrust={(v) => {
                updateTrust(assetDetail.id, v);
              }}
              onBack={back}
              backLabel={backLabel}
              locale={locale}
            />
          ) : item ? (
            <InventoryDetailFallback
              message="This item is no longer in the inventory"
              onBack={back}
              backLabel={backLabel}
            />
          ) : null}
        </Card>
      </div>
    </>
  );
}
