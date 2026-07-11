'use client';

import {
  AssetDetail,
  EmptyState,
  FileDetailDrawer,
  HarnessOverview,
  InventoryNav,
  type InventorySelection as Selection,
  ProjectPane,
} from '@akasecurity/dashboard-ui';
import type {
  AccessLevel,
  AssetDetail as AssetDetailData,
  AssetGroup,
  AssetSummary,
  AssetType,
  FileDetail,
  FileSummary,
  HarnessEventsResponse,
  HarnessSummary,
  ProjectSummary,
  ProjectTreeResponse,
  TrustLevel,
} from '@akasecurity/schema';
import { Card, Sheet, SheetContent } from '@akasecurity/ui-kit';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useState, useTransition } from 'react';

import { useDebouncedUrlQuery } from '../../lib/useDebouncedUrlQuery';
import { setFileAccess, setMcpTrust } from './actions';
import { buildInventoryParams } from './filters';

type TypeFilter = 'all' | AssetType;

/**
 * Client shell for the OSS Inventory page. The nav lists + the selected node's
 * detail come from the Server Component (which reads the local store per URL);
 * selecting a node, browsing a project's files, searching, or opening the file
 * drawer pushes a new URL so the server re-queries — the OSS store is server-only.
 * View mode / type filter / expanded rows / nav search are pure client state. The
 * file-access + MCP-trust edits go through Server Actions.
 */
export function InventoryClient({
  harnesses,
  assetGroups,
  projects,
  attention,
  activeSel,
  proj,
  selHarness,
  assetDetail,
  tree,
  blocked,
  harnessEvents,
  fileDetail,
  path,
  fq,
  drawer,
}: {
  harnesses: HarnessSummary[];
  assetGroups: AssetGroup[];
  projects: ProjectSummary[];
  attention: number;
  activeSel: Selection | null;
  proj: ProjectSummary | null;
  selHarness: HarnessSummary | null;
  assetDetail: AssetDetailData | null;
  tree: ProjectTreeResponse | null;
  blocked: FileSummary[];
  harnessEvents: HarnessEventsResponse | null;
  fileDetail: FileDetail | null;
  path: string[];
  fq: string;
  drawer: string | null;
}) {
  const router = useRouter();
  const pathname = usePathname();

  // Pure client state — no server refetch.
  const [viewMode, setViewMode] = useState<'tree' | 'type'>('tree');
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [navQuery, setNavQuery] = useState('');
  const [showBlocked, setShowBlocked] = useState(true);
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const first = harnesses[0]?.id;
    return first ? { [first]: true } : {};
  });
  const [isWriting, startTransition] = useTransition();
  // Surface a failed file-access / MCP-trust write instead of silently keeping the
  // old value — these are security-posture controls, so a silent no-op is worst.
  const [writeError, setWriteError] = useState<string | null>(null);

  const buildUrl = useCallback(
    (opts: { sel?: Selection | null; path?: string[]; fq?: string; file?: string | null }) => {
      const qs = buildInventoryParams(opts).toString();
      return qs ? `${pathname}?${qs}` : pathname;
    },
    [pathname],
  );

  // In-project file search — the shared hook owns debounce/resync/cancel. A
  // debounced search keeps the current selection + path and drops the drawer;
  // navigating with no term (a selection change) clears the box, so the previous
  // project's search never leaks onto the new node.
  const {
    query: fileQuery,
    setQuery: setFileQuery,
    onNavigate,
  } = useDebouncedUrlQuery(fq, (term) => buildUrl({ sel: activeSel, path, fq: term }));

  const push = useCallback(
    (opts: { sel?: Selection | null; path?: string[]; fq?: string; file?: string | null }) => {
      onNavigate(opts.fq ?? '');
      router.push(buildUrl(opts));
    },
    [onNavigate, router, buildUrl],
  );

  // Run a write action inside the transition, guarding against overlapping writes
  // and surfacing failure inline.
  const runWrite = (label: string, action: () => Promise<boolean>) => {
    if (isWriting) return;
    setWriteError(null);
    startTransition(async () => {
      try {
        if (!(await action())) setWriteError(`Couldn't ${label} — reload to refresh.`);
      } catch {
        setWriteError(`Couldn't ${label}. Please try again.`);
      }
    });
  };

  // Selection handlers — a new node drops path/fq/file so the file browser resets.
  const selectHarness = (id: string) => {
    push({ sel: { type: 'harness', id } });
  };
  const selectProject = (id: string) => {
    push({ sel: { type: 'project', id } });
  };
  const selectAsset = (it: AssetSummary) => {
    push({ sel: { type: it.type as Exclude<AssetType, 'project'>, id: it.id } });
  };

  return (
    <>
      {writeError && (
        <div
          role="alert"
          className="mb-3 shrink-0 rounded-lg border border-border bg-sev-critical-fill px-4 py-2.5 text-sm text-sev-critical"
        >
          {writeError}
        </div>
      )}
      <div className="flex min-h-0 flex-1 gap-4">
        <InventoryNav
          projects={projects}
          assetGroups={assetGroups}
          harnesses={harnesses}
          sel={activeSel}
          viewMode={viewMode}
          onViewMode={setViewMode}
          expanded={expanded}
          onToggleExpand={(id, next) => {
            setExpanded((m) => ({ ...m, [id]: next ?? !m[id] }));
          }}
          typeFilter={typeFilter}
          onTypeFilter={setTypeFilter}
          query={navQuery}
          onQuery={setNavQuery}
          attention={attention}
          onSelectProject={selectProject}
          onSelectAsset={selectAsset}
          onSelectHarness={selectHarness}
        />

        {proj ? (
          <ProjectPane
            proj={proj}
            path={path}
            onPathChange={(p) => {
              push({ sel: activeSel, path: p });
            }}
            query={fileQuery}
            onQueryChange={setFileQuery}
            tree={tree}
            isLoading={false}
            error={null}
            onSetAccess={(filePath, access) => {
              runWrite('update file access', () => setFileAccess(proj.id, filePath, access));
            }}
            onOpenFile={(filePath) => {
              push({ sel: activeSel, path, fq, file: filePath });
            }}
            drawerPath={drawer}
            blocked={blocked}
            showBlocked={showBlocked}
            onToggleBlocked={() => {
              setShowBlocked((s) => !s);
            }}
          />
        ) : (
          <Card className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
            {selHarness ? (
              <HarnessOverview
                harness={selHarness}
                events={harnessEvents}
                onSelect={selectAsset}
                onSelectProject={selectProject}
              />
            ) : assetDetail ? (
              <AssetDetail
                asset={assetDetail}
                onTrust={(v: TrustLevel) => {
                  runWrite('update MCP trust', () => setMcpTrust(assetDetail.id, v));
                }}
              />
            ) : (
              <div className="grid min-h-0 flex-1 place-items-center p-8">
                <EmptyState message="No assets to display" />
              </div>
            )}
          </Card>
        )}
      </div>

      {/* per-file detail drawer */}
      <Sheet
        open={drawer !== null && proj !== null}
        onOpenChange={(open) => {
          if (!open) push({ sel: activeSel, path, fq });
        }}
      >
        <SheetContent className="max-w-120 p-0" aria-describedby={undefined}>
          {proj &&
            drawer !== null &&
            (fileDetail ? (
              <FileDetailDrawer
                file={fileDetail}
                onChange={(v: AccessLevel) => {
                  runWrite('update file access', () => setFileAccess(proj.id, fileDetail.path, v));
                }}
              />
            ) : (
              <div className="grid h-full place-items-center p-6 text-center text-sm text-text-3">
                File not found
              </div>
            ))}
        </SheetContent>
      </Sheet>
    </>
  );
}
