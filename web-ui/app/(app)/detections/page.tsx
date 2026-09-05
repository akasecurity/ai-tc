import {
  type DetectionPolicyFloor,
  PageHead,
  showsVaultDrift,
  type SummaryStatItem,
  SummaryStripView,
  VAULT_DRIFT_BODY,
  VAULT_DRIFT_TITLE,
  type VaultDriftState,
} from '@akasecurity/dashboard-ui';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { DetectionListItem, WorkspaceSettings } from '@akasecurity/schema';
import { isAttached, isVaultConsentValid } from '@akasecurity/schema';

import { ActivityIcon, BracesIcon, ListIcon, ShieldCheckIcon } from '../../components/icons';
import { db } from '../../lib/db';
import { DetectionsClient } from './DetectionsClient';
import {
  type DetectionsSearchParams,
  parseDetectionFilter,
  parseDetectionQuery,
  parseSelectedId,
  toListQuery,
} from './filters';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Detections' };

// Reads the local store's installed detections + stats for the URL's filter/search,
// resolves the selected detail, then hands off to the client shell for the
// interactive master/detail + rule inspector. List state lives in the URL so this
// re-runs (server-side) on every filter/search/select change.
export default async function DetectionsPage({
  searchParams,
}: {
  searchParams: Promise<DetectionsSearchParams>;
}) {
  const sp = await searchParams;
  const filter = parseDetectionFilter(sp);
  const query = parseDetectionQuery(sp);
  const requestedId = parseSelectedId(sp);

  const store = db();
  const detections = store.detections;
  const [stats, list] = await Promise.all([
    detections.getDetectionStats(),
    detections.listDetections(toListQuery(filter, query)),
  ]);

  // ONE settings read for the render, shared by both answers below. They ask
  // this file different questions (is this machine attached, did it ever
  // consent to vaulting), and reading it twice would let one render describe two
  // different moments of the same machine. Null when it cannot be read at all,
  // which both treat as the unconstrained answer.
  const settings = readSettings();

  // Whether this machine used to vault and now does not — see showsVaultDrift.
  // Read UNFILTERED, from the policy catalog rather than `list`: `list` is
  // narrowed by the URL's filter and search, so a user who had typed a query
  // would be told nothing is vaulted whenever their query happened to exclude
  // the pack that is.
  //
  // Fail-open like every other read on this page: if any part of it throws, the
  // page renders without the notice rather than not at all.
  const vaultDrift = await readVaultDrift(store, settings);

  // What this machine's organization requires per detection, if anything. The
  // store computes it and functions cannot cross into the browser, so what goes
  // down is a plain record of the two facts each answer carries.
  const floors = readPolicyFloors(store, list.items, settings);

  // Honor the pinned ?id when it's still in the filtered list; otherwise default
  // to the first row so the detail pane is never empty when detections exist.
  const selectedId =
    requestedId && list.items.some((d) => d.id === requestedId)
      ? requestedId
      : (list.items[0]?.id ?? '');
  const detail = selectedId ? await detections.getDetectionDetail(selectedId) : null;

  const statItems: SummaryStatItem[] = [
    {
      icon: ListIcon,
      value: stats.detections.toLocaleString(),
      label: 'Detections',
      tone: 'primary',
    },
    {
      icon: BracesIcon,
      value: stats.rules.toLocaleString(),
      label: 'Rules',
      tone: 'violet',
    },
    {
      icon: ShieldCheckIcon,
      // Both halves formatted the same way: this cell and the Detections cell
      // above render the same number, so they must not disagree about it.
      value: `${stats.active.toLocaleString()} / ${stats.detections.toLocaleString()}`,
      label: 'Active',
      tone: 'ok',
    },
    {
      icon: ActivityIcon,
      value: stats.findingsLast30d.toLocaleString(),
      label: 'Findings · 30d',
      tone: 'neutral',
    },
  ];
  return (
    <div className="flex h-full min-h-0 flex-col p-6">
      <PageHead title="Detections" sub="Rules that generate findings from code, prompts & pastes" />

      {showsVaultDrift(vaultDrift) && (
        <div
          className="mb-4 rounded-xl border border-sev-high-fill bg-sev-high-fill px-4 py-3"
          data-slot="vault-drift-notice"
        >
          <p className="text-sm font-semibold text-sev-high-ink">{VAULT_DRIFT_TITLE}</p>
          <p className="mt-1 text-xs text-text-2">{VAULT_DRIFT_BODY}</p>
        </div>
      )}

      {/* stat strip — the compact single-Card form the Activity page uses. */}
      <SummaryStripView items={statItems} isLoading={false} />

      <DetectionsClient
        list={list}
        detail={detail}
        filter={filter}
        query={query}
        selectedId={selectedId}
        floors={floors}
      />
    </div>
  );
}

/**
 * The machine's settings, or null when the file cannot be read at all.
 *
 * Read here rather than inside each consumer so one render asks the file once.
 * Not a cache: the reader is deliberately live, and the next render reads it
 * again — this is one snapshot for one page, which is what makes the two
 * answers below consistent with each other.
 */
function readSettings(): WorkspaceSettings | null {
  try {
    return readWorkspaceSettings();
  } catch {
    return null;
  }
}

/**
 * The control-plane floor on each listed detection, keyed by detection id.
 *
 * Detections the organization says nothing about are simply absent, so a
 * standalone machine sends an empty record and every surface downstream renders
 * exactly as it did before this existed.
 *
 * The attachment check up front is not redundant with the per-pack read — that
 * one answers null for an unattached machine too. It is there because the
 * per-pack read re-opens settings.json and the cached bundle EACH time, and a
 * page listing thirty detections would pay for those reads per pack to learn
 * what the one settings read above already settles for the overwhelmingly
 * common case. Attached, that per-pack cost stands: the store's floor entry
 * point takes one pack, so collapsing it into a single parse of the cached
 * bundle is a change to make below this page, not on it.
 *
 * Fail-open like every other read on this page: a store or a settings file that
 * cannot answer must render the page without the constraint rather than not at
 * all. The store is still the authority on the write, so a floor missing from
 * this record costs a refusal the user can read, never an assignment that
 * silently sticks.
 */
function readPolicyFloors(
  store: ReturnType<typeof db>,
  items: readonly DetectionListItem[],
  settings: WorkspaceSettings | null,
): Record<string, DetectionPolicyFloor> {
  try {
    if (settings === null || !isAttached(settings)) return {};
    // One batch read: the settings and the cached bundle are read and parsed
    // once for the whole page rather than once per row, which is what asking
    // per pack costs. Keyed `namespace/packId` there, re-keyed to the list's
    // own ids here, and a pack the control plane does not govern simply has no
    // entry — the same answer the single-pack read gives as null.
    const byPack = store.installedPacks.policyFloors(items);
    const floors: Record<string, DetectionPolicyFloor> = {};
    for (const item of items) {
      const floor = byPack.get(`${item.namespace}/${item.packId}`);
      if (floor !== undefined) floors[item.id] = floor;
    }
    return floors;
  } catch {
    return {};
  }
}

// The three facts showsVaultDrift needs, each read defensively: a store that
// cannot answer one of them must not take the whole page down over a notice.
async function readVaultDrift(
  store: ReturnType<typeof db>,
  settings: WorkspaceSettings | null,
): Promise<VaultDriftState> {
  try {
    if (settings === null || !isVaultConsentValid(settings.vaultConsent)) {
      // No valid grant — nothing was being vaulted before this change either,
      // so there is no drift to report and no need to count anything.
      return { consentValid: false, vaultEntries: 0, vaultAssignedPacks: 0 };
    }
    const policies = await store.policyCatalog.getPolicyList();
    const vaultPolicy = policies.items.find((p) => p.id === 'vault');
    return {
      consentValid: true,
      vaultEntries: store.secretVault.countEntries(),
      vaultAssignedPacks: vaultPolicy?.usedByCount ?? 0,
    };
  } catch {
    return { consentValid: false, vaultEntries: 0, vaultAssignedPacks: 0 };
  }
}
