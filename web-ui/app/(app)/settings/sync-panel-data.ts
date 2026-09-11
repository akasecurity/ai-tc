import 'server-only';

import type {
  SyncKindRow,
  SyncLocalOnlyLine,
  SyncPanelState,
  SyncPanelViewProps,
} from '@akasecurity/dashboard-ui';
import type { CountedEventType, HistorySyncKindPartition } from '@akasecurity/persistence';
import {
  dataDir,
  isForwardPaused,
  isHistorySyncLeaseLive,
  readForwardHealth,
  readHistorySyncState,
} from '@akasecurity/persistence';
import type { CredentialState, WorkspaceSettings } from '@akasecurity/schema';
import {
  isAttached,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
} from '@akasecurity/schema';

import { db } from '../../lib/db.ts';

/**
 * Everything the sync panel renders from, as a Server Component reads it.
 *
 * The view's own props minus the callbacks, because those belong to the client
 * that can hold them — this is the serialisable half, and every field in it is
 * a number, a string or a member of a closed enum.
 */
export type SyncPanelData = Omit<SyncPanelViewProps, 'onSyncNow' | 'busy' | 'startError'>;

/**
 * What each counted lane is called on screen.
 *
 * EXHAUSTIVE over `CountedEventType` rather than a lookup with a fallback: a
 * kind added to the ledger and not to this map is a compile error here, instead
 * of a bar labelled `tool_use` in front of a user. The store's own names are
 * not labels — `llm_call` is an implementation detail of how activity is
 * recorded, and this is the one place that decides what to call it.
 */
const KIND_LABELS: Record<CountedEventType, string> = {
  session: 'Sessions',
  llm_call: 'Model calls',
  tool_call: 'Tool calls',
  prompt: 'Prompts',
  response: 'Responses',
  tool_use: 'Tool inputs',
};

/**
 * What this machine holds that its deployment does not receive as rows.
 *
 * LINES, never bars, and no counts — see SyncLocalOnlyLine for why a bar would
 * be a false statement about these rather than a rough one. A count is left off
 * for a smaller reason: none of these has a denominator, so the number answers
 * nothing a reader could act on, and each one is a fresh scan of a large table
 * on a page load.
 */
const LOCAL_ONLY: readonly SyncLocalOnlyLine[] = [
  {
    id: 'findings',
    label: 'Findings',
    detail: 'derived by your deployment from the activity it receives, not sent from here',
  },
  {
    id: 'shares',
    label: 'Data shares',
    detail: 'reconciled whole-project on each pass, so there is no per-item backlog',
  },
  {
    id: 'inventory',
    label: 'Inventory',
    detail: 'a snapshot keyed by id — the latest pass replaces the last one',
  },
];

/** Why a credential this machine holds will not authenticate, said to a user. */
function credentialDetail(state: Extract<CredentialState, { usable: false }>): string {
  switch (state.reason) {
    case 'absent':
      return 'This machine holds no key for your deployment. Re-attach to resume sending.';
    case 'endpoint-mismatch':
      return `This machine holds a key for ${state.credentialEndpoint} but settings name ${state.settingsEndpoint}. Re-attach, or point settings back.`;
    case 'untrusted-file':
      return 'The key file on this machine is not trusted — it is a link, or owned by someone else. Re-attach to replace it.';
    case 'unsafe-endpoint':
      return 'The key on this machine was minted against an endpoint this build will not send to. Re-attach to resume sending.';
    case 'unreadable':
    case 'malformed':
      return 'The key file on this machine could not be read. Re-attach to replace it.';
  }
}

/**
 * One counted lane as a row, or nothing.
 *
 * A kind the store reported but that holds no rows is dropped rather than
 * rendered at 0 of 0 — the partition omits a kind with nothing to report, and a
 * total of zero arriving anyway is the same statement one layer down.
 */
function toRow(p: HistorySyncKindPartition): SyncKindRow | null {
  if (p.total === 0) return null;
  return {
    kind: p.kind,
    label: KIND_LABELS[p.kind],
    synced: p.synced,
    // In-progress rows are CLAIMED, not sent: something is working on them now,
    // which is what queued means to a reader deciding whether to wait.
    queued: p.queued + p.inProgress,
    notSent: p.failed + p.refused + p.detached,
    total: p.total,
  };
}

/**
 * What the sync panel should say, or null when it should not be rendered.
 *
 * NULL FOR A STANDALONE MACHINE, and that is the honest answer rather than a
 * smaller one. A machine that has never attached is not a machine with nothing
 * to sync — it is one this panel has no business describing, and zeros in a bar
 * look identical to absence while meaning something else entirely. The page
 * renders nothing at all.
 *
 * The order of the branches below is the order of the questions a reader would
 * ask, and it is load-bearing in one place: a machine with no history grant is
 * `not-shared` and shows NO bars, because the ledger counts a backlog nothing
 * has been told it may send. Bars there would promise delivery of rows that
 * will sit for ever.
 */
export function readSyncPanel(
  settings: WorkspaceSettings,
  credentialState: CredentialState,
  renderedAt: number,
): SyncPanelData | null {
  const connection = settings.controlPlane;
  if (!isAttached(settings) || connection === undefined) return null;

  const ledger = db().historySync;
  const dir = dataDir();
  const progress = readHistorySyncState(dir);
  const base = {
    deployment: connection.label ?? connection.endpoint,
    renderedAt,
    running: isHistorySyncLeaseLive(ledger.lease(), renderedAt),
    // The breaker, which is the answer to "I pressed the button and nothing
    // happened". A pass started while it is open declines before it opens the
    // store, and the child is detached, so that decision reaches no surface at
    // all unless this page reads the same file the pass would.
    paused: isForwardPaused(readForwardHealth(dir, renderedAt), renderedAt),
    localOnly: LOCAL_ONLY,
    ...(progress === null
      ? {}
      : {
          lastOutcome: progress.lastOutcome,
          lastPassAt: new Date(progress.lastPassAtMs).toISOString(),
        }),
  };

  return { ...base, state: panelState(settings, credentialState, connection.endpoint, ledger) };
}

function panelState(
  settings: WorkspaceSettings,
  credentialState: CredentialState,
  endpoint: string,
  ledger: ReturnType<typeof db>['historySync'],
): SyncPanelState {
  // BEFORE the consent branches. A machine whose key will not authenticate
  // sends nothing whatever it was granted, and "not shared" read against that
  // machine describes a decision the user never made.
  if (!credentialState.usable) {
    return { status: 'credential-unusable', detail: credentialDetail(credentialState) };
  }
  // Stale before absent: both fail isHistorySyncConsentValid, and only one of
  // them is a grant the user can resume in place.
  if (isHistorySyncConsentStale(settings.historySyncConsent, endpoint)) {
    return { status: 'consent-stale' };
  }
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return { status: 'not-shared' };
  }

  const kinds = ledger.partitionByKind().map(toRow).filter(isRow);
  return kinds.length === 0 ? { status: 'nothing-recorded' } : { status: 'ready', kinds };
}

function isRow(row: SyncKindRow | null): row is SyncKindRow {
  return row !== null;
}
