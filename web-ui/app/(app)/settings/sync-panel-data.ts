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
import type { AttachmentMode, CredentialState, WorkspaceSettings } from '@akasecurity/schema';
import {
  isAttached,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
  resolveScope,
  scopeFilterOf,
} from '@akasecurity/schema';

import { db } from '../../lib/db.ts';

/**
 * Everything the sync panel renders from, as a Server Component reads it.
 *
 * The view's own props minus the callbacks, because those belong to the client
 * that can hold them — this is the serialisable half, and every field in it is
 * plain serialisable data: numbers, strings, booleans, closed-enum members, and
 * arrays and objects of those.
 */
export type SyncPanelData = Omit<
  SyncPanelViewProps,
  'onSyncNow' | 'busy' | 'startError' | 'renderedAt' | 'locale'
>;

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
 * The order the rows are shown in, taken from the map above.
 *
 * LANE ORDER, deliberately: the three structural kinds, then the three that
 * carry text. The store returns whatever order its index walk produces, which
 * came out as Model calls, Prompts, Responses, Sessions, Tool calls, Tool
 * inputs — alphabetical by accident, and it interleaves two lanes that behave
 * differently and are gated differently. A reader comparing "sessions" to "tool
 * calls" is comparing like with like; comparing "prompts" to "sessions" is not.
 */
const KIND_ORDER: readonly string[] = Object.keys(KIND_LABELS);

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
 * What the panel says when the key read as usable and its MODE did not.
 *
 * The page reads the credential twice, and this is the answer when the two
 * reads disagree; panelState says why it is neither machine-wide counts nor an
 * empty scope.
 */
const MODE_UNREAD_DETAIL =
  'This page could not tell whether this machine is attached as a personal or an organization ' +
  'device, so it cannot say what is sent. Reload the page, and re-attach if this persists.';

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
 * ask, and it is load-bearing in three places. The two questions about the key
 * come first, in this order: does it authenticate, and can its mode be read. No
 * state about sharing is drawn for a machine whose key, or whose kind of
 * attachment, is unknown, because "not shared" read against that machine
 * describes a decision the user never made. Within the grant, stale comes
 * before absent, since only a stale grant can be resumed in place. And the
 * grant comes before any count: a machine with no history grant is `not-shared`
 * and shows NO bars, because the ledger counts a backlog nothing has been told
 * it may send. Bars there would promise delivery of rows that will sit for ever.
 *
 * ON A SCOPED ATTACHMENT THE BARS COUNT WHAT ITS SCOPE COVERS, and nothing else.
 * The scope is resolved from the credential's mode, the scope record in the
 * settings in force and the connection's endpoint: the inputs the history drain
 * resolves its own filter from, through the same two functions, so the bars and
 * the drain filter by one list. Every bucket is filtered, sent rows included: a
 * repository that is unenrolled leaves the bars at the next render, and what it
 * already sent leaves with it. A machine-wide attachment resolves to no filter
 * and runs the read it always ran.
 */
export function readSyncPanel(
  settings: WorkspaceSettings,
  credentialState: CredentialState,
  /**
   * The instant to judge the claim and the breaker against — the route's own,
   * so every time-derived answer on the page comes from ONE reading of the
   * clock. It is not returned: the panel takes `renderedAt` as its own prop,
   * the way every other consumer on every other route does.
   */
  at: number,
  /**
   * The mode of the credential held for `settings.controlPlane`, as the page
   * read it for the form, or undefined when that read found no usable
   * credential. Passed in rather than read here, so this module makes no
   * credential read of its own and the page reads the mode once.
   */
  attachmentMode: AttachmentMode | undefined,
): SyncPanelData | null {
  const connection = settings.controlPlane;
  if (!isAttached(settings) || connection === undefined) return null;

  const ledger = db().historySync;
  const dir = dataDir();
  const progress = readHistorySyncState(dir);
  const base = {
    deployment: connection.label ?? connection.endpoint,
    running: isHistorySyncLeaseLive(ledger.lease(), at),
    // The breaker, which is the answer to "I pressed the button and nothing
    // happened". A pass started while it is open declines before it opens the
    // store, and the child is detached, so that decision reaches no surface at
    // all unless this page reads the same file the pass would.
    paused: isForwardPaused(readForwardHealth(dir, at), at),
    localOnly: LOCAL_ONLY,
    // A personal device sends activity only from its enrolled repositories, and
    // the not-shared line says what is sent from now on. Present only on one,
    // so a machine-wide attachment's props are what they were.
    ...(attachmentMode === 'scoped' ? { scoped: true } : {}),
    ...(progress === null
      ? {}
      : {
          lastOutcome: progress.lastOutcome,
          lastPassAt: new Date(progress.lastPassAtMs).toISOString(),
        }),
  };

  return {
    ...base,
    state: panelState(settings, credentialState, attachmentMode, connection.endpoint, ledger),
  };
}

function panelState(
  settings: WorkspaceSettings,
  credentialState: CredentialState,
  attachmentMode: AttachmentMode | undefined,
  endpoint: string,
  ledger: ReturnType<typeof db>['historySync'],
): SyncPanelState {
  // BEFORE the consent branches. A machine whose key will not authenticate
  // sends nothing whatever it was granted, and "not shared" read against that
  // machine describes a decision the user never made.
  if (!credentialState.usable) {
    return { status: 'credential-unusable', detail: credentialDetail(credentialState) };
  }
  // A usable key whose MODE did not read. The page reads the credential twice,
  // once for the state above and once for the mode, and the two can disagree:
  // the file can be replaced or removed between the reads, and the mode read
  // answers undefined for any failure. Counted machine-wide, the bars would say
  // a personal device owes its whole store; counted under an empty scope, that
  // it owes nothing. Neither is known, so the panel says so, and the next render
  // reads both again. Asked before the consent branches, so no later state is
  // drawn for a machine whose kind of attachment is unknown.
  if (attachmentMode === undefined) {
    return { status: 'credential-unusable', detail: MODE_UNREAD_DETAIL };
  }
  // Stale before absent: both fail isHistorySyncConsentValid, and only one of
  // them is a grant the user can resume in place.
  if (isHistorySyncConsentStale(settings.historySyncConsent, endpoint)) {
    return { status: 'consent-stale' };
  }
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return { status: 'not-shared' };
  }

  // The drain's filter, resolved the way the drain resolves it, on every render
  // and never kept: an enroll or an unenroll shows at the next one. Undefined on
  // a machine-wide attachment, which runs the ledger's machine read; on a scoped
  // one the enrolled keys, possibly none, and an empty list counts nothing.
  const scopeKeys = scopeFilterOf(
    resolveScope({ mode: attachmentMode, scope: settings.attachmentScope, endpoint }),
  );
  const kinds = ledger
    .partitionByKind(scopeKeys)
    .map(toRow)
    .filter(isRow)
    .sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
  if (kinds.length > 0) return { status: 'ready', kinds };
  // Nothing counted means nothing recorded only when nothing was filtered out. A
  // scoped attachment's store can be full of activity its scope does not cover,
  // so it gets its own state, carrying how many identities the scope enrolls.
  return scopeKeys === undefined
    ? { status: 'nothing-recorded' }
    : { status: 'nothing-in-scope', enrolled: scopeKeys.length };
}

function isRow(row: SyncKindRow | null): row is SyncKindRow {
  return row !== null;
}
