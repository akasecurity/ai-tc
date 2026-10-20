// Reports the human labels this machine holds — the exceptions a person granted
// and the findings they dismissed, each with the reason they picked — to the
// deployment it is attached to. Runs in the detached sync child, never on a
// hook path.
import type { LocalDatabase } from '@akasecurity/persistence';
import {
  dataDir,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import { createRemoteClient, RemoteRouteAbsent } from '@akasecurity/remote';
import type { DetectionException, ReportedDismissal, ReportedGrant } from '@akasecurity/schema';
import {
  attachmentModeOf,
  isAttached,
  isHistorySyncConsentValid,
  LABEL_REPORT_BATCH_MAX,
  ReportedDismissal as ReportedDismissalSchema,
  ReportedGrant as ReportedGrantSchema,
} from '@akasecurity/schema';

import { recordUnsendableLabels } from './label-drops.ts';
import { withTimeout } from './with-timeout.ts';

export const LABEL_REQUEST_TIMEOUT_MS = 30_000;

/**
 * `reported`      a batch was sent, taken and marked reported.
 * `nothing`       every label is already reported in its current form.
 * `no-consent`    the history grant is missing, stale or for another endpoint.
 * `scoped`        a scoped attachment, which does not send labels.
 * `route-absent`  the deployment predates the route; nothing is marked.
 * `failed`        the read or the send failed; nothing is marked.
 */
export type LabelSyncOutcome =
  'reported' | 'nothing' | 'no-consent' | 'scoped' | 'route-absent' | 'failed';

export interface RunLabelSyncDeps {
  /** The ~/.aka root. */
  base: string;
  settingsDir: string;
  now?: (() => number) | undefined;
}

/**
 * The label a grant carries on the wire, field by field — never a spread of
 * the row, so the justification, the revoke reason, the local account name
 * and the keyed fingerprint cannot ride along. Null when the row does not fit
 * the wire contract, which drops that one grant rather than the batch.
 */
function toReportedGrant(g: DetectionException): ReportedGrant | null {
  const parsed = ReportedGrantSchema.safeParse({
    id: g.id,
    ruleId: g.ruleId,
    category: g.category,
    keyVersion: g.keyVersion,
    maskedValue: g.maskedValue,
    capability: g.capability,
    scope: g.scope,
    expiresAt: g.expiresAt,
    maxUses: g.maxUses,
    useCount: g.useCount,
    lastUsedAt: g.lastUsedAt,
    method: g.method,
    confirmedBy: g.confirmedBy,
    createdVia: g.createdVia,
    createdAt: g.createdAt,
    updatedAt: g.updatedAt,
    revokedAt: g.revokedAt,
  });
  return parsed.success ? parsed.data : null;
}

interface Batch {
  grants: ReportedGrant[];
  dismissals: ReportedDismissal[];
  /** Rows the wire contract refuses: stamped reported and counted, never sent. */
  unsendableGrantIds: string[];
  unsendableDismissalIds: string[];
}

async function readBatch(db: LocalDatabase): Promise<Batch> {
  const batch: Batch = {
    grants: [],
    dismissals: [],
    unsendableGrantIds: [],
    unsendableDismissalIds: [],
  };
  for (const g of await db.exceptions.unreportedLabels(LABEL_REPORT_BATCH_MAX)) {
    const wire = toReportedGrant(g);
    if (wire === null) batch.unsendableGrantIds.push(g.id);
    else batch.grants.push(wire);
  }
  for (const d of db.resolutions.unreportedDismissals(LABEL_REPORT_BATCH_MAX)) {
    const parsed = ReportedDismissalSchema.safeParse(d);
    if (parsed.success) batch.dismissals.push(parsed.data);
    else batch.unsendableDismissalIds.push(d.id);
  }
  return batch;
}

/**
 * Send one batch of unreported labels, and mark what the deployment took.
 *
 * Returns null, and calls nothing, unless the machine is attached. Sends only
 * under a current history grant for this endpoint (payload v4 names labels),
 * and only from a machine-wide attachment: a scoped one forwards what its
 * enrolled projects record, and a grant or a dismissal belongs to none.
 *
 * At most one batch per run, so a long backlog drains over later sessions
 * rather than holding the sync child. Never throws.
 */
export async function runLabelSync(deps: RunLabelSyncDeps): Promise<LabelSyncOutcome | null> {
  let db: LocalDatabase | undefined;
  try {
    const settings = readWorkspaceSettings(deps.base);
    const connection = isAttached(settings) ? settings.controlPlane : undefined;
    if (connection === undefined) return null;
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);
    if (!state.usable) return null;
    if (!isHistorySyncConsentValid(settings.historySyncConsent, connection.endpoint)) {
      return 'no-consent';
    }
    if (attachmentModeOf(state.credential) !== 'machine') return 'scoped';

    // Taken BEFORE the read, so a grant changed after it keeps an updated_at
    // past the stamp and is offered again.
    const startedAt = (deps.now ?? Date.now)();
    db = openLocalDatabase(dataDir(deps.base));
    const batch = await readBatch(db);
    // Before the send, and whatever becomes of it: a row that cannot be sent
    // now cannot be sent later either, and left unstamped it would hold the
    // head of the queue on every run.
    const unsendable = batch.unsendableGrantIds.length + batch.unsendableDismissalIds.length;
    if (unsendable > 0) {
      await db.exceptions.markLabelsReported(batch.unsendableGrantIds, startedAt);
      db.resolutions.markDismissalsReported(batch.unsendableDismissalIds, startedAt);
      recordUnsendableLabels(dataDir(deps.base), unsendable, startedAt);
    }
    if (batch.grants.length === 0 && batch.dismissals.length === 0) return 'nothing';

    const { apiKey } = state.credential;
    const client = createRemoteClient({
      endpoint: connection.endpoint,
      apiKey,
      timeoutMs: LABEL_REQUEST_TIMEOUT_MS,
    });
    await withTimeout(
      client.reportLabels({ grants: batch.grants, dismissals: batch.dismissals }),
      LABEL_REQUEST_TIMEOUT_MS,
    );

    await db.exceptions.markLabelsReported(
      batch.grants.map((g) => g.id),
      startedAt,
    );
    db.resolutions.markDismissalsReported(
      batch.dismissals.map((d) => d.id),
      startedAt,
    );
    return 'reported';
  } catch (err) {
    return err instanceof RemoteRouteAbsent ? 'route-absent' : 'failed';
  } finally {
    try {
      db?.close();
    } catch {
      // A close that fails leaves nothing to undo.
    }
  }
}
