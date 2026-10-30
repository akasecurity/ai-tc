/**
 * The files an attachment LEAVES BEHIND, and the one way to clear them.
 *
 * Ten of these are written by the attached runtime rather than by the attach
 * itself — a cached policy bundle, the capture settings taken from it, the sync
 * outcome, the forward breaker's state,
 * its drop tally, the posture self-report's last outcome, the history drain's
 * progress, the tally of labels too large to report, and the config inventory
 * reports staged for the sync child with what it last delivered of them. The
 * eleventh, the record of who attached the machine, is
 * written by the attach and kept current by the sync child and by the hooks that
 * validate a work account, all through attached-identity.ts in this package.
 * None of them is the attachment; all of them describe one. Each session's
 * account state, a directory beside them (session-accounts.ts), is cleared with
 * them.
 *
 * They live HERE rather than beside the code that writes them because clearing
 * them is a detach concern, and there are two detach surfaces: `aka detach` and
 * the dashboard's settings action. The attached runtime
 * (@akasecurity/plugin-runtime) writes most of them and sits ABOVE both callers
 * in the graph — the dashboard cannot import it — so a shared list has to sit
 * below, which is this package.
 *
 * WHY A DETACH THAT STOPS AT THE CREDENTIAL IS NOT A DETACH. Two of these go on
 * acting after the attachment is gone:
 *
 *   the cached policy bundle merges over the local one RAISE-ONLY, so one left
 *   behind keeps escalating enforcement on a machine nothing manages any more —
 *   and nothing would ever refresh or clear it, because the sync that wrote it
 *   runs only while attached.
 *
 *   the forward breaker's `openedAtMs` survives, so a machine that detaches and
 *   later re-attaches takes the breaker's early return and forwards NOTHING
 *   until a cooldown elapses that was opened against a deployment it no longer
 *   talks to. The drop tally beside it reports events lost to that same
 *   deployment, under the new one's name.
 */
import { rmSync } from 'node:fs';
import { join } from 'node:path';

import { clearSessionAccountState } from './session-accounts.ts';

/** The policy bundle the sync child caches. */
export const POLICY_CACHE_FILENAME = 'policy-cache.json';

/** The capture settings of the cached bundle, small enough for every hook to read. */
export const ATTACHED_CAPTURE_SETTINGS_FILENAME = 'attached-capture.json';

/** The last sync outcome `aka status` reports. */
export const ATTACHED_SYNC_STATE_FILENAME = 'attached-sync-state.json';

/** The forward breaker's open/closed state. */
export const ATTACHED_FORWARD_STATE_FILENAME = 'attached-state.json';

/** The tally of events the breaker dropped. */
export const ATTACHED_FORWARD_DROPS_FILENAME = 'attached-forward-drops.json';

/** What the last posture self-report send did, as `aka status` renders it. */
export const ATTACHED_POSTURE_REPORT_FILENAME = 'attached-posture-report.json';

/** How far the background drain of already-recorded activity has got. */
export const ATTACHED_HISTORY_SYNC_STATE_FILENAME = 'attached-history-sync.json';

/** How many labels were too large to report (label-drops.ts in plugin-runtime). */
export const ATTACHED_LABEL_SYNC_FILENAME = 'attached-label-sync.json';

/** Who attached this machine, as digests beside its credential (attached-identity.ts). */
export const ATTACHED_IDENTITY_FILENAME = 'attached-identity.json';

/** The config inventory reports session starts staged for the sync child to send. */
export const ATTACHED_CONFIG_INVENTORY_FILENAME = 'attached-config-inventory.json';

/** What the sync child last delivered of each staged config inventory report. */
export const ATTACHED_CONFIG_INVENTORY_STATE_FILENAME = 'attached-config-inventory-state.json';

/**
 * Every file above, so a caller iterates the list rather than restating it.
 *
 * A derived file added to the runtime joins both detach paths by being added
 * here, which is the whole point of the list existing.
 */
export const ATTACHED_DERIVED_FILENAMES: readonly string[] = [
  POLICY_CACHE_FILENAME,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  ATTACHED_SYNC_STATE_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_POSTURE_REPORT_FILENAME,
  ATTACHED_HISTORY_SYNC_STATE_FILENAME,
  ATTACHED_LABEL_SYNC_FILENAME,
  ATTACHED_IDENTITY_FILENAME,
  ATTACHED_CONFIG_INVENTORY_FILENAME,
  ATTACHED_CONFIG_INVENTORY_STATE_FILENAME,
];

/**
 * Remove everything an attachment left behind, in the DATA dir: every file on
 * the list, and each session's account state, a directory the per-file removal
 * cannot take (clearSessionAccountState).
 *
 * `force: true` on each, so a file that was never written is not an error — a
 * machine that attached and never synced has none of these, and that is the
 * ordinary case rather than a fault.
 *
 * Best-effort by design: a detach whose descriptor and credential are already
 * gone has succeeded at the part that decides whether the machine is attached,
 * and failing it over a leftover cache would report a detach that did happen as
 * one that did not.
 */
export function clearAttachmentDerivedState(dataDir: string): void {
  for (const name of ATTACHED_DERIVED_FILENAMES) {
    try {
      rmSync(join(dataDir, name), { force: true });
    } catch {
      // See above: a leftover is not worth failing a completed detach over.
    }
  }
  clearSessionAccountState(dataDir);
}
