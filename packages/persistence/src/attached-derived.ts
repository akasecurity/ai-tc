/**
 * The files an attachment LEAVES BEHIND, and the one way to clear them.
 *
 * These four are written by the attached runtime rather than by the attach
 * itself — a cached policy bundle, the sync outcome, the forward breaker's state
 * and its drop tally. None of them is the attachment; all of them describe one.
 *
 * They live HERE rather than beside the code that writes them because clearing
 * them is a detach concern, and there are two detach surfaces: `aka detach` and
 * the dashboard's settings action. @akasecurity/plugin-runtime owns the writers
 * and re-exports these names, but it sits ABOVE both callers in the graph — the
 * dashboard cannot import it — so a shared list has to sit below, which is this
 * package.
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

/** The policy bundle the sync child caches. */
export const POLICY_CACHE_FILENAME = 'policy-cache.json';

/** The last sync outcome `aka status` reports. */
export const ATTACHED_SYNC_STATE_FILENAME = 'attached-sync-state.json';

/** The forward breaker's open/closed state. */
export const ATTACHED_FORWARD_STATE_FILENAME = 'attached-state.json';

/** The tally of events the breaker dropped. */
export const ATTACHED_FORWARD_DROPS_FILENAME = 'attached-forward-drops.json';

/**
 * Every file above, so a caller iterates the list rather than restating it.
 *
 * A fifth derived file added to the runtime joins both detach paths by being
 * added here, which is the whole point of the list existing.
 */
export const ATTACHED_DERIVED_FILENAMES: readonly string[] = [
  POLICY_CACHE_FILENAME,
  ATTACHED_SYNC_STATE_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  ATTACHED_FORWARD_DROPS_FILENAME,
];

/**
 * Remove everything an attachment left behind, in the DATA dir.
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
}
