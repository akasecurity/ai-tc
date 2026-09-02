'use server';

import { BuiltinPolicyId, splitDetectionId } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';
import {
  asPolicyFloorRefusal,
  DETECTION_ID_INVALID,
  DETECTION_MISSING,
  DETECTION_POLICY_INVALID,
  DETECTION_STAYS_ON_REFUSAL,
  DETECTION_WRITE_ERROR,
  isControlPlaneRefusal,
  policyFloorRefusal,
} from '../../lib/detection-refusals';

// Per-detection enforcement-policy assignment and enable/disable, persisted to
// the local store. Server Actions call the persistence write facade (off the
// shared read ports) and revalidate the page so the Server Component re-reads
// and the UI reflects the change.
//
// The local-store writes + revalidatePath are synchronous, but Next.js requires
// every 'use server' export to be async — hence the require-await disables below.

/**
 * The outcome of a per-detection write, in terms the client can render.
 *
 * These RETURN a refusal rather than throwing one, for the reason every
 * mutating action on this dashboard does: a rejected Server Action escalates to
 * the route error boundary and replaces the whole page. But they also no longer
 * return NOTHING, which is what they used to do — a write refused by the control
 * plane left the control showing the choice the user made, the store holding a
 * different one, and enforcement applying a third. A refusal nobody can see is
 * indistinguishable from a control that ignores you.
 *
 * One shape for both writes: they answer the same questions (did it land, and
 * if not, what does the user read), and a second shape saying the same thing is
 * how two controls on one page start reporting the same refusal differently.
 */
export interface DetectionWriteResult {
  ok: boolean;
  error?: string;
}

/**
 * Assign one of the built-in enforcement policies to a detection.
 *
 * On an ATTACHED machine the store refuses an assignment below what the
 * organization's policy requires, and refuses any re-assignment at all for a
 * detection the organization has written a policy for. Those refusals are
 * recognised structurally (see asPolicyFloorRefusal) and reported as the
 * organization's decision — never as a failure, because retrying cannot help
 * and the user has done nothing wrong.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setDetectionPolicy(
  id: string,
  policyId: string,
): Promise<DetectionWriteResult> {
  const parts = splitDetectionId(id);
  // Both malformed inputs answer with the same sentence: only a stale or
  // hand-made client sends either, the remedy for both is a reload, and neither
  // message may quote what was sent.
  if (!parts) return { ok: false, error: DETECTION_POLICY_INVALID };
  // The picker only emits built-in ids, but setPolicy throws a plain Error on an
  // unknown one — validate first so that branch stays a crash-shaped fault
  // rather than a routine input answer.
  if (!BuiltinPolicyId.safeParse(policyId).success) {
    return { ok: false, error: DETECTION_POLICY_INVALID };
  }
  let written: boolean;
  try {
    written = db().installedPacks.setPolicy(parts.namespace, parts.packId, policyId);
  } catch (error) {
    const refused = asPolicyFloorRefusal(error);
    if (refused !== null) return { ok: false, error: policyFloorRefusal(refused) };
    return { ok: false, error: DETECTION_WRITE_ERROR };
  }
  revalidatePath('/detections');
  // No row changed: the pack this page rendered is not installed any more. Said
  // plainly, because the revalidated page below is about to stop showing it and
  // an unexplained disappearance reads as the write having broken something.
  return written ? { ok: true } : { ok: false, error: DETECTION_MISSING };
}

/**
 * Enable or disable a detection.
 *
 * On an ATTACHED machine the store refuses to switch OFF a detection the
 * organization's bundle names at all — a detection that does not run supplies
 * no rules and no actions, which is below every archetype the organization
 * could have asked for, so the floor it set would be unreachable rather than
 * merely lowered. Re-enabling is never refused.
 *
 * That refusal is recognised structurally (see isControlPlaneRefusal) and
 * reported as the organization's decision, never as a failure: retrying cannot
 * help and the user has done nothing wrong. It goes through the same result
 * shape the assignment does, so a toggle that is somehow clicked anyway — a
 * stale page, a second tab, a sync that landed between render and click — says
 * why instead of snapping back in silence.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setDetectionEnabled(
  id: string,
  enabled: boolean,
): Promise<DetectionWriteResult> {
  const parts = splitDetectionId(id);
  // Only a stale or hand-made client sends this; the remedy is a reload, and
  // the message may not quote what was sent.
  if (!parts) return { ok: false, error: DETECTION_ID_INVALID };
  let written: boolean;
  try {
    written = db().installedPacks.setEnabled(parts.namespace, parts.packId, enabled);
  } catch (error) {
    if (isControlPlaneRefusal(error)) return { ok: false, error: DETECTION_STAYS_ON_REFUSAL };
    return { ok: false, error: DETECTION_WRITE_ERROR };
  }
  revalidatePath('/detections');
  // No row changed: the detection this page rendered is not installed any more.
  // Said plainly, because the revalidated page below is about to stop showing
  // it and an unexplained disappearance reads as the write having broken
  // something.
  return written ? { ok: true } : { ok: false, error: DETECTION_MISSING };
}

/**
 * Manually apply the available update for a detection: copies the latest
 * snapshot recorded by the plugin/CLI (available_packs) onto the installed
 * pack, preserving the user's enabled state and policy assignment. This is the
 * ONLY write path that moves an installed pack to a new version — the seeding
 * on gateway open / `aka init` never touches an existing row.
 *
 * Never throws: a rejected Server Action would escalate to the route error
 * boundary and replace the whole page. A failed/ineffective apply (locked
 * store, pack or mirror row missing) simply leaves the row unchanged — after
 * the revalidate the detection still shows its update badge, which is the
 * honest signal that nothing was applied.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function pullDetectionUpdate(id: string): Promise<void> {
  const parts = splitDetectionId(id);
  if (!parts) return;
  try {
    db().installedPacks.applyUpdate(parts.namespace, parts.packId);
  } catch {
    // Swallow: the revalidated page state is the outcome report.
  }
  revalidatePath('/detections');
}

/**
 * Re-read the update state ("Check again" on the unknown provenance state).
 * In OSS, "checking" means RE-READING THE STORE — nothing more: the web-ui
 * bundles no rules and may not import the plugin SDK (boundary), so it cannot
 * source an inventory itself. Inventories are recorded by the binaries that
 * ship rules: a plugin hook (any Claude Code session), `aka init`,
 * `aka detections`, or `aka dashboard` on launch. If one of those ran since
 * the page rendered, the revalidated read picks its recording up.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function recheckDetections(): Promise<void> {
  revalidatePath('/detections');
}
