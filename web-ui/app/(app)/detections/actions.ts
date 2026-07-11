'use server';

import { BuiltinPolicyId, splitDetectionId } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// Per-detection enforcement-policy assignment and enable/disable, persisted to
// the local store. Server Actions call the persistence write facade (off the
// shared read ports) and revalidate the page so the Server Component re-reads
// and the UI reflects the change.
//
// The local-store writes + revalidatePath are synchronous, but Next.js requires
// every 'use server' export to be async — hence the require-await disables below.

/** Assign one of the built-in enforcement policies to a detection. */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setDetectionPolicy(id: string, policyId: string): Promise<void> {
  const parts = splitDetectionId(id);
  if (!parts) return;
  // Defensive: the picker only emits built-in ids, but setPolicy THROWS on an
  // unknown one and the caller can't observe a rejected Server Action — validate
  // here and no-op on anything unexpected instead of crashing the action.
  if (!BuiltinPolicyId.safeParse(policyId).success) return;
  db().installedPacks.setPolicy(parts.namespace, parts.packId, policyId);
  revalidatePath('/detections');
}

/** Enable or disable a detection. */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setDetectionEnabled(id: string, enabled: boolean): Promise<void> {
  const parts = splitDetectionId(id);
  if (!parts) return;
  db().installedPacks.setEnabled(parts.namespace, parts.packId, enabled);
  revalidatePath('/detections');
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
