'use server';

import { EgressDecision } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// Data Shares write paths, persisted to the local store and revalidated so the
// Server Component re-reads and the UI reflects the change. The local-store
// writes + revalidatePath are synchronous, but Next.js requires every 'use server'
// export to be async — hence the require-await disables below.

/**
 * Set (or clear, with null) the per-destination egress decision override. Returns
 * whether the write landed (false when the destination row is gone) so the client
 * can surface a failure instead of silently keeping the stale toggle — this is a
 * security-posture control, so a silent no-op is the worst mode.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setEgressDecision(
  destinationId: string,
  decision: EgressDecision | null,
): Promise<boolean> {
  // Defensive: the toggle only emits allow/block/null, but validate before writing
  // (setEgressDecision would otherwise store an arbitrary string as the decision).
  if (decision !== null && !EgressDecision.safeParse(decision).success) return false;
  const ok = db().shares.setEgressDecision(destinationId, decision);
  revalidatePath('/data-shares');
  return ok;
}
