'use server';

import { TrustLevel } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// Inventory write path, persisted to the local store and revalidated so the
// Server Component re-reads and the UI reflects the change. A sync write, but
// Next.js requires 'use server' exports to be async — hence the disable below.

/**
 * Set (or clear-on-default) the MCP trust classification for an asset. Returns
 * whether it applied (false when the asset is missing or isn't an MCP server).
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setMcpTrust(assetId: string, trust: TrustLevel): Promise<boolean> {
  if (!TrustLevel.safeParse(trust).success) return false;
  const result = db().inventoryAssets.setMcpTrust(assetId, trust);
  revalidatePath('/inventory');
  return result === 'ok';
}
