'use server';

import { AccessLevel, TrustLevel } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// Inventory write paths, persisted to the local store and revalidated so the
// Server Component re-reads and the UI reflects the change. Sync writes, but
// Next.js requires 'use server' exports to be async — hence the disables below.

/**
 * Set (or clear-on-default) the per-file LLM access override. Returns whether the
 * write landed (false when the file row is gone) so the client can surface a
 * failed write — this is a security-posture control, so a silent no-op is worst.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function setFileAccess(
  projectId: string,
  path: string,
  access: AccessLevel,
): Promise<boolean> {
  if (!AccessLevel.safeParse(access).success) return false;
  const ok = db().inventoryAssets.setFileAccess(projectId, path, access);
  revalidatePath('/inventory');
  return ok;
}

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
