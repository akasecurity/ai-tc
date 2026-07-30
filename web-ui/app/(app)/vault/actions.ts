'use server';

import {
  createKeyProvider,
  dataDir,
  keysDir,
  loadOrCreateFingerprintKey,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type { PointerDescriptor } from '@akasecurity/schema';
import { isVaultConsentValid, PointerToken } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// The web vault surface — the browser twin of `aka vault show` and the manage
// verbs. A raw value exists in-process only for the duration of one request:
// de-referenced from the vault, returned to the caller, never logged and never
// persisted anywhere but the audit trail the vault itself writes.

// The same construction the CLI performs: the vault over the local store, the
// key custody the settings name, and consent read live so a revocation applies
// to the very next call.
function buildVault(): SecretVault {
  return new SecretVault({
    repo: db().secretVault,
    keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
    fingerprintKey: loadOrCreateFingerprintKey(dataDir()),
    isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
  });
}

export type RevealResult =
  | { ok: true; value: string | null; descriptor: PointerDescriptor | null }
  | { ok: false; error: string };

/**
 * Resolve one pointer for the human at the dashboard. `value: null` with
 * `ok: true` means the vault could not resolve it — a forged/tampered token, a
 * purged entry, or unavailable key material, which the vault deliberately does
 * not distinguish.
 */
export async function revealPointer(input: { pointer: string }): Promise<RevealResult> {
  // Reject anything that is not pointer-shaped before it reaches the vault.
  const parsed = PointerToken.safeParse(input.pointer.trim());
  if (!parsed.success) {
    return { ok: false, error: 'Not a vault pointer — paste the full [[aka:...]] token.' };
  }

  try {
    const vault = buildVault();
    const value = await vault.detokenize(parsed.data, {
      target: 'human',
      reason: 'explicit-reveal',
    });
    const descriptor = await vault.describePointer(parsed.data);
    return { ok: true, value: typeof value === 'string' ? value : null, descriptor };
  } catch {
    // Corrupt key file or unreadable store — same outward shape as an
    // unresolvable pointer; the error never carries store internals.
    return { ok: true, value: null, descriptor: null };
  }
}

export type EntryRevealResult = { ok: true; value: string | null } | { ok: false; error: string };

/**
 * Owner-surface reveal of one inventory row by its pointer id — the button on
 * the vault register, audited exactly like a pasted-pointer reveal (target
 * 'human', reason 'explicit-reveal'). `value: null` means unresolvable: a
 * purged entry or unavailable key material.
 */
export async function revealEntry(input: { pointerId: string }): Promise<EntryRevealResult> {
  try {
    const value = await buildVault().revealEntry(input.pointerId, {
      reason: 'explicit-reveal',
    });
    revalidatePath('/vault');
    return { ok: true, value: typeof value === 'string' ? value : null };
  } catch {
    return { ok: false, error: 'The vault could not be read.' };
  }
}

export type VaultActionResult = { ok: true } | { ok: false; error: string };

/** Revoke the active reveal-to-model grant covering a vaulted value — terminal, audit-retained. */
export async function revokeRevealGrant(input: { grantId: string }): Promise<VaultActionResult> {
  try {
    const revoked = await db().exceptions.revoke(input.grantId, 'dashboard');
    if (!revoked) return { ok: false, error: 'No active grant with that id.' };
    revalidatePath('/vault');
    return { ok: true };
  } catch {
    return { ok: false, error: 'The grant could not be revoked.' };
  }
}

export type PurgeVaultResult = { ok: true; destroyed: number } | { ok: false; error: string };

/**
 * Destroy every vaulted value. Irreversible: every pointer everywhere becomes
 * permanently unresolvable; the de-reference audit trail survives. Guarded by
 * a typed confirmation — anything but the literal word is rejected before the
 * store is touched.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function purgeVault(input: { confirmation: string }): Promise<PurgeVaultResult> {
  if (input.confirmation !== 'purge') {
    return { ok: false, error: "Type 'purge' to confirm — nothing was destroyed." };
  }
  try {
    const destroyed = buildVault().purgeVault();
    revalidatePath('/vault');
    return { ok: true, destroyed };
  } catch {
    return { ok: false, error: 'The vault could not be purged.' };
  }
}

export type RotateVaultKeyResult =
  { ok: true; version: number; reEncrypted: number } | { ok: false; error: string };

/**
 * Mint the next vault key epoch and re-encrypt every entry under it. Existing
 * pointers keep working — their tags verify against the historical epoch they
 * name, which the key provider retains.
 */
export async function rotateVaultKey(): Promise<RotateVaultKeyResult> {
  try {
    const { version, reEncrypted } = await buildVault().rotateVaultKey();
    revalidatePath('/vault');
    return { ok: true, version, reEncrypted };
  } catch {
    return { ok: false, error: 'The vault key could not be rotated.' };
  }
}
