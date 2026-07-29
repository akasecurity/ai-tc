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

import { db } from '../../lib/db';

// The web reveal surface — the browser twin of `aka vault show`. The raw value
// exists in-process only for the duration of one request: de-referenced from
// the vault, returned to the caller, never logged and never persisted anywhere
// but the audit trail the vault itself writes (reason: explicit-reveal).

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
    const vault = new SecretVault({
      repo: db().secretVault,
      keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
      fingerprintKey: loadOrCreateFingerprintKey(dataDir()),
      // Read live so a consent revocation applies to the very next call.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
    });
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
