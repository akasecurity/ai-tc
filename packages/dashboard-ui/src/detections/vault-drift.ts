// The one-time notice for a machine that used to vault and now does not.
//
// Moving custody into the policy framework changed what an existing install
// does, silently and in the one direction that cannot be undone. Before, a valid
// vault consent made EVERY redaction on the machine reversible; now nothing is
// reversible until a detection is assigned Redact & Vault. So a user who granted
// consent, saw "Allow vaulting" on Settings and has been relying on recoverable
// redaction starts getting one-way destruction — and unlike every other setting
// on that page, putting it back does not bring the values back. They are gone.
//
// Nothing migrates the old behaviour forward, deliberately: assigning an
// archetype to packs on the user's behalf would be this feature making an
// enforcement decision nobody asked it to make. Telling them is the honest
// alternative to guessing.

/** What the store says about this machine's vaulting, as the notice needs it. */
export interface VaultDriftState {
  // A vault-consent grant that is present AND still valid at the current consent
  // version. Validity, not presence: a stale grant authorizes nothing, so a
  // machine holding one is not vaulting today either way and has nothing to be
  // told it lost.
  consentValid: boolean;
  // How many entries the local vault already holds.
  vaultEntries: number;
  // How many installed packs are assigned the reversible archetype.
  vaultAssignedPacks: number;
}

export const VAULT_DRIFT_TITLE = 'Nothing is being vaulted on this machine';

export const VAULT_DRIFT_BODY =
  'Reversible redaction is now assigned per detection rather than by the vault consent alone. ' +
  'This machine has the consent granted and entries already in its vault, but no detection is ' +
  'set to Redact & Vault — so detected values are being redacted one-way, and what is removed ' +
  'from here on cannot be recovered. Set the detections you want kept to Redact & Vault below. ' +
  'Entries already in the vault are unaffected.';

/**
 * Whether to show it.
 *
 * All three conditions matter, and the middle one is what keeps this from being
 * noise. `vaultEntries > 0` is the evidence that this machine ACTUALLY vaulted
 * under the old behaviour — a fresh install that granted consent during setup
 * and has never vaulted anything has lost nothing, and telling it otherwise
 * would train users to dismiss the notice.
 *
 * It clears itself: assigning the archetype to any detection makes it false,
 * with no dismissal state to store and nothing to re-show if the user changes
 * their mind later.
 */
export function showsVaultDrift(state: VaultDriftState): boolean {
  return state.consentValid && state.vaultEntries > 0 && state.vaultAssignedPacks === 0;
}
