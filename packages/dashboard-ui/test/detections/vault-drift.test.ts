import { describe, expect, it } from 'vitest';

import type { VaultDriftState } from '../../src/detections/vault-drift.ts';
import {
  showsVaultDrift,
  VAULT_DRIFT_BODY,
  VAULT_DRIFT_TITLE,
} from '../../src/detections/vault-drift.ts';

// The notice for a machine that used to vault and now does not. It exists
// because moving custody into the policy framework changed what an existing
// install DOES, silently, in the one direction that cannot be undone: a valid
// consent used to make every redaction reversible, and now nothing is until a
// detection is assigned the archetype.

const state = (over: Partial<VaultDriftState> = {}): VaultDriftState => ({
  consentValid: true,
  vaultEntries: 4,
  vaultAssignedPacks: 0,
  ...over,
});

describe('showsVaultDrift', () => {
  it('shows for a machine that vaulted before and now assigns the archetype nowhere', () => {
    // The case it exists for.
    expect(showsVaultDrift(state())).toBe(true);
  });

  it('stays silent once ANY detection is assigned the archetype', () => {
    // Self-clearing, which is why there is no dismissal state to store: the
    // user acting on the notice is what makes it stop.
    expect(showsVaultDrift(state({ vaultAssignedPacks: 1 }))).toBe(false);
  });

  it('stays silent on a fresh machine that granted consent but never vaulted', () => {
    // The condition that keeps this from being noise. Such a machine has lost
    // nothing — telling it otherwise trains users to dismiss the notice, and
    // then it is worth nothing to the machine that HAS lost something.
    expect(showsVaultDrift(state({ vaultEntries: 0 }))).toBe(false);
  });

  it('stays silent without a valid consent, even with entries already stored', () => {
    // A revoked or stale grant is not vaulting today either way, so there is no
    // change to report. Validity rather than presence: a grant recorded against
    // an older version authorizes nothing.
    expect(showsVaultDrift(state({ consentValid: false }))).toBe(false);
  });

  it('needs all three, not any two', () => {
    // Exhaustive over the eight combinations, so a future edit that collapses
    // the predicate to a cheaper one has to disagree with a case here.
    for (const consentValid of [true, false]) {
      for (const vaultEntries of [0, 4]) {
        for (const vaultAssignedPacks of [0, 1]) {
          const expected = consentValid && vaultEntries > 0 && vaultAssignedPacks === 0;
          expect(
            showsVaultDrift({ consentValid, vaultEntries, vaultAssignedPacks }),
            `${String(consentValid)}/${String(vaultEntries)}/${String(vaultAssignedPacks)}`,
          ).toBe(expected);
        }
      }
    }
  });
});

describe('the notice copy', () => {
  it('says what changed, what it costs, and what to do', () => {
    // A notice that only announced a change would leave the user unable to act,
    // and one that omitted the irreversibility would understate it.
    expect(VAULT_DRIFT_BODY).toMatch(/per detection/i);
    expect(VAULT_DRIFT_BODY).toMatch(/cannot be recovered/i);
    expect(VAULT_DRIFT_BODY).toMatch(/Redact & Vault/);
  });

  it('does not claim entries already stored are affected', () => {
    // They are not, and a user who read this as "the vault has been emptied"
    // would go looking for a restore that is not needed.
    expect(VAULT_DRIFT_BODY).toMatch(/already in the vault are unaffected/i);
  });

  it('names the machine rather than blaming the user', () => {
    expect(VAULT_DRIFT_TITLE).toMatch(/this machine/i);
  });
});
