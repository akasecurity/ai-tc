'use server';

import { applyOnboarding } from '@akasecurity/persistence';
import {
  HistoricalAccess,
  isVaultConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  SimpleDetectionPolicy,
  VAULT_CONSENT_VERSION,
  VaultInlineReveal,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

// The web twin of the `/aka:setup` wizard's editable knobs, writing the same
// ~/.aka/settings/settings.json through the same shared writer (atomic
// tmp+rename, schema-validated merge). historicalAccess is read live on each
// hook. The policy field is a stored default only — per-category policies (not
// this global toggle) govern runtime enforcement, so changing it does not alter
// what the plugin does when a detection fires.

export interface SaveSettingsResult {
  ok: boolean;
  error?: string;
}

// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function saveSettings(input: {
  policy: string;
  historicalAccess: string;
  // The distinct model-judge egress consent, as a bare answer: true grants,
  // false/absent revokes. Deliberately not the stored record — the
  // acknowledgement time and payload version are stamped below from server
  // state, so a client cannot backdate a grant or claim a version it never saw.
  modelJudgeConsent?: boolean;
  vaultConsent: string;
  vaultInlineReveal: string;
}): Promise<SaveSettingsResult> {
  const policy = SimpleDetectionPolicy.safeParse(input.policy);
  const historicalAccess = HistoricalAccess.safeParse(input.historicalAccess);
  const inlineReveal = VaultInlineReveal.safeParse(input.vaultInlineReveal);
  const vaultChoice = input.vaultConsent;
  if (
    !policy.success ||
    !historicalAccess.success ||
    !inlineReveal.success ||
    (vaultChoice !== 'on' && vaultChoice !== 'off')
  ) {
    return { ok: false, error: 'Invalid settings value.' };
  }
  // policy/historicalAccess are parsed above because their values are persisted
  // verbatim; modelJudgeConsent needs no equivalent parse because only its
  // truthiness survives — the record written below is built entirely here.
  try {
    // Derived inside applyOnboarding's write lock, not before it: `current` is
    // read back on the far side of the merge that is about to happen, so a
    // grant this page keeps is one that is still on file. Reading it out here
    // instead would carry a stale grant across a concurrent revoke — from the
    // wizard, or from a second tab — and write it back, silently reinstating
    // consent the user had just withdrawn.
    applyOnboarding((current) => ({
      policy: policy.data,
      historicalAccess: historicalAccess.data,
      // Grant records fresh consent at the current payload version; revoke
      // clears it (undefined ⇒ dropped by the schema on the merged write).
      modelJudgeConsent: input.modelJudgeConsent
        ? { acknowledgedAt: new Date().toISOString(), payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION }
        : undefined,
      // The vault grant is stamped HERE, never accepted from the client — the
      // input is only the choice string, so a caller-supplied acknowledgedAt or
      // version has no path in. 'on' records the current time at the current
      // consent version; if a still-valid grant is already on file it is kept
      // as-is so its acknowledgedAt survives unrelated edits. 'off' clears the
      // field entirely: future vaulting stops, but entries already stored remain
      // until the vault is purged.
      vaultConsent:
        vaultChoice === 'off'
          ? undefined
          : isVaultConsentValid(current.vaultConsent)
            ? current.vaultConsent
            : { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
      vaultInlineReveal: inlineReveal.data,
    }));
  } catch {
    return { ok: false, error: 'Could not write settings.json.' };
  }
  revalidatePath('/settings');
  return { ok: true };
}
