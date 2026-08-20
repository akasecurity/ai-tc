'use server';

import { applyOnboarding, ManagedFieldError } from '@akasecurity/persistence';
import {
  AttachInput,
  HistoricalAccess,
  isVaultConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  parseActionInput,
  SaveSettingsInput,
  VAULT_CONSENT_VERSION,
  VaultInlineReveal,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { malformedInput, managedRefusal, SETTINGS_WRITE_ERROR } from '../../lib/action-refusals';

// The web twin of the `/aka:setup` wizard's editable knobs, writing the same
// ~/.aka/settings/settings.json through the same shared writer (atomic
// tmp+rename, schema-validated merge, held under the settings file lock).
//
// historicalAccess gates the /aka:setup history sweep and backfill — NOT every
// hook; no hook entrypoint reads it. Enforcement handling (Monitor / Warn /
// Redact / Redact & Vault / Block) is not here at all: it is assigned per
// detection on the Detections page, which is the only axis that can express it.

export interface SaveSettingsResult {
  ok: boolean;
  error?: string;
}

// Every mutating entry point below parses its WHOLE input before reading a
// field. These arrive as untrusted JSON over an HTTP POST, so a caller can post
// a number, a null, or an object whose `toString` throws — and reading a field
// off a non-object throws, which REJECTS the Server Action and replaces the page
// with a framework error instead of returning the recoverable result these
// were written to give.
//
// The refusal wording lives in ../../lib/action-refusals.ts: every export of a
// 'use server' module must be an async Server Action, so a formatter defined
// here would be testable only by driving the whole write it describes.

// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function saveSettings(input: unknown): Promise<SaveSettingsResult> {
  const parsed = parseActionInput(SaveSettingsInput, input);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const { data } = parsed;

  const historicalAccess = HistoricalAccess.safeParse(data.historicalAccess);
  const inlineReveal = VaultInlineReveal.safeParse(data.vaultInlineReveal);
  const vaultChoice = data.vaultConsent;
  if (
    !historicalAccess.success ||
    !inlineReveal.success ||
    (vaultChoice !== 'on' && vaultChoice !== 'off')
  ) {
    return { ok: false, error: 'Invalid settings value.' };
  }
  try {
    // Derived inside applyOnboarding's write lock, not before it: `current` is
    // read back on the far side of the merge that is about to happen, so a
    // grant this page keeps is one that is still on file. Reading it out here
    // instead would carry a stale grant across a concurrent revoke — from the
    // wizard, or from a second tab — and write it back, silently reinstating
    // consent the user had just withdrawn.
    applyOnboarding((current) => ({
      historicalAccess: historicalAccess.data,
      // Grant records fresh consent at the current payload version; revoke
      // clears it (undefined ⇒ dropped by the schema on the merged write).
      // REQUIRED on the input, so an omitted field can no longer read as a
      // revocation of a live egress grant.
      modelJudgeConsent: data.modelJudgeConsent
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
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  revalidatePath('/settings');
  return { ok: true };
}

/**
 * Register this machine against an organization's deployment.
 *
 * THIS WRITES STATE AND DIALS NOTHING. The open-source build carries no
 * control-plane transport — it makes no network calls at all — so what this
 * records is the machine's intent and the descriptor a transport would need.
 * A build with a transport plugged in reads the same settings; one without runs
 * standalone regardless, which is why the mode alone never counts as attached
 * (see isAttached).
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function attachToControlPlane(input: unknown): Promise<SaveSettingsResult> {
  const parsed = parseActionInput(AttachInput, input);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const endpoint = parsed.data.endpoint.trim();
  // Checked after the parse, not instead of it: the parse guarantees a string
  // to call .trim() on, and this guarantees the string says something. An empty
  // endpoint would write a descriptor that isAttached accepts and no transport
  // could ever use.
  if (endpoint === '') return { ok: false, error: 'Enter the deployment endpoint to attach.' };
  const label = parsed.data.label?.trim();
  try {
    applyOnboarding({
      runMode: 'attached',
      controlPlane: {
        endpoint,
        ...(label === undefined || label === '' ? {} : { label }),
        // Stamped server-side like every other timestamp on this page.
        attachedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  revalidatePath('/settings');
  return { ok: true };
}

/**
 * Return this machine to standalone.
 *
 * Clears the descriptor as well as the mode. Leaving a stale descriptor behind
 * would let a later hand edit of `runMode` alone silently re-attach to a
 * deployment the user thought they had left.
 *
 * Refused when an administrator has locked the connection — that refusal comes
 * from applyOnboarding, which decides it inside the write lock against the
 * managed file, so a user cannot win a race against it.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function detachFromControlPlane(): Promise<SaveSettingsResult> {
  try {
    applyOnboarding({ runMode: 'standalone', controlPlane: undefined });
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  revalidatePath('/settings');
  return { ok: true };
}
