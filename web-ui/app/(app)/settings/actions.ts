'use server';

import {
  applyOnboarding,
  isSafeEndpoint,
  ManagedFieldError,
  readControlPlaneCredentialState,
  removeControlPlaneCredential,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
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

import {
  ATTACH_ENDPOINT_INSECURE,
  ATTACH_KEY_MISSING,
  ATTACH_VERIFY_FAILED,
  malformedInput,
  managedRefusal,
  SETTINGS_WRITE_ERROR,
} from '../../lib/action-refusals';

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
 * THIS NOW DIALS. The docblock here used to open "THIS WRITES STATE AND DIALS
 * NOTHING", on the premise that the open-source build carried no control-plane
 * transport. That premise ended with @akasecurity/remote: the transport is in
 * this repository, `aka attach` uses it, and this action was the one attach
 * surface left behind.
 *
 * What being left behind cost: it wrote the descriptor and no credential, so a
 * user who attached here got a machine that every later surface reads as
 * attached-and-broken — `aka status` prints "attached — no usable credential",
 * and forwarding silently does nothing because the runtime falls back to the
 * standalone gateway. Nothing reported an error, at attach time or after.
 *
 * The order below is the CLI's, and it is deliberate in the same two ways:
 *
 *   VERIFY BEFORE WRITING ANYTHING. A key that the deployment does not accept
 *   must leave the machine as it was, not attached-and-broken by a second route.
 *
 *   CREDENTIAL FIRST, THEN DESCRIPTOR. The reverse order leaves a machine
 *   claiming an attachment it has no credential for if the second write fails —
 *   which is precisely the state this change exists to stop producing.
 *
 * The key reaches `writeControlPlaneCredential` and nothing else. It is not
 * logged, not returned, and never enters settings.json, which keeps carrying the
 * public half alone (see ControlPlaneConnection). No refusal below interpolates
 * it: `malformedInput` names the offending FIELD and never its value, and the
 * suite pins that with a no-echo assertion rather than trusting it.
 */
export async function attachToControlPlane(input: unknown): Promise<SaveSettingsResult> {
  const parsed = parseActionInput(AttachInput, input);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const endpoint = parsed.data.endpoint.trim();
  // Checked after the parse, not instead of it: the parse guarantees a string
  // to call .trim() on, and this guarantees the string says something. An empty
  // endpoint would write a descriptor that isAttached accepts and no transport
  // could ever use.
  if (endpoint === '') return { ok: false, error: 'Enter the deployment endpoint to attach.' };
  const accessKey = parsed.data.accessKey.trim();
  if (accessKey === '') return { ok: false, error: ATTACH_KEY_MISSING };
  // Ahead of the round trip, so a cleartext endpoint is refused before the key
  // is put on the wire rather than after. writeControlPlaneCredential throws on
  // the same predicate, but by then the send has already happened.
  if (!isSafeEndpoint(endpoint)) return { ok: false, error: ATTACH_ENDPOINT_INSECURE };
  const label = parsed.data.label?.trim();

  try {
    await createRemoteClient({ endpoint, apiKey: accessKey }).whoami();
  } catch {
    // The cause is deliberately not forwarded. It can carry the endpoint, a
    // response body, or a redacted header set, and this string is rendered
    // straight into the page.
    return { ok: false, error: ATTACH_VERIFY_FAILED };
  }

  // What was there before, so a failed write can be put back. Re-attaching is
  // how a key is ROTATED, so this routinely runs on a machine that is already
  // attached and working; an unconditional rollback would take that machine from
  // attached-and-forwarding to attached-and-broken.
  const dir = settingsDir();
  const previous = readControlPlaneCredentialState(dir);
  try {
    writeControlPlaneCredential(dir, {
      specVersion: 1,
      endpoint,
      apiKey: accessKey,
      mintedAt: new Date().toISOString(),
    });
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
    try {
      if (previous.usable) writeControlPlaneCredential(dir, previous.credential);
      else removeControlPlaneCredential(dir);
    } catch {
      // The rollback itself failed. Nothing further to try, and the message
      // below is the weaker of the two on purpose.
    }
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
    // The credential goes with the descriptor, and only AFTER it. This surface
    // could not write one until attach started doing so, which is what makes
    // removing it newly load-bearing: leaving it behind would keep a live
    // access key at rest on a machine whose settings say standalone, and
    // nothing would ever read it again to notice.
    //
    // After, not before, because applyOnboarding is the throwing half — an
    // administrative lock refuses there, and a credential already deleted by
    // then would leave a machine still descriptively attached with no way to
    // reach its deployment.
    removeControlPlaneCredential(settingsDir());
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  revalidatePath('/settings');
  return { ok: true };
}
