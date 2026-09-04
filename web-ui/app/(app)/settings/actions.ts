'use server';

import {
  applyOnboarding,
  clearAttachmentDerivedState,
  dataDir,
  isSafeEndpoint,
  ManagedFieldError,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
  removeControlPlaneCredential,
  seedCaptureBacklogOwed,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type {
  HistorySyncConsent,
  HistorySyncConsentChoice,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  AttachInput,
  HistoricalAccess,
  HISTORY_SYNC_PAYLOAD_VERSION,
  isHistorySyncConsentValid,
  isModelJudgeConsentValid,
  isVaultConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  parseActionInput,
  SaveSettingsInput,
  VAULT_CONSENT_VERSION,
  VaultInlineReveal,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import {
  ATTACH_CREDENTIAL_UNWRITABLE,
  ATTACH_ENDPOINT_INSECURE,
  ATTACH_ENDPOINT_UNPARSEABLE,
  ATTACH_KEY_MISSING,
  ATTACH_LABEL_INVALID,
  ATTACH_VERIFY_FAILED,
  DETACH_CREDENTIAL_STUCK,
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

/**
 * The history-sync field of the merge, pulled out of the updater below so its
 * FRESH-grant instant can be reported back to the caller rather than only to
 * the write. Same three-way logic as before extraction: 'unchanged' keeps
 * whatever is on file, 'revoked' or no endpoint clears it, an already-valid
 * grant is kept as-is (so its acknowledgedAt survives an unrelated save), and
 * only the remaining case — no valid grant on file, and the answer is not a
 * decline — is a FRESH grant.
 *
 * `freshGrantAt` is undefined unless this call is the one that produced a new
 * grant; the caller's capture backfill (`seedCaptureBacklogOwed`) runs only
 * then, same as `aka attach` and `aka sync-history --on` run it only at their
 * own grant sites.
 */
function resolveHistorySyncConsent(
  requested: HistorySyncConsentChoice,
  current: WorkspaceSettings,
): { consent: HistorySyncConsent | undefined; freshGrantAt: number | undefined } {
  if (requested === 'unchanged') {
    return { consent: current.historySyncConsent, freshGrantAt: undefined };
  }
  if (requested === 'revoked' || current.controlPlane === undefined) {
    return { consent: undefined, freshGrantAt: undefined };
  }
  if (isHistorySyncConsentValid(current.historySyncConsent, current.controlPlane.endpoint)) {
    return { consent: current.historySyncConsent, freshGrantAt: undefined };
  }
  const grantedAt = Date.now();
  return {
    consent: {
      acknowledgedAt: new Date(grantedAt).toISOString(),
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: current.controlPlane.endpoint,
    },
    freshGrantAt: grantedAt,
  };
}

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
  // Set inside the updater below, iff it resolves a FRESH history-sync grant —
  // never for 'unchanged', a decline, or a kept-valid grant. Read only after
  // the write below has succeeded, so the capture backfill runs for a grant
  // this call actually made and committed, never for one that was attempted
  // and then rolled back by a thrown ManagedFieldError.
  let freshHistorySyncGrantAt: number | undefined;
  try {
    // Derived inside applyOnboarding's write lock, not before it: `current` is
    // read back on the far side of the merge that is about to happen, so a
    // grant this page keeps is one that is still on file. Reading it out here
    // instead would carry a stale grant across a concurrent revoke — from the
    // wizard, or from a second tab — and write it back, silently reinstating
    // consent the user had just withdrawn.
    applyOnboarding((current) => {
      const { consent, freshGrantAt } = resolveHistorySyncConsent(data.historySyncConsent, current);
      freshHistorySyncGrantAt = freshGrantAt;
      return {
        historicalAccess: historicalAccess.data,
        // Grant records fresh consent at the current payload version; revoke
        // clears it (undefined ⇒ dropped by the schema on the merged write).
        // REQUIRED on the input, so an omitted field can no longer read as a
        // revocation of a live egress grant.
        // THREE answers, matching the history-sync grant below. 'unchanged' is what
        // an untouched row sends, and it is what stops an unrelated save from
        // deleting this grant the moment MODEL_JUDGE_PAYLOAD_VERSION is bumped —
        // and, today, from rewriting acknowledgedAt on every save. A still-valid
        // grant is kept as-is for the same reason the vault grant is.
        modelJudgeConsent:
          data.modelJudgeConsent === 'unchanged'
            ? current.modelJudgeConsent
            : data.modelJudgeConsent === 'revoked'
              ? undefined
              : isModelJudgeConsentValid(current.modelJudgeConsent)
                ? current.modelJudgeConsent
                : {
                    acknowledgedAt: new Date().toISOString(),
                    payloadVersion: MODEL_JUDGE_PAYLOAD_VERSION,
                  },
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
        // The history grant names the deployment it covers, and that name is read
        // inside the lock for the same reason as the grants above: a machine
        // detached from another tab must not have a grant written back naming the
        // deployment it just left. No endpoint on file means nothing to grant
        // against, so the grant cannot be recorded at all. A still-valid grant is
        // kept as-is so its acknowledgedAt survives unrelated edits.
        // THREE answers, and 'unchanged' is the one an unrelated save sends. A
        // boolean here forced every save to assert something about this grant, and
        // both assertions are wrong for a STALE one: granting re-consents to a
        // widened payload nobody affirmed, revoking deletes the record and every
        // surface that explains why sharing is paused. See resolveHistorySyncConsent
        // above for the logic itself.
        historySyncConsent: consent,
        vaultInlineReveal: inlineReveal.data,
      };
    });
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  // The capture half of a fresh grant — see seedCaptureBacklogOwed. `aka attach`
  // and `aka sync-history --on` call it at their own grant sites; this is the
  // third.
  if (freshHistorySyncGrantAt !== undefined) {
    seedCaptureBacklogOwed(dataDir(), freshHistorySyncGrantAt);
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
  if (!parsed.ok) {
    // `label` is the one field on this input a USER types, so it is the one
    // whose rejection must not be answered with malformedInput's wording. That
    // string is right for its intended case — a payload shape only a stale
    // client produces — and tells the reader to reload the page, which loses the
    // endpoint and key they just typed and cannot change the label that was
    // refused. Say what is wrong with it instead.
    if (parsed.field === 'label') return { ok: false, error: ATTACH_LABEL_INVALID };
    return { ok: false, error: malformedInput(parsed) };
  }
  const endpoint = parsed.data.endpoint.trim();
  // Checked after the parse, not instead of it: the parse guarantees a string
  // to call .trim() on, and this guarantees the string says something. An empty
  // endpoint would write a descriptor that isAttached accepts and no transport
  // could ever use.
  if (endpoint === '') return { ok: false, error: 'Enter the deployment endpoint to attach.' };
  // The endpoint is judged BEFORE the key, matching the CLI, and the order is
  // the diagnosis rather than a style choice. Posting both an insecure endpoint
  // and an empty key — which the UI's disabled button prevents but a direct
  // caller can do — should be told the endpoint is the problem: no key would
  // make that address safe to attach to, so reporting the missing key first
  // sends them off to fetch one they still could not use.
  //
  // It is also ahead of the round trip, so a cleartext endpoint is refused
  // before the key is put on the wire. writeControlPlaneCredential throws on the
  // same predicate, but by then the send has already happened.
  // Split from the safety check below, because isSafeEndpoint returns false for
  // two unrelated things and one refusal cannot describe both. `not-a-url-at-all`
  // and `aka.acme.internal` (no scheme — the likeliest typo, since that is how
  // people write a host) both fail to parse; answering either with "use an https
  // address" is a wrong diagnosis pointing at a fix that will not help.
  if (!URL.canParse(endpoint)) return { ok: false, error: ATTACH_ENDPOINT_UNPARSEABLE };
  if (!isSafeEndpoint(endpoint)) return { ok: false, error: ATTACH_ENDPOINT_INSECURE };
  const accessKey = parsed.data.accessKey.trim();
  if (accessKey === '') return { ok: false, error: ATTACH_KEY_MISSING };
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

  // The credential write gets its OWN try, for the reason detach's does one
  // paragraph down and in the mirror image. writeControlPlaneCredential throws on
  // its own account — ensureDataDirSync failing, EACCES on ~/.aka/settings, a
  // directory in the tmp path's way, ENOSPC — and when it does, applyOnboarding
  // has not run and settings.json has not been touched. Folding that into the
  // catch below reports SETTINGS_WRITE_ERROR, sending the user to look at a file
  // that is fine, about a failure in one whose name they were never told.
  //
  // Nothing to roll back here: this is the first write, so failing it leaves the
  // machine exactly as it was.
  let previous;
  try {
    // The snapshot is INSIDE this try, not above it. Its read looks total —
    // `throwIfNoEntry: false` covers a missing file — but that flag answers
    // ENOENT and nothing else: with a FILE where ~/.aka/settings should be a
    // directory, lstat raises ENOTDIR and this throws. Outside a try that
    // rejects the whole Server Action and replaces the page with a framework
    // error, which is precisely the failure every action in this file is written
    // to return instead of raise.
    // The FULL read, not the narrow state, and this is one of the two callers
    // that is entitled to it: rolling a credential back means writing the exact
    // bytes that were there. A Server Action runs only on the server, so
    // nothing here crosses to a browser.
    previous = readControlPlaneCredentialFile(dir);
    writeControlPlaneCredential(dir, {
      specVersion: 1,
      endpoint,
      apiKey: accessKey,
      mintedAt: new Date().toISOString(),
    });
  } catch {
    return { ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE };
  }

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
    try {
      // Restore only if the file still holds what WE wrote. None of the
      // credential helpers takes a lock (settings.json does, through
      // applyOnboarding), so a second process sharing this ~/.aka — `aka attach`
      // in a terminal, another dashboard — can have committed its own credential
      // between our write and this rollback. Blindly restoring `previous` there
      // would clobber a working attachment with a stale key and produce exactly
      // the attached-but-unusable state this action exists to stop creating.
      //
      // This narrows that window rather than closing it. Closing it means
      // locking the credential transaction inside @akasecurity/persistence so
      // the CLI is covered too; a lock taken only here would leave the CLI
      // racing and read as a fix. Flagged on the PR rather than half-done.
      const current = readControlPlaneCredentialFile(dir);
      const ours = current.usable && current.credential.apiKey === accessKey;
      if (ours) {
        if (previous.usable) writeControlPlaneCredential(dir, previous.credential);
        else removeControlPlaneCredential(dir);
      }
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
  // BEFORE the descriptor is cleared, because it is what says when this
  // attachment began. Hands the period since then to the live forward path and
  // releases the history drain's boundary, so a later re-attach to the same
  // deployment freezes a new one and picks up the window in which nothing was
  // forwarding. `aka detach` does the same; the two surfaces have to agree, and
  // this is the one that could not do it until now.
  closeHistoryWindow(readWorkspaceSettings().controlPlane?.attachedAt);

  try {
    // The history grant goes with the attachment it named, spelled rather than
    // omitted: this writer MERGES, so leaving the key out preserves a grant for
    // the deployment the machine is leaving — and a re-attach to that same
    // deployment would pick it straight back up without asking.
    applyOnboarding({
      runMode: 'standalone',
      controlPlane: undefined,
      historySyncConsent: undefined,
    });
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }

  // The credential goes with the descriptor, and only AFTER it. This surface
  // could not write one until attach started doing so, which is what makes
  // removing it newly load-bearing: leaving it behind would keep a live access
  // key at rest on a machine whose settings say standalone, and nothing would
  // ever read it again to notice.
  //
  // After, not before, because applyOnboarding is the throwing half — an
  // administrative lock refuses there, and a credential already deleted by then
  // would leave a machine still descriptively attached with no way to reach its
  // deployment.
  //
  // IN ITS OWN try, not the one above, and this is the point of the split: the
  // settings write has already committed by the time we get here, so folding a
  // failure here into that catch reports SETTINGS_WRITE_ERROR — "could not write
  // settings.json" — about a file that was written correctly. The user reads
  // that the detach failed, and the machine is in the one state this removal
  // exists to prevent: standalone in settings, live key still on disk. Say what
  // actually happened instead, and name the file so it can be dealt with.
  try {
    removeControlPlaneCredential(settingsDir());
  } catch {
    revalidatePath('/settings');
    return { ok: false, error: DETACH_CREDENTIAL_STUCK };
  }

  // And everything the attachment left behind, which `aka detach` has always
  // cleared and this path did not. It was survivable while this surface could
  // not produce a USABLE attachment — nothing attached here ever synced, so
  // none of these files existed — and stopped being once it could. Two of them
  // go on acting after the attachment is gone: a cached bundle merges over the
  // local policy raise-only, and the forward breaker's cooldown makes a later
  // re-attach forward nothing until it elapses, against a deployment this
  // machine no longer talks to.
  //
  // After the credential and outside its refusal: the machine is already
  // detached by the two writes above, and a leftover cache is not worth
  // reporting a completed detach as a failure.
  clearAttachmentDerivedState(dataDir());
  revalidatePath('/settings');
  return { ok: true };
}

/**
 * Hand the attached period over to the live path, and release the drain's
 * boundary so the next attachment can set its own.
 *
 * BEST-EFFORT and deliberately silent, for the same reason the derived-state
 * clear is: by the time this matters the machine is being detached either way,
 * and failing a completed detach over ledger bookkeeping would report a detach
 * that happened as one that did not.
 *
 * Not part of `clearAttachmentDerivedState`, despite sitting beside it: that
 * helper removes FILES and takes only a directory, while this needs the store
 * and the moment the attachment began. Both detach surfaces call both.
 */
function closeHistoryWindow(attachedAt: string | undefined): void {
  if (attachedAt === undefined) return;
  const attachedAtMs = Date.parse(attachedAt);
  if (!Number.isFinite(attachedAtMs)) return;
  try {
    const db = openLocalDatabase(dataDir());
    try {
      db.historySync.closeAttachedWindow(attachedAtMs, Date.now());
    } finally {
      db.close();
    }
  } catch {
    // See above: a ledger that cannot be updated is not a failed detach.
  }
}
