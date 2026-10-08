'use server';

import { readFileSync } from 'node:fs';

import { triggerHistorySyncRun, uninstallBackgroundSync } from '@akasecurity/local-ops';
import {
  applyOnboarding,
  type AttachModeDecision,
  captureBackfillScope,
  clearAttachmentDerivedState,
  controlPlaneCredentialPath,
  type CredentialFileRead,
  dataDir,
  decideAttachMode,
  defaultDataDir,
  freshAttachmentScope,
  holdsScopedFor,
  isForwardPaused,
  isSafeEndpoint,
  managedAttachRefusal,
  managedDetachRefusal,
  ManagedFieldError,
  managedScopedRefusal,
  mayBePersonalDevice,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  readControlPlaneCredentialState,
  readForwardHealth,
  readWorkspaceSettings,
  removeControlPlaneCredential,
  seedCaptureBacklogOwed,
  settingsDir,
  settledDecisionHolds,
  writeControlPlaneCredential,
  writeOwnerOnlyFileSync,
  writesSettingsFirst,
} from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type {
  AttachedCredentialAny,
  AttachmentMode,
  ConnectionRefusal,
  HistorySyncConsent,
  HistorySyncConsentChoice,
  PluginWhoami,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_CREDENTIAL_SPEC_VERSION,
  AttachInput,
  BodyRetention,
  HistoricalAccess,
  HISTORY_SYNC_PAYLOAD_VERSION,
  isAttached,
  isAttachmentScopeBoundTo,
  isHistorySyncConsentValid,
  isModelJudgeConsentValid,
  isVaultConsentValid,
  isWebChatCaptureConsentValid,
  MODEL_JUDGE_PAYLOAD_VERSION,
  parseActionInput,
  RedactFallback,
  SaveSettingsInput,
  VAULT_CONSENT_VERSION,
  VaultInlineReveal,
  WEB_CHAT_CAPTURE_CONSENT_VERSION,
  type WebChatCapture,
  type WebChatCaptureConsentChoice,
  webChatCaptureOf,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import {
  ATTACH_CHANGED_WHILE_WAITING,
  ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS,
  ATTACH_CREDENTIAL_UNWRITABLE,
  ATTACH_ENDPOINT_INSECURE,
  ATTACH_ENDPOINT_UNPARSEABLE,
  ATTACH_KEY_MISSING,
  ATTACH_LABEL_INVALID,
  ATTACH_MODE_REQUIRED,
  ATTACH_ROLLBACK_FAILED,
  ATTACH_ROLLBACK_LOST,
  ATTACH_VERIFY_FAILED,
  connectionRefusal,
  DETACH_CREDENTIAL_STUCK,
  malformedInput,
  managedRefusal,
  SETTINGS_WRITE_ERROR,
  SYNC_KEY_UNUSABLE,
  SYNC_NO_CLI_ENTRY,
  SYNC_NOT_ATTACHED,
  SYNC_NOT_GRANTED,
  SYNC_PAUSED,
  SYNC_SPAWN_FAILED,
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
// here would be testable only by driving the whole write it describes. A
// connection an administrator holds is refused in the sentence `aka attach` /
// `aka detach` use for the same decision; see connectionRefusal there.

/**
 * The history-sync field of the merge, pulled out of the updater below so the
 * grant's own backfill instant can be reported back to the caller rather than
 * only to the write. Same three-way logic as before extraction: 'unchanged'
 * keeps whatever is on file, 'revoked' or no endpoint clears it, and 'granted'
 * either keeps an already-valid grant as-is (so its acknowledgedAt survives an
 * unrelated save) or stamps a fresh one.
 *
 * `backfillAsOf` is undefined only for 'unchanged' and a decline — 'granted'
 * always returns one, whether the grant it resolved to was fresh or kept, so
 * the caller's capture backfill (`seedCaptureBacklogOwed`) gets ANOTHER
 * attempt every time a human deliberately re-asks for it, not only the one
 * time it happened to produce a new grant record. `seedCaptureBacklogOwed` is
 * best-effort and silent by design — a locked or unwritable store at grant
 * time must not turn a successful consent into a reported failure — and
 * `aka attach` / `aka sync-history --on` get their own retry for free because
 * a human can simply run either again. This is the dashboard's only way to
 * offer the same thing: bounded to the grant's OWN acknowledgedAt either way,
 * never widened to "now", so a retry recovers exactly what the original grant
 * promised and nothing a later save happens to add.
 */
function resolveHistorySyncConsent(
  requested: HistorySyncConsentChoice,
  current: WorkspaceSettings,
): { consent: HistorySyncConsent | undefined; backfillAsOf: number | undefined } {
  if (requested === 'unchanged') {
    return { consent: current.historySyncConsent, backfillAsOf: undefined };
  }
  if (requested === 'revoked' || current.controlPlane === undefined) {
    return { consent: undefined, backfillAsOf: undefined };
  }
  if (
    current.historySyncConsent !== undefined &&
    isHistorySyncConsentValid(current.historySyncConsent, current.controlPlane.endpoint)
  ) {
    return {
      consent: current.historySyncConsent,
      backfillAsOf: Date.parse(current.historySyncConsent.acknowledgedAt),
    };
  }
  const grantedAt = Date.now();
  return {
    consent: {
      acknowledgedAt: new Date(grantedAt).toISOString(),
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: current.controlPlane.endpoint,
    },
    backfillAsOf: grantedAt,
  };
}

// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function saveSettings(input: unknown): Promise<SaveSettingsResult> {
  const parsed = parseActionInput(SaveSettingsInput, input);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const { data } = parsed;

  const historicalAccess = HistoricalAccess.safeParse(data.historicalAccess);
  const inlineReveal = VaultInlineReveal.safeParse(data.vaultInlineReveal);
  const redactFallback = RedactFallback.safeParse(data.redactFallback);
  // The horizon's RANGE is checked here rather than at the input boundary, so
  // the one definition of a legal window is `BodyRetention`'s own. A day count
  // outside it is refused rather than clamped: a silently-rounded horizon
  // expires a different set of bodies than the one the user asked for, and
  // expiry is not undoable.
  const bodyRetention = BodyRetention.safeParse(data.bodyRetention);
  const vaultChoice = data.vaultConsent;
  if (
    !historicalAccess.success ||
    !inlineReveal.success ||
    !redactFallback.success ||
    !bodyRetention.success ||
    (vaultChoice !== 'on' && vaultChoice !== 'off')
  ) {
    return { ok: false, error: 'Invalid settings value.' };
  }
  // Set inside the updater below, iff 'granted' resolved to a valid consent —
  // never for 'unchanged' or a decline. Read only after the write below has
  // succeeded, so the capture backfill runs for a grant this call actually
  // made and committed, never for one that was attempted and then rolled back
  // by a thrown ManagedFieldError.
  let historySyncBackfillAsOf: number | undefined;
  try {
    // Derived inside applyOnboarding's write lock, not before it: `current` is
    // read back on the far side of the merge that is about to happen, so a
    // grant this page keeps is one that is still on file. Reading it out here
    // instead would carry a stale grant across a concurrent revoke — from the
    // wizard, or from a second tab — and write it back, silently reinstating
    // consent the user had just withdrawn.
    applyOnboarding((current) => {
      const { consent, backfillAsOf } = resolveHistorySyncConsent(data.historySyncConsent, current);
      historySyncBackfillAsOf = backfillAsOf;
      return {
        historicalAccess: historicalAccess.data,
        bodyRetention: bodyRetention.data,
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
        // What a detection set to Redact does on a field that cannot be masked
        // in place. Not a handling setting — it never changes what a detection
        // is assigned — so it carries no consent record and is written like any
        // other plain preference.
        redactFallback: redactFallback.data,
        // The web-chat capture block, rebuilt WHOLE from what is on file at merge
        // time. applyOnboarding merges at the top level, so a block written with
        // only the grant in it REPLACES the response mode and the account answer
        // beside it — neither of which this page has a control for — and an
        // unrelated save here would silently reset a choice made elsewhere.
        // Deriving it from `current` inside the lock is what keeps both true at
        // once: the modes survive, and the grant is judged against the file this
        // write is about to land on rather than the one the page rendered.
        webChatCapture: nextWebChatCapture(current, data.webChatCaptureConsent),
      };
    });
  } catch (error) {
    if (error instanceof ManagedFieldError)
      return { ok: false, error: managedRefusal(error.fields) };
    return { ok: false, error: SETTINGS_WRITE_ERROR };
  }
  // The capture half of the grant — see seedCaptureBacklogOwed and the
  // resolver's own doc comment above for why this retries on every 'granted'
  // save, not only the one that stamps a fresh record. `aka attach` and
  // `aka sync-history --on` are the other two call sites.
  if (historySyncBackfillAsOf !== undefined) {
    // Marked under the scope the drain will read with (see captureBackfillScope),
    // from the settings as they stand after this write and through the same read
    // the drain makes, so the administrator's overlay counts here exactly as it
    // does there. The credential is read here, server-side, and nothing of it
    // but its mode leaves this block. Passed as a function, settings read
    // included, so all of it runs inside the seed's own best-effort guard: the
    // grant is already recorded, and a throw there must not turn it into a
    // failure.
    seedCaptureBacklogOwed(dataDir(), historySyncBackfillAsOf, () => {
      const settings = readWorkspaceSettings();
      const connection = settings.controlPlane;
      return captureBackfillScope(
        connection === undefined
          ? undefined
          : readControlPlaneCredentialFile(settingsDir(), connection),
        settings,
      );
    });
  }
  revalidatePath('/settings');
  return { ok: true };
}

/**
 * The web-chat capture block to write, given the settings this write is about to
 * merge into and the answer the page sent.
 *
 * A private helper rather than an inline expression only because the block has
 * three fields and one of them is derived: every export of a `'use server'`
 * module must be an async Server Action, so this cannot be exported, and it must
 * be CALLED from inside applyOnboarding's updater — `current` is the file under
 * the lock, and reading it out beforehand puts the read back outside.
 *
 * `responses` and `account` have no control on this page and are carried
 * forward. The grant is stamped here and never accepted from the client: the
 * input is the bare answer, so a caller-supplied acknowledgedAt or version has
 * no path in. 'granted' records the current time at the current version, unless
 * a still-valid grant is already on file, which is kept as-is so its
 * acknowledgedAt survives unrelated edits. 'revoked' drops the grant entirely —
 * future recording stops, and what is already stored stays — and on a machine
 * that never answered there is no grant to drop, so the key stays absent.
 * 'unchanged' is what an untouched row sends, and it asserts nothing either way.
 *
 * The branches are ordered so that anything OTHER than the two affirmative
 * answers drops the grant. `webChatCaptureConsent` is required on the input, so
 * there is nothing else to arrive — but if that requirement were ever relaxed,
 * an absent answer must fall to the safe side rather than mint a grant nobody
 * gave.
 */
function nextWebChatCapture(
  current: WorkspaceSettings,
  choice: WebChatCaptureConsentChoice,
): WebChatCapture | undefined {
  // 'unchanged' is what every UNRELATED save sends, and it is answered from the
  // file rather than from the defaults. `webChatCaptureOf` falls back to the
  // schema's defaults when the key is absent, so defaulting first meant that
  // toggling vault reveal on a machine that had never answered this question
  // wrote `{ responses: 'with-findings', account: false }` into settings.json —
  // contradicting "absent until the user answers", which is what every reader
  // of the file takes an absent key to mean, and which the three sibling grants
  // beside this one all honour.
  //
  // Returning the file's own value also keeps the rebuild-whole property below
  // intact: there is nothing to rebuild when the answer is "no change".
  if (choice === 'unchanged') return current.webChatCapture;
  // The same holds for a revoke on a machine that never answered: there is no
  // grant to drop, and falling through would write that defaulted block with no
  // consent in it. The page sends 'revoked' for a row toggled on and back off
  // before saving, so this is reachable. Only 'granted' creates the block.
  if (choice !== 'granted' && current.webChatCapture === undefined) return undefined;
  const block = webChatCaptureOf(current);
  const consent =
    choice === 'granted'
      ? isWebChatCaptureConsentValid(block.consent)
        ? block.consent
        : {
            acknowledgedAt: new Date().toISOString(),
            version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
          }
      : undefined;
  // Spread conditionally rather than assigning `undefined`: an explicit
  // undefined is a present key under exactOptionalPropertyTypes, and the absence
  // of this key is what "not granted" means to every reader of the file.
  return {
    responses: block.responses,
    account: block.account,
    ...(consent === undefined ? {} : { consent }),
  };
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
 * The order below is the CLI's, and it is deliberate in the same three ways:
 *
 *   AN ADMINISTRATOR'S HOLD BEFORE THE KEY IS SENT. A connection whose mode or
 *   deployment an administrator locked or pinned is refused here, not left to
 *   the writer — which refuses a lock only after the key is stored, and a pin
 *   not at all.
 *
 *   VERIFY BEFORE WRITING ANYTHING. A key that the deployment does not accept
 *   must leave the machine as it was, not attached-and-broken by a second route.
 *
 *   CREDENTIAL FIRST, THEN DESCRIPTOR, WHERE A STOP BETWEEN THEM IS HARMLESS,
 *   WITH ONE EXCEPTION. The reverse order leaves a machine claiming an
 *   attachment it has no credential for if the second write fails. The settings
 *   go first exactly where `aka attach` puts them first (`writesSettingsFirst`,
 *   which both surfaces share): where the credential written first would sit
 *   beside an enrolled list or a history grant the finished attach replaces. The
 *   exception is a scoped attach over a usable machine-wide credential, which
 *   writes the credential first as well, as `aka attach` does: a stop there
 *   leaves the new scoped key beside the list on file, which may belong to
 *   another organization or account, and the earlier grant, until the machine is
 *   attached again. See the order of the writes below.
 *
 * THE MODE IS DECIDED BEFORE THE KEY IS SENT, TOO. A machine attaches
 * machine-wide or scoped (`AttachInput.mode`), by `decideAttachMode` asked as a
 * run with no terminal to ask on: a connection an administrator governs is
 * machine-wide, and a scoped request on one is refused; a mode the caller names
 * is used; with none, a usable credential for this same endpoint keeps its
 * mode, a credential file this build cannot read — or a scoped credential for
 * another endpoint — is refused (it may be a scoped one from a newer build, and
 * a machine-wide write over it would widen the machine with nobody deciding),
 * and anything else is machine-wide. Each input is local, so each refusal is
 * made before the round trip.
 *
 * A SCOPED ATTACH WRITES ITS SCOPE RECORD IN THE SAME SETTINGS WRITE. The record
 * on file is kept when the machine was already a scoped attachment to this
 * endpoint and the record is bound to it and to the organization and account
 * the key just verified as — which is how a key rotation keeps every
 * enrollment — and replaced by an empty one otherwise, so a key for someone else
 * starts with nothing enrolled. The administrator's overlay is asked again after
 * the round trip, for every attach, so no write lands where an overlay that
 * arrived while the key was being verified refuses it, and a scoped write never
 * lands on a machine that became managed meanwhile. A machine-wide attach clears
 * the record, so a dormant one cannot come back under a later scoped attach. A
 * machine-wide credential is the v1 file this action has always written, byte
 * for byte.
 *
 * THE DECISION IS PUT AGAIN AFTER THE ROUND TRIP, ON THE CREDENTIAL AS IT IS THEN.
 * The mode was settled from a read made before the key went out, and another
 * process can attach, re-attach or detach the machine while the reply is awaited.
 * So the credential is read once more just before the write and the same decision
 * is made on it, with the administrator's answer read again too
 * (`settledDecisionHolds`). If it no longer agrees, nothing is written and the
 * answer says the connection changed. What is kept of the stored scope record
 * follows that later read as well (`holdsScopedFor`), so a personal device
 * attached meanwhile keeps its enrolled list and one widened meanwhile by an
 * older build does not get the record it left behind revived.
 *
 * A MACHINE-WIDE WRITE OVER ANYTHING THAT WAS, OR MAY HAVE BEEN, A PERSONAL
 * DEVICE'S CREDENTIAL CLEARS THE HISTORY GRANT. A grant given to a personal
 * device was for the history of the repositories the machine enrolled; the same
 * grant over a machine-wide credential would let the drain send the history of
 * activity from anywhere on the machine. This surface has no terminal to ask
 * again on, so the grant is cleared (`replacesPersonalDevice`) and history needs
 * a fresh grant from the Sync panel. "Was or may have been" is judged on both
 * reads of the credential, the one the mode was settled from and the one just
 * before the write, because another process can change the file between them,
 * and a credential file that exists but cannot be read counts, since it may be a
 * personal device's written by a newer build. It holds whichever deployment the
 * credential was for, because a grant names its deployment and one for another
 * deployment would be valid again the day this machine is attached there. A
 * machine with no credential file counts only when its settings still hold an
 * enrolled list, which is written only for a personal device; a grant with no
 * list and no credential file is kept. Every other re-attach, a key rotation
 * that stays scoped and narrowing a machine-wide attachment included, leaves the
 * grant as it is.
 *
 * The key reaches `writeControlPlaneCredential` and nothing else. It is not
 * logged, not returned, and never enters settings.json, which keeps carrying the
 * public half alone (see ControlPlaneConnection). No refusal below interpolates
 * it: `malformedInput` names the offending FIELD and never its value, and the
 * suite pins that with a no-echo assertion rather than trusting it.
 *
 * DOES NOT INSTALL THE BACKGROUND-SYNC LAUNCHAGENT, unlike `aka attach`. A
 * machine attached from here still forwards live activity fine — the drain
 * this scheduler exists for only matters to a machine with no session ever
 * reopening, which is a CLI-shaped machine to begin with. `detachFromControlPlane`
 * below still uninstalls it, since a stray plist left by an unrelated `aka
 * attach` on this same machine must not survive a detach initiated here.
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
  const label = parsed.data.label?.trim();

  // An administrator's decision, ahead of the key and of every side effect below,
  // in the order `aka attach` makes it: after the endpoint is known to be one a
  // key could be sent to, and before anything is. The settings writer refuses a
  // LOCKED connection only, and only after the key has been verified and stored;
  // a PINNED one it writes through, and the next read overlays the pin straight
  // back — leaving a credential for a deployment the settings never name again.
  // No key the caller could supply changes either answer, so a missing key is
  // not reported first.
  //
  // The name typed, an empty one read as none, for this check and the one made
  // again after the round trip.
  const request = { endpoint, label: label === undefined || label === '' ? undefined : label };
  const refusal = managedAttachRefusal(request);
  if (refusal !== null) return { ok: false, error: connectionRefusal(refusal) };

  // What the machine holds now, read for the mode decision and before the key
  // goes on the wire, so a refusal sends nothing. The rollback below still takes
  // its own snapshot right before the write. A read that throws — a FILE where
  // ~/.aka/settings should be a directory — is the state the credential write
  // would fail on, and it is answered the way that write's failure is.
  const dir = settingsDir();
  let prior: CredentialFileRead;
  try {
    prior = readControlPlaneCredentialFile(dir);
  } catch {
    return { ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE };
  }
  // Asked only now that managedAttachRefusal has answered null: a governed
  // connection is machine-wide, and a scoped request on one is refused here,
  // beside the refusal above and for its reason, because no key the caller could
  // supply changes the answer. A user's own pick must not narrow what a machine
  // their organization manages reports.
  const governed = managedScopedRefusal();
  const decided = modeForAttach(parsed.data.mode, governed, prior, endpoint);
  if (!decided.ok) return { ok: false, error: decided.error };
  const { settled } = decided;
  const mode = settled.mode;

  const accessKey = parsed.data.accessKey.trim();
  if (accessKey === '') return { ok: false, error: ATTACH_KEY_MISSING };

  let identity: PluginWhoami;
  try {
    identity = await createRemoteClient({ endpoint, apiKey: accessKey }).whoami();
  } catch {
    // The cause is deliberately not forwarded. It can carry the endpoint, a
    // response body, or a redacted header set, and this string is rendered
    // straight into the page.
    return { ok: false, error: ATTACH_VERIFY_FAILED };
  }

  // THE ADMINISTRATOR'S OVERLAY IS ASKED AGAIN NOW, FOR EVERY ATTACH, with nothing
  // written yet. Both checks above ran before the round trip, and an overlay that
  // arrived meanwhile can hold this machine at standalone, pin it to another
  // deployment or name, or make it machine-only. They are asked again in the same
  // order and answered in the same sentences. The answer about the scoped mode is
  // also what the decision is put again with below, and what keeps the scope
  // record bound to the endpoint every read sees.
  const lateRefusal = managedAttachRefusal(request);
  if (lateRefusal !== null) return { ok: false, error: connectionRefusal(lateRefusal) };
  const governedNow = managedScopedRefusal();
  if (mode === 'scoped' && governedNow !== null) {
    return { ok: false, error: connectionRefusal(governedNow) };
  }

  // What was there before, so a failed write can be put back, and so the decision
  // can be put again on the machine as it is now. Re-attaching is how a key is
  // ROTATED, so this routinely runs on a machine that is already attached and
  // working; an unconditional rollback would take that machine from
  // attached-and-forwarding to attached-and-broken.
  //
  // GUARDED like the early read. Its read looks total — `throwIfNoEntry: false`
  // covers a missing file — but that flag answers ENOENT and nothing else: with a
  // FILE where ~/.aka/settings should be a directory, lstat raises ENOTDIR. A
  // file can take the directory's place during the round trip, and outside a try
  // that rejects the whole Server Action and replaces the page with a framework
  // error, which is precisely the failure every action in this file is written to
  // return instead of raise.
  //
  // The FULL read, not the narrow state, and this is one of the two callers that
  // is entitled to it: rolling a credential back means writing the exact bytes
  // that were there. A Server Action runs only on the server, so nothing here
  // crosses to a browser.
  let previous: CredentialFileRead;
  try {
    previous = readControlPlaneCredentialFile(dir);
  } catch {
    return { ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE };
  }

  // THE LOST UPDATE THE DECISION CANNOT SEE. The mode was settled from `prior`,
  // read before the key went out, and another process can attach, re-attach or
  // detach this machine while the reply is awaited. The same decision is put
  // again on `previous`, with the same flag and endpoint and the administrator's
  // answer as it is now (`governedNow`); if it no longer agrees (see
  // settledDecisionHolds) writing what was settled could widen a personal device,
  // narrow a machine-wide attachment, or overwrite a credential a newer build
  // wrote, so nothing is written.
  if (
    !settledDecisionHolds({
      flag: parsed.data.mode,
      managed: governedNow,
      previous,
      endpoint,
      interactive: false,
      settled,
      mode,
    })
  ) {
    return { ok: false, error: ATTACH_CHANGED_WHILE_WAITING };
  }

  // Who the key belongs to, for a SCOPED attach only: the scope record is bound
  // to these two fields, so a key for another organization or account starts
  // with nothing enrolled. Nothing else from the answer is kept.
  const who: Pick<PluginWhoami, 'tenantName' | 'userEmail'> | undefined =
    mode === 'scoped'
      ? { tenantName: identity.tenantName, userEmail: identity.userEmail }
      : undefined;
  // The stored record can be kept only on a scoped → scoped re-attach, judged on
  // the credential as it is NOW (`previous`, not the read the mode was settled
  // from): another process may have attached or widened this machine since. A
  // record beside a machine-wide credential, or beside none, was left by a
  // writer that did not clear it (an older build's re-attach or detach).
  const keepScope = holdsScopedFor(previous, endpoint);
  // Whether this attach keeps `stored` as the enrolled list: only a scoped
  // re-attach over a personal device's credential for this exact endpoint, with a
  // list bound to the organization and account the key just verified as (`who` is
  // defined exactly when the attach is scoped). The one judgment, shared by what
  // the settings write holds and by the order of the two writes below.
  const keepsStoredList = (stored: unknown): boolean =>
    who !== undefined && keepScope && isAttachmentScopeBoundTo(stored, endpoint, who);
  // A machine-wide write over anything that was, or may have been, a personal
  // device clears the history grant (see the docblock): either read of the
  // credential says it is or may be a personal device's, or there is no credential
  // file and the settings the write lands on still hold an enrolled list, which is
  // written only for a personal device. Judged inside the write, like the list.
  const clearsHistoryGrant = (current: WorkspaceSettings): boolean =>
    replacesPersonalDevice(mode, prior, previous) ||
    (mode === 'machine' &&
      !previous.usable &&
      previous.reason === 'absent' &&
      current.attachmentScope !== undefined);
  // A file this build cannot parse may be a personal device's credential a newer
  // build wrote, and this attach goes ahead over it only because the caller named
  // the mode. Its BYTES are kept, so a failed settings write below puts that file
  // back instead of deleting it. Only a regular file the reader opened and read
  // qualifies: a symbolic link (`untrusted-file`) is never followed, and an
  // `unreadable` one has no bytes to keep.
  const previousBytes =
    !previous.usable && (previous.reason === 'malformed' || previous.reason === 'unsafe-endpoint')
      ? credentialBytes(dir)
      : undefined;

  // THE ORDER OF THE TWO WRITES, chosen by what a stop between them would leave,
  // by the rule `aka attach` uses (`writesSettingsFirst`, shared through the
  // persistence package so the two surfaces cannot order them differently).
  //
  // CREDENTIAL FIRST, then the settings, unless the rule picks the other order.
  // In the other order a machine that fails on the second write is left claiming
  // an attachment it has no credential for.
  //
  // SETTINGS FIRST where the credential written first would sit beside an enrolled
  // list or a history grant that the finished attach replaces:
  //   - a machine-wide attach over a credential that is, or may be, a personal
  //     device's, or over no credential file beside settings that still carry a
  //     list or a grant. The history drain would read a grant given for enrolled
  //     repositories as one for the whole machine;
  //   - a scoped attach that does not keep the list it finds, over settings that
  //     carry a list or a grant. A list enrolled under another organization or
  //     account would forward under the new key.
  // A stop then leaves what the machine had before beside no list (machine-wide)
  // or an empty one (scoped), which sends no repository's activity.
  //
  // THE EXCEPTION is a scoped attach over a usable machine-wide credential, which
  // writes the credential first, as `aka attach` does. In `aka attach`, settings
  // first there would leave the machine-wide credential beside that run's answer
  // about the repositories to be enrolled, and the drain would read it as a grant
  // for the whole machine; this surface asks no history question, but takes the
  // same order so the two cannot differ. So a stop there leaves the new scoped
  // credential beside the list on file, which the finished attach would have
  // replaced and which may be another organization's or account's, and beside the
  // earlier grant. If that list names this deployment, its repositories forward
  // under the new key, and their history goes under the earlier grant, until the
  // machine is attached again.
  const settingsFirst = writesSettingsFirst(
    mode,
    previous,
    readWorkspaceSettings(),
    keepsStoredList,
  );
  const writeCredential = (): void => {
    writeControlPlaneCredential(dir, credentialFor(mode, endpoint, accessKey));
  };
  const writeSettings = (): void => {
    // The updater form, so the scope decision reads the record this write is
    // about to merge over, inside the settings lock.
    applyOnboarding((current) => ({
      runMode: 'attached',
      controlPlane: {
        endpoint,
        ...(label === undefined || label === '' ? {} : { label }),
        // Stamped server-side like every other timestamp on this page.
        attachedAt: new Date().toISOString(),
      },
      attachmentScope: scopeRecordFor(current.attachmentScope, endpoint, who, keepsStoredList),
      // SPELLED, because this writer merges: leaving the key out would keep the
      // grant. Only when a personal device is being replaced by a machine-wide
      // one, or the credential file is gone beside an enrolled list; otherwise the
      // key is absent and the grant stands.
      ...(clearsHistoryGrant(current) ? { historySyncConsent: undefined } : {}),
    }));
  };
  // Why a settings write failed: an administrator's lock, or a write that did not land.
  const settingsRefusal = (error: unknown): string =>
    error instanceof ManagedFieldError ? managedRefusal(error.fields) : SETTINGS_WRITE_ERROR;

  if (settingsFirst) {
    // The first write: when it fails nothing has changed and there is nothing to
    // roll back.
    try {
      writeSettings();
    } catch (error) {
      return { ok: false, error: settingsRefusal(error) };
    }
    // The settings have landed, and they are NOT put back if the credential write
    // fails: that would take another settings write, which can fail too. The
    // refusal says what is left, and the page is refreshed, because it was
    // rendered from settings that have changed.
    try {
      writeCredential();
    } catch {
      revalidatePath('/settings');
      return { ok: false, error: ATTACH_CREDENTIAL_NOT_SAVED_AFTER_SETTINGS };
    }
    revalidatePath('/settings');
    return { ok: true };
  }

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
  try {
    writeCredential();
  } catch {
    return { ok: false, error: ATTACH_CREDENTIAL_UNWRITABLE };
  }

  try {
    writeSettings();
  } catch (error) {
    // The refusal names why the write failed, and adds what the rollback could
    // not put back. With nothing added, the credential file holds what it held
    // before this attach, or what another process has written to it since.
    const note = restoreCredential(dir, previous, previousBytes, accessKey);
    const reason = settingsRefusal(error);
    return { ok: false, error: note === undefined ? reason : `${reason} ${note}` };
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
 * Refused, ahead of everything below, when an administrator locked or pinned the
 * MODE and the machine reads as attached — a detach the next read would undo.
 * applyOnboarding still refuses a lock inside the write lock against the managed
 * file, and that stays the last word for a lock that appears between the two
 * reads; a pin it would write straight through.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function detachFromControlPlane(): Promise<SaveSettingsResult> {
  // FIRST, because every step below is a side effect a refused detach must not
  // leave behind — the history window most of all, which is handed to the live
  // path before the writer is ever asked. The decision is the one `aka detach`
  // makes.
  const refusal = managedDetachRefusal();
  if (refusal !== null) return { ok: false, error: connectionRefusal(refusal) };

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
    // deployment would pick it straight back up without asking. The scope record
    // goes for the same reason: a later scoped attach to that deployment would
    // otherwise revive enrollments made under this attachment.
    applyOnboarding({
      runMode: 'standalone',
      controlPlane: undefined,
      historySyncConsent: undefined,
      attachmentScope: undefined,
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
  // Best-effort, macOS only, same as `aka detach`: without this, a machine
  // attached from the CLI and detached from here keeps a LaunchAgent that
  // re-invokes `aka sync-history --run` every 30 minutes, across reboots,
  // against a deployment this machine no longer talks to. This dashboard has
  // no `--home` concept — it always operates on the real default AKA home —
  // so that is the one base its own attach path could ever have installed
  // the scheduler against.
  uninstallBackgroundSync(defaultDataDir());
  revalidatePath('/settings');
  return { ok: true };
}

/**
 * Ask this machine to drain what it owes its deployment, now.
 *
 * TAKES NO ARGUMENT, which is the whole of its input validation. Every other
 * mutating action here parses an untrusted body before reading a field; this
 * one has no body to parse, so there is nothing a caller can shape. What it
 * does instead is re-derive the gate from disk — a Server Action is an ordinary
 * POST, and a page open since before a detach, a revoked key or a withdrawn
 * grant will happily send one.
 *
 * THE PASS IS DETACHED, and that is not an accident of the spawn. A drain runs
 * for up to two minutes; a Server Action that waited for it would hold the
 * request open past every proxy timeout between here and the browser, and a
 * user who navigated away would kill the pass mid-batch. So this returns as
 * soon as the child exists, and the only thing it can ever report is whether
 * one started. What the pass then does is recorded in the ledger and in the
 * progress file, which the panel reads on its next render.
 *
 * It covers exactly what the drain covers — the two delivery lanes the ledger
 * counts, and nothing else. Findings, project data shares and inventory are not
 * rows this sends, and the panel says so beside the button rather than letting
 * it imply otherwise.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function syncNow(): Promise<SaveSettingsResult> {
  const settings = readWorkspaceSettings();
  const endpoint = settings.controlPlane?.endpoint;
  if (!isAttached(settings) || endpoint === undefined) {
    return { ok: false, error: SYNC_NOT_ATTACHED };
  }
  // The NARROW reader, not readControlPlaneCredentialFile: this branch needs a
  // verdict, and the wide read returns the key beside it.
  if (!readControlPlaneCredentialState(settingsDir(), settings.controlPlane).usable) {
    return { ok: false, error: SYNC_KEY_UNUSABLE };
  }
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return { ok: false, error: SYNC_NOT_GRANTED };
  }

  // LAST of the gates, and the only one read fresh at this instant rather than
  // from the render that drew the button. The cooldown is short and clears
  // itself, so a panel drawn seconds ago can say paused about a machine that is
  // free to send again — refusing on that stale answer would be this surface
  // inventing a pause of its own.
  const now = Date.now();
  if (isForwardPaused(readForwardHealth(dataDir(), now), now)) {
    return { ok: false, error: SYNC_PAUSED };
  }

  // The default home, for the same reason detach uninstalls the scheduler
  // against it: this dashboard has no `--home` concept and always operates on
  // the real one.
  const start = triggerHistorySyncRun(defaultDataDir());
  if (!start.started) {
    return {
      ok: false,
      error: start.reason === 'no-cli-entry' ? SYNC_NO_CLI_ENTRY : SYNC_SPAWN_FAILED,
    };
  }

  // The pass has started, not finished, so this render will still show the
  // backlog. What it picks up is the CLAIM the child takes, which is what turns
  // the panel's "Sending…" on and disables the control.
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

/**
 * The mode an attach writes together with the decision it came from, or the
 * refusal to answer with when it cannot be chosen for the caller. The decision
 * is returned so that it can be put again after the key is verified.
 *
 * The decision is `decideAttachMode`'s, asked as a run with no terminal to ask
 * on and with the caller's `mode` as the flag. Its answers map to this surface
 * as follows. `use` writes that mode: a governed connection is machine-wide, a
 * named mode wins (including `machine` over a scoped attachment, which widens
 * it — on this surface the explicit choice is the confirmation), a usable
 * credential for this same endpoint keeps its mode (the key-rotation path), and
 * anything else is machine-wide. `scoped-managed` is a scoped request on a
 * governed connection and is answered with the managed refusal. `needs-flag`
 * is a credential file that cannot be used, or a scoped credential for another
 * endpoint, with no mode named: either may be a scoped attachment, so the
 * caller has to say which kind of device this is. `ask` cannot be answered
 * without a terminal and is treated the same way.
 */
function modeForAttach(
  requested: AttachmentMode | undefined,
  governed: ConnectionRefusal | null,
  prior: CredentialFileRead,
  endpoint: string,
):
  | { ok: true; settled: Extract<AttachModeDecision, { kind: 'use' }> }
  | { ok: false; error: string } {
  const decision = decideAttachMode({
    flag: requested,
    managed: governed,
    previous: prior,
    endpoint,
    interactive: false,
  });
  switch (decision.kind) {
    case 'use':
      return { ok: true, settled: decision };
    case 'refuse':
      // The decision refuses `scoped-managed` only when `governed` is non-null.
      return {
        ok: false,
        error:
          decision.why === 'scoped-managed' && governed !== null
            ? connectionRefusal(governed)
            : ATTACH_MODE_REQUIRED,
      };
    case 'ask':
      return { ok: false, error: ATTACH_MODE_REQUIRED };
  }
}

/**
 * The credential an attach writes. Machine-wide is the v1 literal this action
 * has always written, the same keys in the same order, so a machine attachment
 * stays byte-identical; scoped is v2 with its mode last, the order the schema's
 * own parse gives and the terminal command's captured file has. The suite
 * compares the written bytes with a literal in that order, and the order of the
 * keys with that captured file, so the two cannot drift apart.
 */
function credentialFor(
  mode: AttachmentMode,
  endpoint: string,
  apiKey: string,
): AttachedCredentialAny {
  const mintedAt = new Date().toISOString();
  return mode === 'scoped'
    ? {
        specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
        endpoint,
        apiKey,
        mintedAt,
        mode: 'scoped',
      }
    : { specVersion: ATTACHED_CREDENTIAL_SPEC_VERSION, endpoint, apiKey, mintedAt };
}

/**
 * Whether this attach replaces what was, or may have been, a personal device's
 * credential with a machine-wide one, for the deployment it was attached to or
 * any other. Every read passed is asked about, so a change between the early read
 * and the later one cannot hide a personal device.
 */
function replacesPersonalDevice(mode: AttachmentMode, ...reads: CredentialFileRead[]): boolean {
  return mode === 'machine' && reads.some(mayBePersonalDevice);
}

/**
 * The `attachmentScope` an attach writes, given the one on file.
 *
 * Machine-wide (`who` undefined): none, spelled, so the merge drops the key. A
 * machine attachment never holds a scope record, so a later scoped attach
 * cannot revive one.
 *
 * Scoped: the stored record, RAW, when `keepsList` keeps it (the machine was
 * already a scoped attachment to this exact endpoint, and the record is bound to
 * this endpoint and to the verified organization and account) — a key rotation
 * keeps every enrollment, and an entry or envelope key a newer build added
 * survives because nothing here rebuilds the record. Otherwise a fresh empty
 * record bound to them: a record for another endpoint, for someone else, or with
 * no binding at all cannot be checked, and one left beside a machine-wide
 * credential (or none) belongs to an attachment that ended, so it does not carry
 * over.
 *
 * `endpoint` is the effective one: a scoped attach happens only where no
 * administrator governs the connection, so nothing overlays it.
 *
 * `keepsList` is the attach's one judgment of whether the stored list is kept,
 * the same function that chooses the order of its writes.
 */
function scopeRecordFor(
  raw: unknown,
  endpoint: string,
  who: Pick<PluginWhoami, 'tenantName' | 'userEmail'> | undefined,
  keepsList: (stored: unknown) => boolean,
): unknown {
  if (who === undefined) return undefined;
  return keepsList(raw) ? raw : freshAttachmentScope(endpoint, who);
}

/**
 * Put the credential file back as it was before this attach wrote over it, once
 * the settings write has failed on an attach that wrote the credential first, and
 * return the sentence the refusal adds when that could not be done: undefined
 * when nothing needs adding. Never throws.
 *
 * ONLY WHILE THE FILE STILL HOLDS THE KEY THIS ATTACH WROTE. None of the
 * credential helpers takes a lock (settings.json does, through
 * applyOnboarding), so a second process sharing this ~/.aka, `aka attach` in a
 * terminal or another dashboard, can have committed its own credential between
 * this attach's write and the rollback. Restoring over it would replace a
 * working attachment with a stale key, so that file is left as it is. This
 * narrows the window rather than closing it: closing it means locking the
 * credential transaction inside @akasecurity/persistence, so that the terminal
 * command is covered too.
 *
 * Otherwise, by what was there before:
 *   - a credential this build could read is written back from the reader's own
 *     parse;
 *   - no file: the one this attach wrote is removed;
 *   - a file the reader opened and could not use (`previousBytes`): its raw
 *     bytes go back, owner-only and atomic like every credential write;
 *   - a file it could not open at all (a symbolic link, a file that would not
 *     read) has no bytes to put back. This attach's file is removed too: its
 *     settings were never written, so its key left on disk would be half an
 *     attachment. The earlier file is gone, and ATTACH_ROLLBACK_LOST says so.
 * A rollback that fails part-way is ATTACH_ROLLBACK_FAILED.
 */
function restoreCredential(
  dir: string,
  previous: CredentialFileRead,
  previousBytes: string | undefined,
  accessKey: string,
): string | undefined {
  try {
    const current = readControlPlaneCredentialFile(dir);
    if (!current.usable || current.credential.apiKey !== accessKey) return undefined;
    if (previous.usable) {
      writeControlPlaneCredential(dir, previous.credential);
      return undefined;
    }
    if (previous.reason === 'absent') {
      removeControlPlaneCredential(dir);
      return undefined;
    }
    if (previousBytes !== undefined) {
      writeOwnerOnlyFileSync(controlPlaneCredentialPath(dir), previousBytes);
      return undefined;
    }
    removeControlPlaneCredential(dir);
    return ATTACH_ROLLBACK_LOST;
  } catch {
    return ATTACH_ROLLBACK_FAILED;
  }
}

/** The credential file's bytes as text, or undefined when they cannot be read. Never throws. */
function credentialBytes(dir: string): string | undefined {
  try {
    return readFileSync(controlPlaneCredentialPath(dir), 'utf8');
  } catch {
    return undefined;
  }
}
